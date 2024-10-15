package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

type ContainerMetrics struct {
	Name                  string  `json:"name"`
	Time                  string  `json:"time"`
	CPUUsagePercentage    float64 `json:"cpu_usage_percentage"`
	MemoryUsagePercentage float64 `json:"memory_usage_percentage"`
	MemoryUsed            uint64  `json:"memory_used"`
	MemoryAvailable       uint64  `json:"available_memory"`
}

func collector() {
	fmt.Printf("[%s] Starting metrics recorder with refresh rate of %d seconds and retention period of %d days.\n", time.Now().Format("2006-01-02 15:04:05"), refreshRateSeconds, collectorRetentionPeriodDays)

	go func() {
		ticker := time.NewTicker(time.Duration(refreshRateSeconds) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Recovered from panic in collector: %v", r)
						}
					}()

					queryTimeInUnixString := getUnixTimeInMilliUTC()

					// fmt.Printf("[%s] Collecting metrics\n", queryTimeInUnixString)
					// CPU usage
					overallPercentage, err := cpu.Percent(0, false)
					if err != nil {
						log.Printf("Error getting CPU percentage: %v", err)
						return
					}

					_, err = db.Exec(`INSERT INTO cpu_usage (time, percent) VALUES (?, ?)`, queryTimeInUnixString, fmt.Sprintf("%.2f", overallPercentage[0]))
					if err != nil {
						log.Printf("Error inserting CPU usage into database: %v", err)
					}

					// collectContainerMetrics(queryTimeInUnixString)

					// Memory usage
					memory, err := mem.VirtualMemory()
					if err != nil {
						log.Printf("Error getting memory usage: %v", err)
						return
					}

					_, err = db.Exec(`INSERT INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?)`,
						queryTimeInUnixString, memory.Total, memory.Available, memory.Used, math.Round(memory.UsedPercent*100)/100, memory.Free)
					if err != nil {
						log.Printf("Error inserting memory usage into database: %v", err)
					}

					// Cleanup old data
					totalRowsToKeep := 10
					currentTime := time.Now().UTC().UnixMilli()
					cutoffTime := currentTime - int64(collectorRetentionPeriodDays*24*60*60*1000)

					cleanupTable := func(tableName string) {
						var totalRows int
						err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&totalRows)
						if err != nil {
							log.Printf("Error counting rows in %s: %v", tableName, err)
							return
						}

						if totalRows > totalRowsToKeep {
							_, err = db.Exec(fmt.Sprintf(`DELETE FROM %s WHERE CAST(time AS BIGINT) < ? AND time NOT IN (SELECT time FROM %s ORDER BY time DESC LIMIT ?)`, tableName, tableName),
								cutoffTime, totalRowsToKeep)
							if err != nil {
								log.Printf("Error deleting old data from %s: %v", tableName, err)
							}
						}
					}

					// checkpoint()
					// vacuum()

					cleanupTable("cpu_usage")
					cleanupTable("memory_usage")
					cleanupTable("container_cpu_usage")
					cleanupTable("container_memory_usage")

				}()
			}
		}
	}()
}

func collectContainerMetrics(queryTimeInUnixString string) {
	// Container usage
	ctx := context.Background()
	apiClient, err := client.NewClientWithOpts()
	if err != nil {
		return
	}
	apiClient.NegotiateAPIVersion(ctx)
	defer apiClient.Close()

	containers, err := apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return
	}

	var wg sync.WaitGroup
	metricsChannel := make(chan ContainerMetrics, len(containers))
	errChannel := make(chan error, len(containers))

	for _, container := range containers {
		wg.Add(1)
		go func(container types.Container) {
			defer wg.Done()
			containerNameFromLabel := container.Labels["coolify.name"]
			if containerNameFromLabel == "" {
				containerNameFromLabel = container.Names[0][1:]
			}

			stats, err := apiClient.ContainerStats(ctx, container.ID, false)
			if err != nil {
				errChannel <- fmt.Errorf("Error getting container stats for %s: %v", containerNameFromLabel, err)
				return
			}
			defer stats.Body.Close()

			var v types.StatsJSON
			dec := JSON.NewDecoder(stats.Body)
			if err := dec.Decode(&v); err != nil {
				if err != io.EOF {
					errChannel <- fmt.Errorf("Error decoding container stats for %s: %v", containerNameFromLabel, err)
				}
				return
			}

			metrics := ContainerMetrics{
				Name:                  containerNameFromLabel,
				CPUUsagePercentage:    calculateCPUPercent(v),
				MemoryUsagePercentage: calculateMemoryPercent(v),
				MemoryUsed:            calculateMemoryUsed(v),
				MemoryAvailable:       v.MemoryStats.Limit,
			}

			metricsChannel <- metrics
		}(container)
	}

	go func() {
		wg.Wait()
		close(metricsChannel)
		close(errChannel)
	}()

	for err := range errChannel {
		log.Println(err)
	}

	for metrics := range metricsChannel {
		_, err = db.Exec(`INSERT INTO container_cpu_usage (time, container_id, percent) VALUES (?, ?, ?)`,
			queryTimeInUnixString, metrics.Name, fmt.Sprintf("%.2f", metrics.CPUUsagePercentage))
		if err != nil {
			log.Printf("Error inserting container CPU usage into database: %v", err)
		}

		_, err = db.Exec(`INSERT INTO container_memory_usage (time, container_id, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			queryTimeInUnixString, metrics.Name, metrics.MemoryAvailable, metrics.MemoryAvailable, metrics.MemoryUsed, metrics.MemoryUsagePercentage, metrics.MemoryAvailable-metrics.MemoryUsed)
		if err != nil {
			log.Printf("Error inserting container memory usage into database: %v", err)
		}
	}
}
func cleanup() {
	fmt.Printf("[%s] Removing old data.\n", time.Now().Format("2006-01-02 15:04:05"))

	cutoffTime := time.Now().AddDate(0, 0, -collectorRetentionPeriodDays).UnixMilli()

	_, err := db.Exec(`DELETE FROM cpu_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old data: %v", err)
	}

	_, err = db.Exec(`DELETE FROM memory_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old memory data: %v", err)
	}

	go func() {
		for {
			time.Sleep(24 * time.Hour)
			cleanup()
		}
	}()
}

func calculateCPUPercent(stat types.StatsJSON) float64 {
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage) - float64(stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage) - float64(stat.PreCPUStats.SystemUsage)
	numberOfCpus := stat.CPUStats.OnlineCPUs
	return (cpuDelta / systemDelta) * float64(numberOfCpus) * 100.0
}

func calculateMemoryPercent(stat types.StatsJSON) float64 {
	usedMemory := float64(stat.MemoryStats.Usage) - float64(stat.MemoryStats.Stats["cache"])
	availableMemory := float64(stat.MemoryStats.Limit)
	return (usedMemory / availableMemory) * 100.0
}
func calculateMemoryUsed(stat types.StatsJSON) uint64 {
	return (stat.MemoryStats.Usage) / 1024 / 1024
}
