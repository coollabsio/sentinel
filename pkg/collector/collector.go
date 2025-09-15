package collector

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"sync"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
	"github.com/coollabsio/sentinel/pkg/dockerClient"
	"github.com/coollabsio/sentinel/pkg/json"
	"github.com/coollabsio/sentinel/pkg/types"
	"github.com/coollabsio/sentinel/pkg/utils"
	dockerTypes "github.com/docker/docker/api/types"
	dockerContainer "github.com/docker/docker/api/types/container"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

type Collector struct {
	config   *config.Config
	client   *dockerClient.DockerClient
	database *db.Database
}

func New(config *config.Config, database *db.Database, dockerClient *dockerClient.DockerClient) *Collector {
	return &Collector{
		config:   config,
		client:   dockerClient,
		database: database,
	}
}

func (c *Collector) Run(ctx context.Context) {
	fmt.Printf("[%s] Starting metrics recorder with refresh rate of %d seconds and retention period of %d days.\n", time.Now().Format("2006-01-02 15:04:05"), c.config.RefreshRateSeconds, c.config.CollectorRetentionPeriodDays)

	ticker := time.NewTicker(time.Duration(c.config.RefreshRateSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Printf("[%s] Stopping metrics recorder.\n", time.Now().Format("2006-01-02 15:04:05"))
			return
		case <-ticker.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Recovered from panic in collector: %v", r)
					}
				}()

				queryTimeInUnixString := utils.GetUnixTimeInMilliUTC()

				// CPU usage
				overallPercentage, err := cpu.Percent(0, false)
				if err != nil {
					log.Printf("Error getting CPU percentage: %v", err)
					return
				}

				_, err = c.database.Exec(`INSERT OR REPLACE INTO cpu_usage (time, percent) VALUES (?, ?)`, queryTimeInUnixString, fmt.Sprintf("%.2f", overallPercentage[0]))
				if err != nil {
					log.Printf("Error inserting CPU usage into database: %v", err)
				} else if c.config.Debug {
					log.Printf("[DEBUG] Inserted CPU usage - time: %s, percent: %.2f", queryTimeInUnixString, overallPercentage[0])
				}

				c.collectContainerMetrics(queryTimeInUnixString)

				// Memory usage
				memory, err := mem.VirtualMemory()
				if err != nil {
					log.Printf("Error getting memory usage: %v", err)
					return
				}

				_, err = c.database.Exec(`INSERT OR REPLACE INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?)`,
					queryTimeInUnixString, memory.Total, memory.Available, memory.Used, math.Round(memory.UsedPercent*100)/100, memory.Free)
				if err != nil {
					log.Printf("Error inserting memory usage into database: %v", err)
				} else if c.config.Debug {
					log.Printf("[DEBUG] Inserted memory usage - time: %s, total: %d, used: %d, usedPercent: %.2f",
						queryTimeInUnixString, memory.Total, memory.Used, math.Round(memory.UsedPercent*100)/100)
				}

				// Cleanup old data
				totalRowsToKeep := 10
				currentTime := time.Now().UTC().UnixMilli()
				cutoffTime := currentTime - int64(c.config.CollectorRetentionPeriodDays*24*60*60*1000)

				cleanupTable := func(tableName string) {
					var totalRows int
					err := c.database.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)).Scan(&totalRows)
					if err != nil {
						log.Printf("Error counting rows in %s: %v", tableName, err)
						return
					}

					if totalRows > totalRowsToKeep {
						_, err = c.database.Exec(fmt.Sprintf(`DELETE FROM %s WHERE CAST(time AS BIGINT) < ? AND time NOT IN (SELECT time FROM %s ORDER BY time DESC LIMIT ?)`, tableName, tableName),
							cutoffTime, totalRowsToKeep)
						if err != nil {
							log.Printf("Error deleting old data from %s: %v", tableName, err)
						}
					}
				}

				cleanupTable("cpu_usage")
				cleanupTable("memory_usage")
				cleanupTable("container_cpu_usage")
				cleanupTable("container_memory_usage")

			}()
		}
	}
}

func (c *Collector) collectContainerMetrics(queryTimeInUnixString string) {
	// Container usage
	// Use makeDockerRequest to interact with Docker API
	resp, err := c.client.MakeRequest("/containers/json?all=true")
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return
	}
	defer resp.Body.Close()

	containersOutput, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading containers response: %v", err)
		return
	}

	if len(containersOutput) == 0 {
		log.Println("No containers found or empty response")
		return
	}

	var containers []dockerTypes.Container
	if err := json.Unmarshal(containersOutput, &containers); err != nil {
		log.Printf("Error unmarshalling container list: %v", err)
		return
	}

	var wg sync.WaitGroup
	metricsChannel := make(chan types.ContainerMetrics, len(containers))
	errChannel := make(chan error, len(containers))

	// Create a worker pool to limit concurrent Docker API requests
	// Using 10 workers as a reasonable default - can be made configurable
	const maxWorkers = 10
	workerCount := maxWorkers
	if len(containers) < maxWorkers {
		workerCount = len(containers)
	}

	containersChan := make(chan dockerTypes.Container, len(containers))

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for container := range containersChan {
				containerNameFromLabel := container.Labels["coolify.name"]
				if containerNameFromLabel == "" {
					// Safe name extraction with bounds checking
					if len(container.Names) > 0 && len(container.Names[0]) > 1 {
						containerNameFromLabel = container.Names[0][1:] // Remove leading '/'
					} else if len(container.Names) > 0 {
						containerNameFromLabel = container.Names[0]
					} else {
						containerNameFromLabel = container.ID[:12] // Use short ID as fallback
						log.Printf("Warning: Container %s has no names, using ID as name", container.ID)
					}
				}

				resp, err := c.client.MakeRequest(fmt.Sprintf("/containers/%s/stats?stream=false", container.ID))
				if err != nil {
					errChannel <- fmt.Errorf("Error getting container stats for %s: %v", containerNameFromLabel, err)
					continue
				}

				statsOutput, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					errChannel <- fmt.Errorf("Error reading container stats for %s: %v", containerNameFromLabel, err)
					continue
				}

				var v dockerContainer.StatsResponse
				if err := json.Unmarshal(statsOutput, &v); err != nil {
					errChannel <- fmt.Errorf("Error decoding container stats for %s: %v", containerNameFromLabel, err)
					continue
				}

				metrics := types.ContainerMetrics{
					Name:                  containerNameFromLabel,
					CPUUsagePercentage:    calculateCPUPercent(v),
					MemoryUsagePercentage: calculateMemoryPercent(v),
					MemoryUsed:            calculateMemoryUsed(v),
					MemoryAvailable:       v.MemoryStats.Limit,
				}

				metricsChannel <- metrics
			}
		}()
	}

	// Feed containers to workers
	for _, container := range containers {
		containersChan <- container
	}
	close(containersChan)

	go func() {
		wg.Wait()
		close(metricsChannel)
		close(errChannel)
	}()

	// Process errors in a separate goroutine to avoid blocking
	go func() {
		for err := range errChannel {
			log.Println(err)
		}
	}()

	// Collect all metrics for batch insert
	var allMetrics []types.ContainerMetrics
	for metrics := range metricsChannel {
		allMetrics = append(allMetrics, metrics)
	}

	// Batch insert all container metrics
	if len(allMetrics) > 0 {
		// Begin transaction for better performance
		tx, err := c.database.Begin()
		if err != nil {
			log.Printf("Error starting transaction: %v", err)
			return
		}
		defer tx.Rollback()

		// Prepare statements for batch inserts
		cpuStmt, err := tx.Prepare(`INSERT OR REPLACE INTO container_cpu_usage (time, container_id, percent) VALUES (?, ?, ?)`)
		if err != nil {
			log.Printf("Error preparing CPU statement: %v", err)
			return
		}
		defer cpuStmt.Close()

		memStmt, err := tx.Prepare(`INSERT OR REPLACE INTO container_memory_usage (time, container_id, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			log.Printf("Error preparing memory statement: %v", err)
			return
		}
		defer memStmt.Close()

		// Execute batch inserts
		for _, metrics := range allMetrics {
			_, err = cpuStmt.Exec(queryTimeInUnixString, metrics.Name, fmt.Sprintf("%.2f", metrics.CPUUsagePercentage))
			if err != nil {
				log.Printf("Error inserting container CPU usage into database: %v", err)
			} else if c.config.Debug {
				log.Printf("[DEBUG] Inserted container CPU - time: %s, id: %s, percent: %.2f",
					queryTimeInUnixString, metrics.Name, metrics.CPUUsagePercentage)
			}

			_, err = memStmt.Exec(queryTimeInUnixString, metrics.Name, metrics.MemoryAvailable, metrics.MemoryAvailable,
				metrics.MemoryUsed, fmt.Sprintf("%.2f", metrics.MemoryUsagePercentage), metrics.MemoryAvailable-metrics.MemoryUsed)
			if err != nil {
				log.Printf("Error inserting container memory usage into database: %v", err)
			} else if c.config.Debug {
				log.Printf("[DEBUG] Inserted container memory - time: %s, id: %s, total: %d, used: %d, usedPercent: %.2f",
					queryTimeInUnixString, metrics.Name, metrics.MemoryAvailable, metrics.MemoryUsed, metrics.MemoryUsagePercentage)
			}
		}

		// Commit transaction
		if err = tx.Commit(); err != nil {
			log.Printf("Error committing transaction: %v", err)
		}
	}
}

func calculateCPUPercent(stat dockerContainer.StatsResponse) float64 {
	cpuDelta := float64(stat.CPUStats.CPUUsage.TotalUsage) - float64(stat.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stat.CPUStats.SystemUsage) - float64(stat.PreCPUStats.SystemUsage)
	numberOfCpus := stat.CPUStats.OnlineCPUs
	return (cpuDelta / systemDelta) * float64(numberOfCpus) * 100.0
}

func calculateMemoryPercent(stat dockerContainer.StatsResponse) float64 {
	usedMemory := float64(stat.MemoryStats.Usage) - float64(stat.MemoryStats.Stats["cache"])
	availableMemory := float64(stat.MemoryStats.Limit)
	return (usedMemory / availableMemory) * 100.0
}

func calculateMemoryUsed(stat dockerContainer.StatsResponse) uint64 {
	return (stat.MemoryStats.Usage) / 1024 / 1024
}
