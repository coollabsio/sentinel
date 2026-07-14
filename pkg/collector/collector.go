package collector

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
	"github.com/coollabsio/sentinel/pkg/json"
	"github.com/coollabsio/sentinel/pkg/types"
	"github.com/coollabsio/sentinel/pkg/utils"
	dockerContainer "github.com/moby/moby/api/types/container"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

type Collector struct {
	config   *config.Config
	client   dockerAPI
	database *db.Database
}

type dockerAPI interface {
	MakeRequest(context.Context, string) (*http.Response, error)
}

func New(config *config.Config, database *db.Database, dockerClient dockerAPI) *Collector {
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

				c.collectContainerMetrics(ctx, queryTimeInUnixString)

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

			}()
		}
	}
}

func (c *Collector) collectContainerMetrics(ctx context.Context, queryTimeInUnixString string) {
	// Container usage
	// Use makeDockerRequest to interact with Docker API
	resp, err := c.client.MakeRequest(ctx, "/containers/json?all=true")
	if err != nil {
		log.Printf("Error getting containers: %v", err)
		return
	}
	if resp == nil || resp.Body == nil {
		log.Printf("Error getting containers: empty Docker response")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	containersOutput, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading containers response: %v", err)
		return
	}

	if len(containersOutput) == 0 {
		log.Println("No containers found or empty response")
		return
	}

	var containers []dockerContainer.Summary
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

	containersChan := make(chan dockerContainer.Summary, len(containers))

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
						containerNameFromLabel = container.ID
						if len(containerNameFromLabel) > 12 {
							containerNameFromLabel = containerNameFromLabel[:12]
						}
						log.Printf("Warning: Container %s has no names, using ID as name", container.ID)
					}
				}

				resp, err := c.client.MakeRequest(ctx, fmt.Sprintf("/containers/%s/stats?stream=false", container.ID))
				if err != nil {
					errChannel <- fmt.Errorf("get container stats for %s: %w", containerNameFromLabel, err)
					continue
				}
				if resp == nil || resp.Body == nil {
					errChannel <- fmt.Errorf("get container stats for %s: empty Docker response", containerNameFromLabel)
					continue
				}

				statsOutput, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					errChannel <- fmt.Errorf("read container stats for %s: %w", containerNameFromLabel, err)
					continue
				}

				var v dockerContainer.StatsResponse
				if err := json.Unmarshal(statsOutput, &v); err != nil {
					errChannel <- fmt.Errorf("decode container stats for %s: %w", containerNameFromLabel, err)
					continue
				}

				metrics := types.ContainerMetrics{
					Name:                  containerNameFromLabel,
					CPUUsagePercentage:    calculateCPUPercent(v),
					MemoryUsagePercentage: calculateMemoryPercent(v),
					MemoryUsed:            calculateMemoryUsed(v),
					MemoryLimit:           v.MemoryStats.Limit,
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
		defer func() { _ = tx.Rollback() }()

		// Prepare statements for batch inserts
		cpuStmt, err := tx.Prepare(`INSERT OR REPLACE INTO container_cpu_usage (time, container_id, percent) VALUES (?, ?, ?)`)
		if err != nil {
			log.Printf("Error preparing CPU statement: %v", err)
			return
		}
		defer func() { _ = cpuStmt.Close() }()

		memStmt, err := tx.Prepare(`INSERT OR REPLACE INTO container_memory_usage (time, container_id, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			log.Printf("Error preparing memory statement: %v", err)
			return
		}
		defer func() { _ = memStmt.Close() }()

		// Execute batch inserts
		for _, metrics := range allMetrics {
			_, err = cpuStmt.Exec(queryTimeInUnixString, metrics.Name, fmt.Sprintf("%.2f", metrics.CPUUsagePercentage))
			if err != nil {
				log.Printf("Error inserting container CPU usage into database: %v", err)
			} else if c.config.Debug {
				log.Printf("[DEBUG] Inserted container CPU - time: %s, id: %s, percent: %.2f",
					queryTimeInUnixString, metrics.Name, metrics.CPUUsagePercentage)
			}

			freeMemory := uint64(0)
			if metrics.MemoryLimit > metrics.MemoryUsed {
				freeMemory = metrics.MemoryLimit - metrics.MemoryUsed
			}
			_, err = memStmt.Exec(queryTimeInUnixString, metrics.Name, metrics.MemoryLimit, freeMemory,
				metrics.MemoryUsed, fmt.Sprintf("%.2f", metrics.MemoryUsagePercentage), freeMemory)
			if err != nil {
				log.Printf("Error inserting container memory usage into database: %v", err)
			} else if c.config.Debug {
				log.Printf("[DEBUG] Inserted container memory - time: %s, id: %s, total: %d, used: %d, usedPercent: %.2f",
					queryTimeInUnixString, metrics.Name, metrics.MemoryLimit, metrics.MemoryUsed, metrics.MemoryUsagePercentage)
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
	if cpuDelta <= 0 || systemDelta <= 0 {
		return 0
	}

	numberOfCPUs := stat.CPUStats.OnlineCPUs
	if numberOfCPUs == 0 {
		numberOfCPUs = uint32(len(stat.CPUStats.CPUUsage.PercpuUsage))
	}
	if numberOfCPUs == 0 {
		return 0
	}

	return (cpuDelta / systemDelta) * float64(numberOfCPUs) * 100.0
}

func calculateMemoryPercent(stat dockerContainer.StatsResponse) float64 {
	usedMemory := float64(calculateMemoryUsed(stat))
	availableMemory := float64(stat.MemoryStats.Limit)
	if availableMemory <= 0 {
		return 0
	}
	return (usedMemory / availableMemory) * 100.0
}

func calculateMemoryUsed(stat dockerContainer.StatsResponse) uint64 {
	// Try total_inactive_file first (cgroup v1), fall back to inactive_file (cgroup v2)
	// This matches Docker CLI calculation behavior
	cacheUsage := stat.MemoryStats.Stats["total_inactive_file"]
	if cacheUsage == 0 {
		cacheUsage = stat.MemoryStats.Stats["inactive_file"]
	}
	if cacheUsage >= stat.MemoryStats.Usage {
		return 0
	}
	return stat.MemoryStats.Usage - cacheUsage
}
