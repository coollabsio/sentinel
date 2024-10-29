package controller

import (
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"time"

	"github.com/coollabsio/sentinel/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/mem"
)

func (c *Controller) setupDebugRoutes() {
	c.ginE.GET("/api/export/cpu_usage/csv", func(ctx *gin.Context) {
		rows, err := c.database.Query("COPY cpu_usage TO 'output/cpu_usage.csv';")
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
	})
	c.ginE.GET("/api/load/cpu", func(ctx *gin.Context) {
		createTestCpuData(c.database)
		ctx.String(200, "ok, cpu load running in the background")
	})
	c.ginE.GET("/api/load/memory", func(ctx *gin.Context) {
		createTestMemoryData(c.database)
		ctx.String(200, "ok, memory load running in the background")
	})

	c.ginE.GET("/api/vacuum", func(ctx *gin.Context) {
		c.database.Vacuum()
		ctx.String(200, "ok")
	})

	c.ginE.GET("/api/checkpoint", func(ctx *gin.Context) {
		c.database.Checkpoint()
		ctx.String(200, "ok")
	})

	c.ginE.GET("/api/stats", func(ctx *gin.Context) {
		var count int
		var storageUsage int64
		err := c.database.QueryRow("SELECT COUNT(*), SUM(LENGTH(time) + LENGTH(percent)) FROM cpu_usage").Scan(&count, &storageUsage)
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		// Convert storage usage to KB
		storageKB := float64(storageUsage) / 1024
		// add memory stats
		memory, err := mem.VirtualMemory()
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		// Query to get table names and their sizes
		rows, err := c.database.Query(`
			SELECT
				table_name,
				SUM(estimated_size) AS total_size
			FROM duckdb_tables()
			GROUP BY table_name
			ORDER BY total_size DESC
		`)
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var tables []gin.H
		for rows.Next() {
			var tableName string
			var sizeBytes int64
			if err := rows.Scan(&tableName, &sizeBytes); err != nil {
				log.Printf("Error scanning row: %v", err)
				continue
			}

			// Convert bytes to MB for readability
			sizeMB := float64(sizeBytes) / (1024 * 1024)

			tables = append(tables, gin.H{
				"table_name": tableName,
				"size_mb":    fmt.Sprintf("%.2f", sizeMB),
				"size_kb":    fmt.Sprintf("%.2f", sizeMB*1024),
			})
		}

		if err := rows.Err(); err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(200, gin.H{
			"row_count":        count,
			"storage_usage_kb": fmt.Sprintf("%.2f", storageKB),
			"storage_usage_mb": fmt.Sprintf("%.2f", storageKB/1024),
			"memory_usage":     memory,
			"table_sizes":      tables,
		})
	})
}

func createTestCpuData(database *db.Database) {
	go func() {
		defer func() {
			database.Checkpoint()
			database.Vacuum()
		}()

		numberOfRows := 10000
		numWorkers := 10
		jobs := make(chan int, numberOfRows)
		results := make(chan error, numberOfRows)

		// Start worker goroutines
		for w := 0; w < numWorkers; w++ {
			go func() {
				for range jobs {
					// Generate a random date within the last month
					now := time.Now()
					randomDate := now.AddDate(0, 0, -(rand.Int() % 31))

					timestamp := fmt.Sprintf("%d", randomDate.UnixNano()/int64(time.Millisecond))
					percent := fmt.Sprintf("%.1f", rand.Float64()*100)
					_, err := database.Exec(`INSERT INTO cpu_usage (time, percent) VALUES (?, ?)`, timestamp, percent)
					results <- err
				}
			}()
		}

		// Send jobs to workers
		for i := 0; i < numberOfRows; i++ {
			jobs <- i
		}
		close(jobs)

		// Collect results
		for i := 0; i < numberOfRows; i++ {
			if err := <-results; err != nil {
				log.Printf("Error inserting test data: %v", err)
			}
		}
	}()
}

func createTestMemoryData(database *db.Database) {
	go func() {
		defer func() {
			database.Checkpoint()
			database.Vacuum()
		}()

		numberOfRows := 10000
		numWorkers := 10
		jobs := make(chan int, numberOfRows)
		results := make(chan error, numberOfRows)

		// Start worker goroutines
		for w := 0; w < numWorkers; w++ {
			go func() {
				for range jobs {
					// Generate a random date within the last month
					now := time.Now()
					randomDate := now.AddDate(0, 0, -(rand.Int() % 31))

					timestamp := fmt.Sprintf("%d", randomDate.UnixNano()/int64(time.Millisecond))
					memory, err := mem.VirtualMemory()
					usage := MemUsage{
						Time:        timestamp,
						Total:       memory.Total,
						Available:   memory.Available,
						Used:        memory.Used,
						UsedPercent: math.Round(memory.UsedPercent*100) / 100,
						Free:        memory.Free,
					}
					if err != nil {
						log.Printf("Error getting memory usage: %v", err)
						continue
					}
					_, err = database.Exec(`INSERT INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, ?, ?, ?, ?, ?)`, usage.Time, usage.Total, usage.Available, usage.Used, usage.UsedPercent, usage.Free)
					results <- err
				}
			}()
		}

		// Send jobs to workers
		for i := 0; i < numberOfRows; i++ {
			jobs <- i
		}
		close(jobs)

		// Collect results
		for i := 0; i < numberOfRows; i++ {
			if err := <-results; err != nil {
				log.Printf("Error inserting test data: %v", err)
			}
		}
	}()
}
