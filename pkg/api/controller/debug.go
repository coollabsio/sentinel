package controller

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/mem"
)

func (c *Controller) setupDebugRoutes() {
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