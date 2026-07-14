package controller

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/mem"
)

func (c *Controller) setupDebugRoutes() {
	c.ginE.GET("/api/stats", func(ctx *gin.Context) {
		memory, err := mem.VirtualMemory()
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		var pageCount, pageSize int64
		if err := c.database.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		if err := c.database.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		tableStats := []struct {
			name      string
			sizeQuery string
		}{
			{"cpu_usage", "SELECT COALESCE(SUM(LENGTH(time) + LENGTH(percent)), 0) FROM cpu_usage"},
			{"memory_usage", "SELECT COALESCE(SUM(LENGTH(time) + LENGTH(total) + LENGTH(available) + LENGTH(used) + LENGTH(usedPercent) + LENGTH(free)), 0) FROM memory_usage"},
			{"container_cpu_usage", "SELECT COALESCE(SUM(LENGTH(time) + LENGTH(container_id) + LENGTH(percent)), 0) FROM container_cpu_usage"},
			{"container_memory_usage", "SELECT COALESCE(SUM(LENGTH(time) + LENGTH(container_id) + LENGTH(total) + LENGTH(available) + LENGTH(used) + LENGTH(usedPercent) + LENGTH(free)), 0) FROM container_memory_usage"},
			{"container_logs", "SELECT COALESCE(SUM(LENGTH(time) + LENGTH(container_id) + LENGTH(log)), 0) FROM container_logs"},
		}
		tables := make([]gin.H, 0, len(tableStats))
		totalRows := 0
		for _, table := range tableStats {
			var rowCount int
			if err := c.database.QueryRow("SELECT COUNT(*) FROM " + table.name).Scan(&rowCount); err != nil {
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			totalRows += rowCount

			var sizeBytes int64
			if err := c.database.QueryRow(table.sizeQuery).Scan(&sizeBytes); err != nil {
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			tables = append(tables, gin.H{
				"table_name": table.name,
				"row_count":  rowCount,
				"size_mb":    fmt.Sprintf("%.2f", float64(sizeBytes)/(1024*1024)),
				"size_kb":    fmt.Sprintf("%.2f", float64(sizeBytes)/1024),
			})
		}

		storageBytes := pageCount * pageSize
		ctx.JSON(200, gin.H{
			"row_count":        totalRows,
			"storage_usage_kb": fmt.Sprintf("%.2f", float64(storageBytes)/1024),
			"storage_usage_mb": fmt.Sprintf("%.2f", float64(storageBytes)/(1024*1024)),
			"memory_usage":     memory,
			"table_sizes":      tables,
		})
	})
}
