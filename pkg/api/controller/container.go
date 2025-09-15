package controller

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var containerIdRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func (c *Controller) setupContainerRoutes() {
	c.ginE.GET("/api/container/:containerId/cpu/history", func(ctx *gin.Context) {
		containerID := strings.ReplaceAll(ctx.Param("containerId"), "/", "")
		containerID = containerIdRegex.ReplaceAllString(containerID, "")
		from := ctx.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:01Z"
		}
		to := ctx.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		// Validate date format
		layout := "2006-01-02T15:04:05Z"
		if from != "" {
			if _, err := time.Parse(layout, from); err != nil {
				ctx.JSON(400, gin.H{"error": "Invalid 'from' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}
		if to != "" {
			if _, err := time.Parse(layout, to); err != nil {
				ctx.JSON(400, gin.H{"error": "Invalid 'to' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}

		var params []interface{}
		query := "SELECT time, container_id, percent FROM container_cpu_usage WHERE container_id = ?"
		params = append(params, containerID)
		if from != "" {
			fromTime, _ := time.Parse(layout, from)
			query += " AND CAST(time AS BIGINT) >= ?"
			params = append(params, fromTime.UnixMilli())
		}
		if to != "" {
			toTime, _ := time.Parse(layout, to)
			if from != "" {
				query += " AND"
			} else {
				query += " WHERE"
			}
			query += " CAST(time AS BIGINT) <= ?"
			params = append(params, toTime.UnixMilli())
		}
		query += " ORDER BY CAST(time AS BIGINT) ASC"
		rows, err := c.database.Query(query, params...)
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []CpuUsage{}
		for rows.Next() {
			var usage CpuUsage
			var containerID string
			if err := rows.Scan(&usage.Time, &containerID, &usage.Percent); err != nil {
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if gin.Mode() == gin.DebugMode {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		ctx.JSON(200, usages)
	})
	c.ginE.GET("/api/container/:containerId/memory/history", func(ctx *gin.Context) {
		containerID := strings.ReplaceAll(ctx.Param("containerId"), "/", "")
		containerID = regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(containerID, "")
		from := ctx.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:01Z"
		}
		to := ctx.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		if c.config.Debug {
			log.Printf("[DEBUG] Container memory history request - containerID: %s, from: %s, to: %s", containerID, from, to)
		}

		// Validate date format
		layout := "2006-01-02T15:04:05Z"
		if from != "" {
			if _, err := time.Parse(layout, from); err != nil {
				ctx.JSON(400, gin.H{"error": "Invalid 'from' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}
		if to != "" {
			if _, err := time.Parse(layout, to); err != nil {
				ctx.JSON(400, gin.H{"error": "Invalid 'to' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}

		var params []interface{}
		query := "SELECT time, container_id, total, available, used, usedPercent, free FROM container_memory_usage WHERE container_id = ?"
		params = append(params, containerID)
		if from != "" {
			fromTime, _ := time.Parse(layout, from)
			query += " AND CAST(time AS BIGINT) >= ?"
			params = append(params, fromTime.UnixMilli())
		}
		if to != "" {
			toTime, _ := time.Parse(layout, to)
			if from != "" {
				query += " AND"
			} else {
				query += " WHERE"
			}
			query += " CAST(time AS BIGINT) <= ?"
			params = append(params, toTime.UnixMilli())
		}
		query += " ORDER BY CAST(time AS BIGINT) ASC"

		if c.config.Debug {
			log.Printf("[DEBUG] Container memory query: %s with params: %v", query, params)
		}

		rows, err := c.database.Query(query, params...)
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []MemUsage{}
		rowCount := 0
		for rows.Next() {
			var usage MemUsage
			var containerID string
			var totalStr, availableStr, usedStr, usedPercentStr, freeStr string
			if err := rows.Scan(&usage.Time, &containerID, &totalStr, &availableStr, &usedStr, &usedPercentStr, &freeStr); err != nil {
				log.Printf("[ERROR] Container scan failed: %v", err)
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			rowCount++
			if c.config.Debug {
				log.Printf("[DEBUG] Container row %d - time: %s, id: %s, total: %s, available: %s, used: %s, usedPercent: %s, free: %s",
					rowCount, usage.Time, containerID, totalStr, availableStr, usedStr, usedPercentStr, freeStr)
			}
			usage.Total, _ = strconv.ParseUint(totalStr, 10, 64)
			usage.Available, _ = strconv.ParseUint(availableStr, 10, 64)
			usage.Used, _ = strconv.ParseUint(usedStr, 10, 64)
			usage.UsedPercent, _ = strconv.ParseFloat(usedPercentStr, 64)
			usage.Free, _ = strconv.ParseUint(freeStr, 10, 64)
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if gin.Mode() == gin.DebugMode {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		if c.config.Debug {
			log.Printf("[DEBUG] Returning %d container memory records", len(usages))
		}
		ctx.JSON(200, usages)
	})
}
