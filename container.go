package main

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Container struct {
	Time         string            `json:"time"`
	ID           string            `json:"id"`
	Image        string            `json:"image"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Labels       map[string]string `json:"labels"`
	HealthStatus string            `json:"health_status"`
}

var containerIdRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func setupContainerRoutes(r *gin.Engine) {
	r.GET("/api/container/:containerId/cpu/history", func(c *gin.Context) {
		containerID := strings.ReplaceAll(c.Param("containerId"), "/", "")
		containerID = containerIdRegex.ReplaceAllString(containerID, "")
		from := c.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:01Z"
		}
		to := c.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		// Validate date format
		layout := "2006-01-02T15:04:05Z"
		if from != "" {
			if _, err := time.Parse(layout, from); err != nil {
				c.JSON(400, gin.H{"error": "Invalid 'from' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}
		if to != "" {
			if _, err := time.Parse(layout, to); err != nil {
				c.JSON(400, gin.H{"error": "Invalid 'to' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
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
		rows, err := db.Query(query, params...)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []CpuUsage{}
		for rows.Next() {
			var usage CpuUsage
			var containerID string
			if err := rows.Scan(&usage.Time, &containerID, &usage.Percent); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if debug {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		c.JSON(200, usages)
	})
	r.GET("/api/container/:containerId/memory/history", func(c *gin.Context) {
		containerID := strings.ReplaceAll(c.Param("containerId"), "/", "")
		containerID = regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(containerID, "")
		from := c.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:01Z"
		}
		to := c.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		// Validate date format
		layout := "2006-01-02T15:04:05Z"
		if from != "" {
			if _, err := time.Parse(layout, from); err != nil {
				c.JSON(400, gin.H{"error": "Invalid 'from' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
				return
			}
		}
		if to != "" {
			if _, err := time.Parse(layout, to); err != nil {
				c.JSON(400, gin.H{"error": "Invalid 'to' date format. Use YYYY-MM-DDTHH:MM:SSZ"})
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
		rows, err := db.Query(query, params...)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []MemUsage{}
		for rows.Next() {
			var usage MemUsage
			var containerID string
			if err := rows.Scan(&usage.Time, &containerID, &usage.Total, &usage.Available, &usage.Used, &usage.UsedPercent, &usage.Free); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if debug {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		c.JSON(200, usages)
	})
}
