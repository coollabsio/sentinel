package main

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
)

type CpuUsage struct {
	Time              string `json:"time"`
	Percent           string `json:"percent"`
	HumanFriendlyTime string `json:"human_friendly_time,omitempty"`
}

func setupCpuRoutes(r *gin.Engine) {
	r.GET("/api/cpu/current", func(c *gin.Context) {
		queryTimeInUnixString := getUnixTimeInMilliUTC()
		overallPercentage, err := cpu.Percent(0, false)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"time": queryTimeInUnixString, "percent": overallPercentage[0]})
	})
	r.GET("/api/cpu/history", func(c *gin.Context) {
		from := c.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:00Z"
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

		query := "SELECT * FROM cpu_usage"
		var params []interface{}
		if from != "" {
			fromTime, _ := time.Parse(layout, from)
			query += " WHERE CAST(time AS BIGINT) >= ?"
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
			if err := rows.Scan(&usage.Time, &usage.Percent); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if gin.Mode() == gin.DebugMode {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		c.JSON(200, usages)
	})
}
