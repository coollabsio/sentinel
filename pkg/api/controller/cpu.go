package controller

import (
	"log"
	"strconv"
	"time"

	"github.com/coollabsio/sentinel/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
)

type CpuUsage struct {
	Time              string `json:"time"`
	Percent           string `json:"percent"`
	HumanFriendlyTime string `json:"human_friendly_time,omitempty"`
}

func (c *Controller) setupCpuRoutes() {
	c.ginE.GET("/api/cpu/current", func(ctx *gin.Context) {
		queryTimeInUnixString := utils.GetUnixTimeInMilliUTC()
		overallPercentage, err := cpu.Percent(0, false)
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(200, gin.H{"time": queryTimeInUnixString, "percent": overallPercentage[0]})
	})
	c.ginE.GET("/api/cpu/history", func(ctx *gin.Context) {
		from := ctx.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:00Z"
		}
		to := ctx.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		if c.config.Debug {
			log.Printf("[DEBUG] CPU history request - from: %s, to: %s", from, to)
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

		if c.config.Debug {
			log.Printf("[DEBUG] CPU query: %s with params: %v", query, params)
		}

		rows, err := c.database.Query(query, params...)
		if err != nil {
			log.Printf("[ERROR] CPU query failed: %v", err)
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []CpuUsage{}
		rowCount := 0
		for rows.Next() {
			var usage CpuUsage
			if err := rows.Scan(&usage.Time, &usage.Percent); err != nil {
				log.Printf("[ERROR] CPU scan failed: %v", err)
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			rowCount++
			if c.config.Debug {
				log.Printf("[DEBUG] CPU row %d - time: %s, percent: %s", rowCount, usage.Time, usage.Percent)
			}
			timeInt, _ := strconv.ParseInt(usage.Time, 10, 64)
			if gin.Mode() == gin.DebugMode {
				usage.HumanFriendlyTime = time.UnixMilli(timeInt).Format(layout)
			}
			usages = append(usages, usage)
		}
		if c.config.Debug {
			log.Printf("[DEBUG] Returning %d CPU usage records", len(usages))
		}
		ctx.JSON(200, usages)
	})
}
