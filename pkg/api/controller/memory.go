package controller

import (
	"log"
	"math"
	"strconv"
	"time"

	"github.com/coollabsio/sentinel/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/mem"
)

type MemUsage struct {
	Time              string  `json:"time"`
	Total             uint64  `json:"total"`
	Available         uint64  `json:"available"`
	Used              uint64  `json:"used"`
	UsedPercent       float64 `json:"usedPercent"`
	Free              uint64  `json:"free"`
	HumanFriendlyTime string  `json:"human_friendly_time,omitempty"`
}

func (c *Controller) setupMemoryRoutes() {
	c.ginE.GET("/api/memory/current", func(ctx *gin.Context) {
		queryTimeInUnixString := utils.GetUnixTimeInMilliUTC()
		memory, err := mem.VirtualMemory()
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}

		usage := MemUsage{
			Time:        queryTimeInUnixString,
			Total:       memory.Total,
			Available:   memory.Available,
			Used:        memory.Used,
			UsedPercent: math.Round(memory.UsedPercent*100) / 100,
			Free:        memory.Free,
		}
		ctx.JSON(200, usage)
	})
	c.ginE.GET("/api/memory/history", func(ctx *gin.Context) {
		from := ctx.Query("from")
		if from == "" {
			from = "1970-01-01T00:00:00Z"
		}
		to := ctx.Query("to")
		if to == "" {
			to = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		}

		if c.config.Debug {
			log.Printf("[DEBUG] Memory history request - from: %s, to: %s", from, to)
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

		query := "SELECT * FROM memory_usage"
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
			log.Printf("[DEBUG] Executing query: %s with params: %v", query, params)
		}

		rows, err := c.database.Query(query, params...)
		if err != nil {
			log.Printf("[ERROR] Query failed: %v", err)
			ctx.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		usages := []MemUsage{}
		rowCount := 0
		for rows.Next() {
			var usage MemUsage
			var totalStr, availableStr, usedStr, usedPercentStr, freeStr string
			if err := rows.Scan(&usage.Time, &totalStr, &availableStr, &usedStr, &usedPercentStr, &freeStr); err != nil {
				log.Printf("[ERROR] Scan failed: %v", err)
				ctx.JSON(500, gin.H{"error": err.Error()})
				return
			}
			rowCount++
			if c.config.Debug {
				log.Printf("[DEBUG] Row %d scanned - time: %s, total: %s, available: %s, used: %s, usedPercent: %s, free: %s",
					rowCount, usage.Time, totalStr, availableStr, usedStr, usedPercentStr, freeStr)
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
			log.Printf("[DEBUG] Returning %d memory usage records", len(usages))
		}
		ctx.JSON(200, usages)
	})
}
