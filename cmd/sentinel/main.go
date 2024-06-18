package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

var version string = "0.0.5"
var logsDir string = "/app/logs"
var metricsDir string = "/app/metrics"
var cpuMetricsFile string = metricsDir + "/cpu.csv"
var memoryMetricsFile string = metricsDir + "/memory.csv"

// Arguments
var token string
var refreshRateSeconds int = 5
var metricsHistoryInMinutes int = 43200
var startScheduler bool = false

func Token() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token != "" {
			if c.GetHeader("Authorization") != "Bearer "+token {
				c.JSON(401, gin.H{
					"error": "Unauthorized",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
func main() {
	if gin.Mode() == gin.DebugMode {
		logsDir = "./logs"
		metricsDir = "./metrics"
		cpuMetricsFile = metricsDir + "/cpu.csv"
		memoryMetricsFile = metricsDir + "/memory.csv"
	}
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		log.Fatalf("Error creating metrics directory: %v", err)
	}
	if err := os.MkdirAll(metricsDir, 0700); err != nil {
		log.Fatalf("Error creating metrics directory: %v", err)
	}

	// go func() {
	// 	if err := streamLogsToFile(); err != nil {
	// 		log.Fatalf("Error listening to events: %v", err)
	// 	}
	// }()
	flag.StringVar(&token, "token", "", "Token to access the API. Default is empty, which means no token is required.")
	flag.IntVar(&refreshRateSeconds, "refresh", refreshRateSeconds, "Refresh rate in seconds. Default is 5 seconds")
	flag.IntVar(&metricsHistoryInMinutes, "metrics-history", metricsHistoryInMinutes, "Metrics history in minutes. Default is 43200 minutes (30 days)")
	flag.BoolVar(&startScheduler, "scheduler", false, "Start scheduler that collects metrics / data. Default is false.")
	flag.Parse()
	if os.Getenv("SCHEDULER") == "true" {
		startScheduler = true
	}
	if os.Getenv("REFRESH_RATE") != "" {
		refreshRate, err := strconv.Atoi(os.Getenv("REFRESH_RATE"))
		if err != nil {
			log.Fatalf("Error converting REFRESH_RATE to integer: %v", err)
		}
		refreshRateSeconds = refreshRate
	}
	if os.Getenv("METRICS_HISTORY") != "" {
		history, err := strconv.Atoi(os.Getenv("METRICS_HISTORY"))
		if err != nil {
			log.Fatalf("Error converting METRICS_HISTORY to integer: %v", err)
		}
		metricsHistoryInMinutes = history
	}

	if startScheduler {
		if metricsHistoryInMinutes > 60 {
			// convert to hours
			metricsHistoryInMinutes = metricsHistoryInMinutes / 60
			fmt.Println("Starting scheduler with refresh rate of", refreshRateSeconds, "seconds and keeping history for", metricsHistoryInMinutes, "hours.")
		} else {
			fmt.Println("Starting scheduler with refresh rate of", refreshRateSeconds, "seconds and keeping history for", metricsHistoryInMinutes, "minute(s).")
		}
		scheduler()
	}

	r := gin.Default()
	r.GET("/api/health", func(c *gin.Context) {
		c.String(200, "ok")
	})
	r.GET("/api/version", func(c *gin.Context) {
		c.String(200, version)
	})
	r.Use(gin.Recovery())

	authorized := r.Group("/api")
	authorized.Use(Token())
	{
		authorized.GET("/containers", func(c *gin.Context) {
			containers, err := getAllContainers()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"containers": json.RawMessage(containers),
			})
		})
		authorized.GET("/cpu", func(c *gin.Context) {
			usage, err := getCpuUsage(false)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"cpu_usage": json.RawMessage(usage),
			})
		})
		authorized.GET("/cpu/csv", func(c *gin.Context) {
			usage, err := getCpuUsage(true)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			usage = cpuCsvHeader + usage
			c.String(200, usage)
		})
		authorized.GET("/cpu/history", func(c *gin.Context) {
			from := c.Query("from")
			to := c.Query("to")
			usage, err := getHistoryCpuUsage(from, to)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.String(200, usage)
		})
		authorized.GET("/memory", func(c *gin.Context) {
			usage, err := getMemUsage(false)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"mem_usage": json.RawMessage(usage),
			})
		})
		authorized.GET("/memory/csv", func(c *gin.Context) {
			usage, err := getMemUsage(true)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			usage = memoryCsvHeader + usage
			c.String(200, usage)
		})
		authorized.GET("/memory/history", func(c *gin.Context) {
			from := c.Query("from")
			to := c.Query("to")
			usage, err := getHistoryMemoryUsage(from, to)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.String(200, usage)
		})
		authorized.GET("/disk", func(c *gin.Context) {
			usage, err := getDiskUsage()
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}

			c.JSON(200, gin.H{
				"disk_usage": json.RawMessage(usage),
			})
		})
	}

	fmt.Println("Starting API...")
	r.Run("0.0.0.0:8888")

}
