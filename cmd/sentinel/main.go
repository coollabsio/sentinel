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

var version string = "0.0.11"
var logsDir string = "/app/logs"
var metricsDir string = "/app/metrics"
var cpuMetricsFile string = metricsDir + "/cpu.csv"
var memoryMetricsFile string = metricsDir + "/memory.csv"
var diskMetricsFile string = metricsDir + "/disk.csv"

// Arguments
var token string
var refreshRateSeconds int = 5
var metricsHistoryInDays int = 30
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
		diskMetricsFile = metricsDir + "/disk.csv"
	}
	if err := os.MkdirAll(logsDir, 0700); err != nil {
		log.Fatalf("Error creating logs directory: %v", err)
	}
	if err := os.MkdirAll(metricsDir, 0700); err != nil {
		log.Fatalf("Error creating metrics directory: %v", err)
	}
	if _, err := os.Stat(cpuMetricsFile); os.IsNotExist(err) {
		err := os.WriteFile(cpuMetricsFile, []byte(cpuCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}
	if _, err := os.Stat(memoryMetricsFile); os.IsNotExist(err) {
		err := os.WriteFile(memoryMetricsFile, []byte(memoryCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}
	if _, err := os.Stat(diskMetricsFile); os.IsNotExist(err) {
		err := os.WriteFile(diskMetricsFile, []byte(diskCsvHeader), 0644)
		if err != nil {
			fmt.Printf("Error writing file: %s", err)
			return
		}
	}

	// go func() {
	// 	if err := streamLogsToFile(); err != nil {
	// 		log.Fatalf("Error listening to events: %v", err)
	// 	}
	// }()
	flag.StringVar(&token, "token", "", "Token to access the API. Default is empty, which means no token is required.")
	flag.IntVar(&refreshRateSeconds, "refresh", refreshRateSeconds, "Refresh rate in seconds. Default is 5 seconds")
	flag.IntVar(&metricsHistoryInDays, "metrics-history", metricsHistoryInDays, "Metrics history in days. Default is 30 days")
	flag.BoolVar(&startScheduler, "scheduler", false, "Start scheduler that collects metrics / data. Default is false.")
	flag.Parse()

	if os.Getenv("TOKEN") != "" {
		tokenFromEnv := os.Getenv("TOKEN")
		if tokenFromEnv != "" {
			token = tokenFromEnv
		}
	}
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
		metricsHistoryInDays = history
	}

	if startScheduler {
		fmt.Println("Starting scheduler with refresh rate of", refreshRateSeconds, "seconds and keeping history for", metricsHistoryInDays, "days.")
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
		authorized.GET("/config", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"token":                        token,
				"metrics_refresh_rate_seconds": refreshRateSeconds,
				"metrics_history_days":         metricsHistoryInDays,
				"should_start_scheduler":       startScheduler,
			})
		})
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
		authorized.GET("/container/:containerId", func(c *gin.Context) {
			metrics, err := getOneContainer(c.Param("containerId"), false)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.JSON(200, gin.H{
				"container": json.RawMessage(metrics),
			})
		})
		authorized.GET("/container/:containerId/csv", func(c *gin.Context) {
			data, err := getOneContainer(c.Param("containerId"), true)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			data = containerConfigCsvHeader + data
			c.String(200, data)
		})
		authorized.GET("/container/:containerId/metrics", func(c *gin.Context) {
			metrics, err := getOneContainerMetrics(c.Param("containerId"), false)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.JSON(200, gin.H{
				"container": json.RawMessage(metrics),
			})
		})
		authorized.GET("/container/:containerId/metrics/history", func(c *gin.Context) {
			from := c.Query("from")
			to := c.Query("to")
			usage, err := getHistoryContainerUsage(from, to, c.Param("containerId"))
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.String(200, usage)
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
			usage, err := getDiskUsage(false)
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
		authorized.GET("/disk/csv", func(c *gin.Context) {
			usage, err := getDiskUsage(true)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			usage = memoryCsvHeader + usage
			c.String(200, usage)
		})
		authorized.GET("/disk/history", func(c *gin.Context) {
			from := c.Query("from")
			to := c.Query("to")
			usage, err := getHistoryDiskUsage(from, to)
			if err != nil {
				c.JSON(500, gin.H{
					"error": err.Error(),
				})
				return
			}
			c.String(200, usage)
		})
	}

	fmt.Println("Starting API...")
	r.Run("0.0.0.0:8888")

}
