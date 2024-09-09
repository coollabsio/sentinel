package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sentinel/pkg/db"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

var version string = "0.0.14"
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
	db.Init("./")
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

	// go WorkerCpuUsage(refreshRateSeconds)
	// go WorkerMemoryUsage(refreshRateSeconds)
	// go WorkerDiskUsage(refreshRateSeconds)

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
			c.Writer.WriteHeader(200)
			c.Writer.WriteString(cpuCsvHeader)
			db.ReadRange("cpu", 0, int(time.Now().Unix()), func(in CpuUsage) {
				c.Writer.WriteString(fmt.Sprintf("%s,%s\n", in.Time, in.Percent))
			})
		})
		authorized.GET("/cpu/history", func(c *gin.Context) {
			from, to, err := ParseFromTo(c.Query("from"), c.Query("to"))
			if err != nil {
				c.JSON(500, gin.H{
					"error": "Invalid from or to",
				})
			}

			c.Writer.WriteHeader(200)
			c.Writer.WriteString(cpuCsvHeader)
			db.ReadRange("cpu", from, to, func(in CpuUsage) {
				c.Writer.WriteString(fmt.Sprintf("%s,%s\n", in.Time, in.Percent))
			})
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
			c.Writer.WriteHeader(200)
			c.Writer.WriteString(memoryCsvHeader)
			db.ReadRange("memory", 0, int(time.Now().Unix()), func(in MemUsage) {
				c.Writer.WriteString(fmt.Sprintf("%s,%d,%d,%.2f\n", in.Time, in.Used, in.Free, in.UsedPercent))
			})
		})
		authorized.GET("/memory/history", func(c *gin.Context) {
			from, to, err := ParseFromTo(c.Query("from"), c.Query("to"))
			if err != nil {
				c.JSON(500, gin.H{
					"error": "Invalid from or to",
				})
			}

			c.Writer.WriteHeader(200)
			c.Writer.WriteString(memoryCsvHeader)
			db.ReadRange("memory", from, to, func(in MemUsage) {
				c.Writer.WriteString(fmt.Sprintf("%s,%d,%d,%.2f\n", in.Time, in.Used, in.Free, in.UsedPercent))
			})
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
			c.Writer.WriteHeader(200)
			c.Writer.WriteString(diskCsvHeader)
			db.ReadRange("disk", 0, int(time.Now().Unix()), func(in []DiskUsage) {
				for {
					if len(in) == 0 {
						break
					}
					c.Writer.WriteString(fmt.Sprintf("%s,%s,%s,%d,%d,%s\n", in[0].Time, in[0].Disk, in[0].MountPoint, in[0].Total, in[0].Free, in[0].Usage))
					in = in[1:]
				}
			})

		})
		authorized.GET("/disk/history", func(c *gin.Context) {
			tmpfrom := c.Query("from")
			tmpto := c.Query("to")
			if tmpfrom == "" {
				tmpfrom = "0"
			}
			if tmpto == "" {
				tmpto = fmt.Sprintf("%d", time.Now().Unix())
			}
			from, errFrom := strconv.Atoi(tmpfrom)
			to, errTo := strconv.Atoi(tmpto)
			if errFrom != nil || errTo != nil {
				c.JSON(500, gin.H{
					"error": "Invalid from or to",
				})
			}

			c.Writer.WriteHeader(200)
			c.Writer.WriteString(diskCsvHeader)
			db.ReadRange("disk", from, to, func(in []DiskUsage) {
				for {
					if len(in) == 0 {
						break
					}
					c.Writer.WriteString(fmt.Sprintf("%s,%s,%s,%d,%d,%s\n", in[0].Time, in[0].Disk, in[0].MountPoint, in[0].Total, in[0].Free, in[0].Usage))
					in = in[1:]
				}
			})
		})
	}

	fmt.Println("Starting API...")
	r.Run("0.0.0.0:8888")

}
