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

var version string = "0.0.4"
var logsDir string = "/app/logs"
var metricsDir string = "/app/metrics"

// Arguments
var token string
var refreshRateSeconds int = 5
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
	}
	if err := os.MkdirAll(logsDir, 0600); err != nil {
		log.Fatalf("Error creating metrics directory: %v", err)
	}
	if err := os.MkdirAll(metricsDir, 0600); err != nil {
		log.Fatalf("Error creating metrics directory: %v", err)
	}

	go func() {
		if err := streamLogsToFile(); err != nil {
			log.Fatalf("Error listening to events: %v", err)
		}
	}()
	flag.StringVar(&token, "token", "", "help message for flagname")
	flag.IntVar(&refreshRateSeconds, "refresh", 5, "help message for flagname")
	flag.BoolVar(&startScheduler, "scheduler", false, "help message for flagname")
	flag.Parse()
	if os.Getenv("SCHEDULER") == "true" {
		startScheduler = true
	}
	if os.Getenv("REFRESHRATE") != "" {
		refreshRate, err := strconv.Atoi(os.Getenv("REFRESHRATE"))
		if err != nil {
			log.Fatalf("Error converting REFRESHRATE to integer: %v", err)
		}
		refreshRateSeconds = refreshRate
	}

	if startScheduler {
		fmt.Println("Starting scheduler...")
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
