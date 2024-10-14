package main

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	_ "github.com/marcboeker/go-duckdb"
)

var refreshRateSeconds int = 5

var pushEnabled bool = true
var pushIntervalSeconds int = 60
var pushPath string = "/api/v1/sentinel/push"
var pushUrl string

var db *sql.DB
var token string
var endpoint string
var metricsFile string = "db/metrics.duckdb"
var collectorEnabled bool = false
var collectorRetentionPeriodDays int = 7

func Token() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") != "Bearer "+token {
			if gin.Mode() == gin.DebugMode {
				if c.Query("token") == token {
					c.Next()
					return
				}
			}
			c.JSON(401, gin.H{
				"error": "Unauthorized",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	tokenFromEnv := os.Getenv("TOKEN")
	if tokenFromEnv == "" {
		log.Fatal("TOKEN environment variable is required")
	}
	token = tokenFromEnv

	endpointFromEnv := os.Getenv("ENDPOINT")
	if endpointFromEnv == "" {
		if gin.Mode() == gin.DebugMode {
			endpoint = "http://localhost:8000"
		} else {
			log.Fatal("ENDPOINT environment variable is required")
		}
	} else {
		// Validate that the endpoint is a valid HTTPS URL
		if !strings.HasPrefix(endpointFromEnv, "https://") {
			log.Fatal("ENDPOINT must be a valid HTTPS URL")
		}
		endpoint = endpointFromEnv
	}
	pushUrl = endpoint + pushPath

	if os.Getenv("COLLECTOR_ENABLED") != "" {
		collectorEnabledFromEnv := os.Getenv("COLLECTOR_ENABLED")
		if collectorEnabledFromEnv != "" {
			var err error
			collectorEnabled, err = strconv.ParseBool(collectorEnabledFromEnv)
			if err != nil {
				log.Printf("Error parsing COLLECTOR_ENABLED: %v", err)
			}
		}
	}
	if os.Getenv("COLLECTOR_REFRESH_RATE_SECONDS") != "" {
		refreshRateSecondsFromEnv := os.Getenv("COLLECTOR_REFRESH_RATE_SECONDS")
		if refreshRateSecondsFromEnv != "" {
			refreshRateSecondsInt, err := strconv.Atoi(refreshRateSecondsFromEnv)
			if err != nil {
				log.Printf("Error converting REFRESH_RATE_SECONDS to int: %v", err)
			} else {
				if refreshRateSecondsInt > 0 {
					refreshRateSeconds = refreshRateSecondsInt
				} else {
					log.Printf("COLLECTOR_REFRESH_RATE_SECONDS must be greater than 0, using default value: %d", refreshRateSeconds)
				}
			}
		}
	}

	if os.Getenv("COLLECTOR_RETENTION_PERIOD_DAYS") != "" {
		collectorRetentionPeriodDaysFromEnv := os.Getenv("COLLECTOR_RETENTION_PERIOD_DAYS")
		if collectorRetentionPeriodDaysFromEnv != "" {
			collectorRetentionPeriodDaysInt, err := strconv.Atoi(collectorRetentionPeriodDaysFromEnv)
			if err != nil {
				log.Printf("Error converting COLLECTOR_RETENTION_PERIOD_DAYS to int: %v", err)
			} else {
				collectorRetentionPeriodDays = collectorRetentionPeriodDaysInt
			}
		}
	}

	// create directory based on metricsFile
	dir := filepath.Dir(metricsFile)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Fatal(err)
	}
	// make sure the directory has 0750 permissions
	if err := os.Chmod(dir, 0750); err != nil {
		log.Fatal(err)
	}

	var err error
	db, err = sql.Open("duckdb", metricsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	// CPU
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cpu_usage (time VARCHAR, percent VARCHAR)`)
	if err != nil {
		log.Fatal(err)
	}

	// Memory
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS memory_usage (time VARCHAR, total VARCHAR, available VARCHAR, used VARCHAR, usedPercent VARCHAR, free VARCHAR)`)
	if err != nil {
		log.Fatal(err)
	}

	// Container Logs
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS container_logs (time VARCHAR, container_id VARCHAR, log VARCHAR)`)
	if err != nil {
		log.Fatal(err)
	}
	// Create an index on the container_logs table for better query performance
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_logs_time_container_id ON container_logs (time, container_id)`)
	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.GET("/api/health", func(c *gin.Context) {
		c.String(200, "ok")
	})

	if gin.Mode() == gin.DebugMode {
		setupPushRoute(r)
		setupDebugRoutes(r)
		setupCpuRoutes(r)
		setupContainerRoutes(r)
		setupMemoryRoutes(r)
		// setupPush()
	} else {
		setupPush()
	}

	// Collector
	if collectorEnabled {
		collector()
	}
	cleanup()
	r.Run(":8888")
}
