package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	 "github.com/joho/godotenv"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sync/errgroup"
)

var debug bool = false
var refreshRateSeconds int = 5

var pushEnabled bool = true
var pushIntervalSeconds int = 60
var pushPath string = "/api/v1/sentinel/push"
var pushUrl string

var db *sql.DB
var token string
var endpoint string
var metricsFile string = "/app/db/metrics.sqlite"
var collectorEnabled bool = false
var collectorRetentionPeriodDays int = 7

// HTTP client with connection pooling
var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
	Timeout: 10 * time.Second,
}

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

func HandleSignals(ctx context.Context) error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, os.Interrupt)

	select {
	case s := <-signalChan:
		switch s {
		case syscall.SIGTERM:
			return errors.New("received SIGTERM")
		case os.Interrupt: // cross-platform SIGINT
			return errors.New("received interrupt")
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

func main() {
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Println("No .env file found, skipping load")
	} else {
		err := godotenv.Load()
		if err != nil {
			log.Printf("Error loading .env file: %v", err)
		}
	}
	if gin.Mode() == gin.DebugMode {
		metricsFile = "./db/metrics.sqlite"
	}
	debugFromEnv := os.Getenv("DEBUG")
	if debugFromEnv != "" {
		var err error
		debug, err = strconv.ParseBool(debugFromEnv)
		if err != nil {
			log.Printf("Error parsing DEBUG: %v", err)
		}
	}
	if debug {
		log.Printf("[%s] Debug is enabled.", time.Now().Format("2006-01-02 15:04:05"))
	}

	tokenFromEnv := os.Getenv("TOKEN")
	if tokenFromEnv == "" {
		log.Fatal("TOKEN environment variable is required")
	}
	token = tokenFromEnv

	endpointFromEnv := os.Getenv("PUSH_ENDPOINT")
	if gin.Mode() == gin.DebugMode {
		if endpointFromEnv == "" {
			endpoint = "http://localhost:8000"
		} else {
			endpoint = endpointFromEnv
		}
	} else {
		if endpointFromEnv == "" {
			log.Fatal("PUSH_ENDPOINT environment variable is required")
		} else {
			endpoint = endpointFromEnv
		}
	}
	pushUrl = endpoint + pushPath

	if os.Getenv("PUSH_INTERVAL_SECONDS") != "" {
		pushIntervalSecondsFromEnv := os.Getenv("PUSH_INTERVAL_SECONDS")
		if pushIntervalSecondsFromEnv != "" {
			pushIntervalSecondsInt, err := strconv.Atoi(pushIntervalSecondsFromEnv)
			if err != nil {
				log.Printf("Error converting PUSH_INTERVAL_SECONDS to int: %v", err)
			} else {
				pushIntervalSeconds = pushIntervalSecondsInt
			}
		}
	}
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
	db, err = sql.Open("sqlite3", metricsFile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create tables
	// CPU
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cpu_usage (
		time VARCHAR,
		percent VARCHAR,
		PRIMARY KEY (time)
	)`)
	if err != nil {
		log.Fatal(err)
	}
	// Container CPU
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS container_cpu_usage (
		time VARCHAR,
		container_id VARCHAR,
		percent VARCHAR,
		PRIMARY KEY (time, container_id)
	)`)
	if err != nil {
		log.Fatal(err)
	}
	// Create an index on the container_cpu_usage table for better query performance
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_cpu_usage_time_container_id ON container_cpu_usage (container_id,time)`)
	if err != nil {
		log.Fatal(err)
	}

	// Memory
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS memory_usage (
		time VARCHAR,
		total VARCHAR,
		available VARCHAR,
		used VARCHAR,
		usedPercent VARCHAR,
		free VARCHAR,
		PRIMARY KEY (time)
	)`)
	if err != nil {
		log.Fatal(err)
	}
	// Container Memory
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS container_memory_usage (
		time VARCHAR,
		container_id VARCHAR,
		total VARCHAR,
		available VARCHAR,
		used VARCHAR,
		usedPercent VARCHAR,
		free VARCHAR,
		PRIMARY KEY (time, container_id)
	)`)
	if err != nil {
		log.Fatal(err)
	}
	// Create an index on the container_memory_usage table for better query performance
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_memory_usage_time_container_id ON container_memory_usage (time, container_id)`)
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
	} else {
		setupCpuRoutes(r)
		setupContainerRoutes(r)
		setupMemoryRoutes(r)
	}
	if debug {
		r.GET("/debug/pprof", func(c *gin.Context) {
			pprof.Index(c.Writer, c.Request)
		})
		r.GET("/debug/cmdline", func(c *gin.Context) {
			pprof.Cmdline(c.Writer, c.Request)
		})
		r.GET("/debug/profile", func(c *gin.Context) {
			pprof.Profile(c.Writer, c.Request)
		})
		r.GET("/debug/symbol", func(c *gin.Context) {
			pprof.Symbol(c.Writer, c.Request)
		})
		r.GET("/debug/trace", func(c *gin.Context) {
			pprof.Trace(c.Writer, c.Request)
		})
		r.GET("/debug/heap", func(c *gin.Context) {
			pprof.Handler("heap").ServeHTTP(c.Writer, c.Request)
		})
		r.GET("/debug/goroutine", func(c *gin.Context) {
			pprof.Handler("goroutine").ServeHTTP(c.Writer, c.Request)
		})
		r.GET("/debug/block", func(c *gin.Context) {
			pprof.Handler("block").ServeHTTP(c.Writer, c.Request)
		})
	}
	group, gCtx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		return HandleSignals(gCtx)
	})
	group.Go(func() error {
		setupPush(gCtx)
		return nil
	})
	// Collector
	if collectorEnabled {
		group.Go(func() error {
			collector(gCtx)
			return nil
		})
	}
	cleanup()
	srv := &http.Server{
		Addr:    ":8888",
		Handler: r.Handler(),
	}
	group.Go(func() error {
		errorChan := make(chan error, 1)
		go func() {
			defer close(errorChan)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errorChan <- err
			}
		}()
		select {
		case <-gCtx.Done():
			return nil // context cancelled
		case err := <-errorChan:
			return err
		}
	})
	if err := group.Wait(); err != nil {
		switch err.Error() {
		case "received SIGTERM":
			log.Println("received SIGTERM shutting down")
		case "received interrupt":
			log.Println("received interrupt shutting down")
		default:
			log.Fatal(err) // unexpected error
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal(err) // failure/timeout shutting down the server gracefully
	}
	select {
	case <-ctx.Done():
		log.Println("server shutdown")
	}
}

func makeDockerRequest(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://localhost"+url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Use Unix socket transport
	httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial("unix", "/var/run/docker.sock")
	}

	return httpClient.Do(req)
}
