package cmd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/coollabsio/sentinel/pkg/api"
	"github.com/coollabsio/sentinel/pkg/collector"
	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
	"github.com/coollabsio/sentinel/pkg/dockerClient"
	"github.com/coollabsio/sentinel/pkg/push"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sync/errgroup"
)

// HTTP client (Docker) with connection pooling
var dockerHttpClient = dockerClient.New()

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

func Execute() error {
	config := config.NewDefaultConfig()
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Println("No .env file found, skipping load")
	} else {
		err := godotenv.Load()
		if err != nil {
			log.Printf("Error loading .env file: %v", err)
		}
	}
	debugFromEnv := os.Getenv("DEBUG")
	if debugFromEnv != "" {
		var err error
		config.Debug, err = strconv.ParseBool(debugFromEnv)
		if err != nil {
			log.Printf("Error parsing DEBUG: %v", err)
		}
	}

	endpointFromEnv := os.Getenv("PUSH_ENDPOINT")
	if gin.Mode() == gin.DebugMode {
		config.MetricsFile = "./db/metrics.sqlite"

		if endpointFromEnv == "" {
			config.Endpoint = "http://localhost:8000"
		}
	}

	if config.Debug && gin.Mode() != gin.DebugMode {
		gin.SetMode(gin.DebugMode)
		log.Printf("[%s] Debug is enabled.", time.Now().Format("2006-01-02 15:04:05"))
	}


	tokenFromEnv := os.Getenv("TOKEN")
	if tokenFromEnv == "" {
		return fmt.Errorf("TOKEN environment variable is required")
	}
	config.Token = tokenFromEnv

	if config.Endpoint == "" && endpointFromEnv == "" {
		return fmt.Errorf("PUSH_ENDPOINT environment variable is required")
	}

	if config.Endpoint == "" {
		config.Endpoint = endpointFromEnv
	}

	config.PushUrl = config.Endpoint + config.PushPath

	if pushIntervalSecondsFromEnv := os.Getenv("PUSH_INTERVAL_SECONDS"); pushIntervalSecondsFromEnv != "" {
		pushIntervalSecondsInt, err := strconv.Atoi(pushIntervalSecondsFromEnv)
		if err != nil {
			log.Printf("Error converting PUSH_INTERVAL_SECONDS to int: %v", err)
		} else {
			config.PushIntervalSeconds = pushIntervalSecondsInt
		}
	}
	if collectorEnabledFromEnv := os.Getenv("COLLECTOR_ENABLED"); collectorEnabledFromEnv != "" {
		var err error
		config.CollectorEnabled, err = strconv.ParseBool(collectorEnabledFromEnv)
		if err != nil {
			log.Printf("Error parsing COLLECTOR_ENABLED: %v", err)
		}
	}
	if refreshRateSecondsFromEnv := os.Getenv("COLLECTOR_REFRESH_RATE_SECONDS"); refreshRateSecondsFromEnv != "" {
		refreshRateSecondsInt, err := strconv.Atoi(refreshRateSecondsFromEnv)
		if err != nil {
			log.Printf("Error converting REFRESH_RATE_SECONDS to int: %v", err)
		} else {
			if refreshRateSecondsInt > 0 {
				config.RefreshRateSeconds = refreshRateSecondsInt
			} else {
				log.Printf("COLLECTOR_REFRESH_RATE_SECONDS must be greater than 0, using default value: %d", config.RefreshRateSeconds)
			}
		}
	}

	if collectorRetentionPeriodDaysFromEnv := os.Getenv("COLLECTOR_RETENTION_PERIOD_DAYS"); collectorRetentionPeriodDaysFromEnv != "" {
		collectorRetentionPeriodDaysInt, err := strconv.Atoi(collectorRetentionPeriodDaysFromEnv)
		if err != nil {
			log.Printf("Error converting COLLECTOR_RETENTION_PERIOD_DAYS to int: %v", err)
		} else {
			config.CollectorRetentionPeriodDays = collectorRetentionPeriodDaysInt
		}
	}

	database, err := db.New(config)
	if err != nil {
		return err
	}

	defer database.Close()

	if err := database.CreateDefaultTables(); err != nil {
		return err
	}

	log.Printf("[%s] Starting database schema migration...", time.Now().Format("2006-01-02 15:04:05"))
	if err := database.MigrateDatabase(); err != nil {
		log.Printf("[%s] Database migration failed: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return err
	}
	log.Printf("[%s] Database schema migration completed", time.Now().Format("2006-01-02 15:04:05"))

	server := api.New(config, database)
	pusherService := push.New(config, dockerHttpClient)
	collectorService := collector.New(config, database, dockerHttpClient)

	group, gCtx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		return HandleSignals(gCtx)
	})

	// TODO: Do we need to run cleanup if collector is disabled?
	group.Go(func() error {
		database.Run(gCtx)
		return nil
	})

	group.Go(func() error {
		pusherService.Run(gCtx)
		return nil
	})
	// Collector
	if config.CollectorEnabled {
		group.Go(func() error {
			collectorService.Run(gCtx)
			return nil
		})
	}

	group.Go(func() error {
		errorChan := make(chan error, 1)
		go func() {
			defer close(errorChan)
			if err := server.Start(); err != nil && err != http.ErrServerClosed {
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
			return err // unexpected error we return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Stop(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		log.Println("server shutdown")
	}
	return nil
}
