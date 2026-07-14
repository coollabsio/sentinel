package cmd

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
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
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Println("No .env file found, skipping load")
	} else {
		if err := godotenv.Load(); err != nil {
			log.Printf("Error loading .env file: %v", err)
		}
	}

	cfg, err := config.Load(gin.Mode() == gin.DebugMode)
	if err != nil {
		return err
	}
	log.Printf("Sentinel v%s is starting...", cfg.Version)

	if cfg.Debug && gin.Mode() != gin.DebugMode {
		gin.SetMode(gin.DebugMode)
		log.Printf("[%s] Debug is enabled.", time.Now().Format("2006-01-02 15:04:05"))
	}

	database, err := db.New(cfg)
	if err != nil {
		return err
	}

	defer func() {
		if err := database.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	if err := database.CreateDefaultTables(); err != nil {
		return err
	}

	server := api.New(cfg, database)
	pusherService := push.New(cfg, dockerHttpClient)
	collectorService := collector.New(cfg, database, dockerHttpClient)

	group, gCtx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		return HandleSignals(gCtx)
	})

	group.Go(func() error {
		database.Run(gCtx)
		return nil
	})

	group.Go(func() error {
		pusherService.Run(gCtx)
		return nil
	})
	// Collector
	if cfg.CollectorEnabled {
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
	log.Println("server shutdown")
	return nil
}
