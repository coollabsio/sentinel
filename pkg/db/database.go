package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
)

type Database struct {
	db     *sql.DB
	config *config.Config
}

func New(config *config.Config) (*Database, error) {
	// create directory based on metricsFile
	dir := filepath.Dir(config.MetricsFile)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	// make sure the directory has 0750 permissions
	if err := os.Chmod(dir, 0750); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", config.MetricsFile)
	if err != nil {
		return nil, err
	}

	return &Database{
		db:     db,
		config: config,
	}, nil
}

func (d *Database) Run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	d.Cleanup()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Database cleanup stopped")
			return
		case <-ticker.C:
			d.Cleanup()
		}
	}
}

func (d *Database) Cleanup() {
	fmt.Printf("[%s] Removing old data (Retention period: %d days).\n", time.Now().Format("2006-01-02 15:04:05"), d.config.CollectorRetentionPeriodDays)

	cutoffTime := time.Now().AddDate(0, 0, -d.config.CollectorRetentionPeriodDays).UnixMilli()

	_, err := d.db.Exec(`DELETE FROM cpu_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old data: %v", err)
	}

	_, err = d.db.Exec(`DELETE FROM memory_usage WHERE CAST(time AS BIGINT) < ?`, cutoffTime)
	if err != nil {
		log.Printf("Error removing old memory data: %v", err)
	}
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

func (d *Database) Vacuum() error {
	_, err := d.db.Exec("VACUUM")
	return err
}

func (d *Database) Checkpoint() error {
	_, err := d.db.Exec("CHECKPOINT")
	return err
}

func (d *Database) CreateDefaultTables() error {
	var err error
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS cpu_usage (
		time VARCHAR,
		percent VARCHAR,
		PRIMARY KEY (time)
	)`)
	if err != nil {
		return err
	}
	// Container CPU
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS container_cpu_usage (
		time VARCHAR,
		container_id VARCHAR,
		percent VARCHAR,
		PRIMARY KEY (time, container_id)
	)`)
	if err != nil {
		return err
	}
	// Create an index on the container_cpu_usage table for better query performance
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_cpu_usage_time_container_id ON container_cpu_usage (container_id,time)`)
	if err != nil {
		return err
	}

	// Memory
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS memory_usage (
		time VARCHAR,
		total VARCHAR,
		available VARCHAR,
		used VARCHAR,
		usedPercent VARCHAR,
		free VARCHAR,
		PRIMARY KEY (time)
	)`)
	if err != nil {
		return err
	}
	// Container Memory
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS container_memory_usage (
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
		return err
	}
	// Create an index on the container_memory_usage table for better query performance
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_memory_usage_time_container_id ON container_memory_usage (time, container_id)`)
	if err != nil {
		return err
	}

	// Container Logs
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS container_logs (time VARCHAR, container_id VARCHAR, log VARCHAR)`)
	if err != nil {
		return err
	}
	// Create an index on the container_logs table for better query performance
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_logs_time_container_id ON container_logs (time, container_id)`)
	if err != nil {
		return err
	}
	return nil
}
