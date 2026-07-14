package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
	_ "github.com/mattn/go-sqlite3"
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

	// Enable WAL mode for better concurrent read/write performance
	_, err = db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Set synchronous mode to NORMAL for better performance while maintaining durability
	_, err = db.Exec("PRAGMA synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	// Increase cache size for better performance (default is 2000 pages)
	_, err = db.Exec("PRAGMA cache_size=-64000") // 64MB cache
	if err != nil {
		return nil, fmt.Errorf("failed to set cache size: %w", err)
	}

	return &Database{
		db:     db,
		config: config,
	}, nil
}

func (d *Database) Run(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	if err := d.Cleanup(); err != nil {
		log.Printf("Error removing old data: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Database cleanup stopped")
			return
		case <-ticker.C:
			if err := d.Cleanup(); err != nil {
				log.Printf("Error removing old data: %v", err)
			}
		}
	}
}

func (d *Database) Cleanup() error {
	fmt.Printf("[%s] Removing old data (Retention period: %d days).\n", time.Now().Format("2006-01-02 15:04:05"), d.config.CollectorRetentionPeriodDays)

	cutoffTime := time.Now().AddDate(0, 0, -d.config.CollectorRetentionPeriodDays).UnixMilli()
	var cleanupErrors []error
	for _, table := range []string{"cpu_usage", "memory_usage", "container_cpu_usage", "container_memory_usage", "container_logs"} {
		query := fmt.Sprintf(`DELETE FROM %s
			WHERE CAST(time AS INTEGER) < ?
			AND time NOT IN (
				SELECT DISTINCT time FROM %s ORDER BY CAST(time AS INTEGER) DESC LIMIT 10
			)`, table, table)
		if _, err := d.db.Exec(query, cutoffTime); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("clean %s: %w", table, err))
		}
	}
	return errors.Join(cleanupErrors...)
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

func (d *Database) Begin() (*sql.Tx, error) {
	return d.db.Begin()
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
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_cpu_usage_time_integer ON cpu_usage (CAST(time AS INTEGER))`)
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
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_cpu_usage_container_time_integer ON container_cpu_usage (container_id, CAST(time AS INTEGER))`)
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
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_memory_usage_time_integer ON memory_usage (CAST(time AS INTEGER))`)
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
	_, err = d.db.Exec(`CREATE INDEX IF NOT EXISTS idx_container_memory_usage_container_time_integer ON container_memory_usage (container_id, CAST(time AS INTEGER))`)
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
