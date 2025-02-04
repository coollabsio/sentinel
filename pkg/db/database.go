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
	fmt.Printf("[%s] Removing old data.\n", time.Now().Format("2006-01-02 15:04:05"))

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
	// Create migrations table first
	_, err = d.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name VARCHAR NOT NULL,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %v", err)
	}

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

func (d *Database) MigrateDatabase() error {
	// Check if migration has already been applied
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = 1").Scan(&count)
	if err != nil {
		log.Printf("[%s] Error checking migration status: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to check migration status: %v", err)
	}

	if count > 0 {
		log.Printf("[%s] Migration already applied, skipping", time.Now().Format("2006-01-02 15:04:05"))
		return nil
	}

	log.Printf("[%s] Starting database migration...", time.Now().Format("2006-01-02 15:04:05"))

	// Start a transaction to ensure data consistency
	tx, err := d.db.Begin()
	if err != nil {
		log.Printf("[%s] Failed to begin transaction: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback() // Will be ignored if transaction is committed

	// Migrate memory_usage table
	log.Printf("[%s] Migrating memory_usage table...", time.Now().Format("2006-01-02 15:04:05"))
	_, err = tx.Exec(`CREATE TABLE memory_usage_new (
		time VARCHAR,
		total VARCHAR,
		available VARCHAR,
		used VARCHAR,
		usedPercent REAL,
		free VARCHAR,
		PRIMARY KEY (time)
	)`)
	if err != nil {
		log.Printf("[%s] Failed to create memory_usage_new table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to create memory_usage_new: %v", err)
	}

	_, err = tx.Exec(`INSERT INTO memory_usage_new SELECT time, total, available, used, CAST(NULLIF(usedPercent, '') AS REAL), free FROM memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to copy memory_usage data: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to copy memory_usage data: %v", err)
	}

	_, err = tx.Exec(`DROP TABLE memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to drop old memory_usage table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to drop old memory_usage: %v", err)
	}

	_, err = tx.Exec(`ALTER TABLE memory_usage_new RENAME TO memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to rename memory_usage_new table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to rename memory_usage_new: %v", err)
	}

	log.Printf("[%s] Successfully migrated memory_usage table", time.Now().Format("2006-01-02 15:04:05"))

	// Migrate container_memory_usage table
	log.Printf("[%s] Migrating container_memory_usage table...", time.Now().Format("2006-01-02 15:04:05"))
	_, err = tx.Exec(`CREATE TABLE container_memory_usage_new (
		time VARCHAR,
		container_id VARCHAR,
		total VARCHAR,
		available VARCHAR,
		used VARCHAR,
		usedPercent REAL,
		free VARCHAR,
		PRIMARY KEY (time, container_id)
	)`)
	if err != nil {
		log.Printf("[%s] Failed to create container_memory_usage_new table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to create container_memory_usage_new: %v", err)
	}

	_, err = tx.Exec(`INSERT INTO container_memory_usage_new SELECT time, container_id, total, available, used, CAST(NULLIF(usedPercent, '') AS REAL), free FROM container_memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to copy container_memory_usage data: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to copy container_memory_usage data: %v", err)
	}

	_, err = tx.Exec(`DROP TABLE container_memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to drop old container_memory_usage table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to drop old container_memory_usage: %v", err)
	}

	_, err = tx.Exec(`ALTER TABLE container_memory_usage_new RENAME TO container_memory_usage`)
	if err != nil {
		log.Printf("[%s] Failed to rename container_memory_usage_new table: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to rename container_memory_usage_new: %v", err)
	}

	// Recreate the index
	_, err = tx.Exec(`CREATE INDEX idx_container_memory_usage_time_container_id ON container_memory_usage (time, container_id)`)
	if err != nil {
		log.Printf("[%s] Failed to recreate index on container_memory_usage: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to recreate index: %v", err)
	}

	log.Printf("[%s] Successfully migrated container_memory_usage table", time.Now().Format("2006-01-02 15:04:05"))

	// Record the migration
	_, err = tx.Exec(`INSERT INTO schema_migrations (version, name) VALUES (1, 'convert_usedPercent_to_real')`)
	if err != nil {
		log.Printf("[%s] Failed to record migration: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to record migration: %v", err)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		log.Printf("[%s] Failed to commit transaction: %v", time.Now().Format("2006-01-02 15:04:05"), err)
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("[%s] Database migration completed successfully", time.Now().Format("2006-01-02 15:04:05"))

	return nil
}
