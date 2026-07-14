package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/coollabsio/sentinel/pkg/config"
)

func newTestDatabase(t *testing.T) *Database {
	t.Helper()
	cfg := config.NewDefaultConfig()
	cfg.MetricsFile = filepath.Join(t.TempDir(), "metrics.sqlite")
	database, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if err := database.CreateDefaultTables(); err != nil {
		t.Fatalf("CreateDefaultTables() error = %v", err)
	}
	return database
}

func TestCleanupCleansEveryMetricsTableAndPreservesTenSamples(t *testing.T) {
	database := newTestDatabase(t)
	database.config.CollectorRetentionPeriodDays = 1
	oldTime := time.Now().Add(-48 * time.Hour).UnixMilli()

	for i := 0; i < 12; i++ {
		timestamp := oldTime + int64(i)
		if _, err := database.Exec("INSERT INTO cpu_usage (time, percent) VALUES (?, ?)", timestamp, "1"); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("INSERT INTO memory_usage (time, total, available, used, usedPercent, free) VALUES (?, 1, 1, 1, 1, 1)", timestamp); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("INSERT INTO container_cpu_usage (time, container_id, percent) VALUES (?, 'container', '1')", timestamp); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("INSERT INTO container_memory_usage (time, container_id, total, available, used, usedPercent, free) VALUES (?, 'container', 1, 1, 1, 1, 1)", timestamp); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("INSERT INTO container_logs (time, container_id, log) VALUES (?, 'container', 'line')", timestamp); err != nil {
			t.Fatal(err)
		}
	}

	if err := database.Cleanup(); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	for _, table := range []string{"cpu_usage", "memory_usage", "container_cpu_usage", "container_memory_usage", "container_logs"} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 10 {
			t.Fatalf("%s row count = %d, want 10", table, count)
		}
	}
}

func TestCreateDefaultTablesAddsHistoryQueryIndexes(t *testing.T) {
	database := newTestDatabase(t)

	for _, name := range []string{
		"idx_cpu_usage_time_integer",
		"idx_memory_usage_time_integer",
		"idx_container_cpu_usage_container_time_integer",
		"idx_container_memory_usage_container_time_integer",
	} {
		var count int
		if err := database.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?", name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("index %s not found", name)
		}
	}
}

func TestCleanupPreservesTenDistinctContainerSnapshots(t *testing.T) {
	database := newTestDatabase(t)
	database.config.CollectorRetentionPeriodDays = 1
	oldTime := time.Now().Add(-48 * time.Hour).UnixMilli()

	for i := 0; i < 12; i++ {
		for _, containerID := range []string{"one", "two"} {
			timestamp := oldTime + int64(i)
			if _, err := database.Exec("INSERT INTO container_cpu_usage (time, container_id, percent) VALUES (?, ?, '1')", timestamp, containerID); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := database.Cleanup(); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM container_cpu_usage").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 20 {
		t.Fatalf("container snapshot row count = %d, want 20", count)
	}
}
