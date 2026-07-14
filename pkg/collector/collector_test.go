package collector

import (
	"context"
	"io"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
	dockerContainer "github.com/docker/docker/api/types/container"
)

type collectorDockerClient struct {
	responses map[string]string
}

func (f collectorDockerClient) MakeRequest(_ context.Context, path string) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(f.responses[path])),
	}, nil
}

func TestCalculateCPUPercent(t *testing.T) {
	stat := dockerContainer.StatsResponse{
		CPUStats: dockerContainer.CPUStats{
			CPUUsage:    dockerContainer.CPUUsage{TotalUsage: 200},
			SystemUsage: 2_000,
			OnlineCPUs:  2,
		},
		PreCPUStats: dockerContainer.CPUStats{
			CPUUsage:    dockerContainer.CPUUsage{TotalUsage: 100},
			SystemUsage: 1_000,
		},
	}

	if got := calculateCPUPercent(stat); got != 20 {
		t.Fatalf("calculateCPUPercent() = %v, want 20", got)
	}
}

func TestCalculateCPUPercentFallsBackToPerCPUCount(t *testing.T) {
	stat := dockerContainer.StatsResponse{
		CPUStats: dockerContainer.CPUStats{
			CPUUsage: dockerContainer.CPUUsage{
				TotalUsage:  200,
				PercpuUsage: []uint64{1, 2, 3, 4},
			},
			SystemUsage: 2_000,
		},
		PreCPUStats: dockerContainer.CPUStats{
			CPUUsage:    dockerContainer.CPUUsage{TotalUsage: 100},
			SystemUsage: 1_000,
		},
	}

	if got := calculateCPUPercent(stat); got != 40 {
		t.Fatalf("calculateCPUPercent() = %v, want 40", got)
	}
}

func TestCalculateCPUPercentHandlesInvalidDeltas(t *testing.T) {
	stat := dockerContainer.StatsResponse{}
	if got := calculateCPUPercent(stat); got != 0 || math.IsNaN(got) {
		t.Fatalf("calculateCPUPercent() = %v, want 0", got)
	}
}

func TestContainerMemoryCalculationsUseBytes(t *testing.T) {
	stat := dockerContainer.StatsResponse{
		MemoryStats: dockerContainer.MemoryStats{
			Usage: 5_000,
			Limit: 8_000,
			Stats: map[string]uint64{"inactive_file": 1_000},
		},
	}

	if got := calculateMemoryUsed(stat); got != 4_000 {
		t.Fatalf("calculateMemoryUsed() = %d, want 4000 bytes", got)
	}
	if got := calculateMemoryPercent(stat); got != 50 {
		t.Fatalf("calculateMemoryPercent() = %v, want 50", got)
	}
}

func TestContainerMemoryCalculationsHandleInvalidStats(t *testing.T) {
	stat := dockerContainer.StatsResponse{
		MemoryStats: dockerContainer.MemoryStats{
			Usage: 100,
			Stats: map[string]uint64{"inactive_file": 200},
		},
	}

	if got := calculateMemoryUsed(stat); got != 0 {
		t.Fatalf("calculateMemoryUsed() = %d, want 0", got)
	}
	if got := calculateMemoryPercent(stat); got != 0 || math.IsNaN(got) {
		t.Fatalf("calculateMemoryPercent() = %v, want 0", got)
	}
}

func TestCollectContainerMetricsHandlesShortIDsAndStoresBytes(t *testing.T) {
	cfg := config.NewDefaultConfig()
	cfg.MetricsFile = filepath.Join(t.TempDir(), "metrics.sqlite")
	database, err := db.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.CreateDefaultTables(); err != nil {
		t.Fatal(err)
	}

	docker := collectorDockerClient{responses: map[string]string{
		"/containers/json?all=true": `[{"Id":"abc","Names":[],"Labels":{}}]`,
		"/containers/abc/stats?stream=false": `{
			"cpu_stats":{"cpu_usage":{"total_usage":200,"percpu_usage":[1]},"system_cpu_usage":2000,"online_cpus":1},
			"precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000},
			"memory_stats":{"usage":5000,"limit":8000,"stats":{"inactive_file":1000}}
		}`,
	}}
	collector := New(cfg, database, docker)

	collector.collectContainerMetrics(context.Background(), "123")

	var total, available, used, free uint64
	if err := database.QueryRow(`SELECT total, available, used, free FROM container_memory_usage WHERE container_id = 'abc'`).Scan(&total, &available, &used, &free); err != nil {
		t.Fatal(err)
	}
	if total != 8_000 || available != 4_000 || used != 4_000 || free != 4_000 {
		t.Fatalf("stored memory = total:%d available:%d used:%d free:%d", total, available, used, free)
	}
}
