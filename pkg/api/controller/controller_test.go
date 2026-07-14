package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/coollabsio/sentinel/pkg/config"
	"github.com/coollabsio/sentinel/pkg/db"
)

func newTestController(t *testing.T, debug bool) (*Controller, *config.Config) {
	t.Helper()
	cfg := config.NewDefaultConfig()
	cfg.Token = "test-token"
	cfg.Debug = debug
	cfg.MetricsFile = filepath.Join(t.TempDir(), "metrics.sqlite")
	database, err := db.New(cfg)
	if err != nil {
		t.Fatalf("db.New() error = %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})
	if err := database.CreateDefaultTables(); err != nil {
		t.Fatalf("CreateDefaultTables() error = %v", err)
	}

	controller := New(cfg, database)
	controller.SetupRoutes()
	if debug {
		controller.SetupDebugRoutes()
	}
	return controller, cfg
}

func performRequest(controller *Controller, method, path, token string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	controller.GetEngine().ServeHTTP(recorder, request)
	return recorder
}

func TestPublicRoutesDoNotRequireAuthentication(t *testing.T) {
	controller, _ := newTestController(t, false)

	for _, path := range []string{"/api/health", "/api/version"} {
		response := performRequest(controller, http.MethodGet, path, "")
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, response.Code)
		}
	}
}

func TestMetricsRoutesRequireAuthentication(t *testing.T) {
	controller, cfg := newTestController(t, false)

	for _, token := range []string{"", "wrong-token"} {
		unauthorized := performRequest(controller, http.MethodGet, "/api/cpu/history", token)
		if unauthorized.Code != http.StatusUnauthorized {
			t.Fatalf("unauthorized status = %d, want 401", unauthorized.Code)
		}
	}

	authorized := performRequest(controller, http.MethodGet, "/api/cpu/history", cfg.Token)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized status = %d, want 200; body = %s", authorized.Code, authorized.Body.String())
	}
}

func TestDebugStatsUsesSQLiteAndHandlesEmptyDatabase(t *testing.T) {
	controller, cfg := newTestController(t, true)
	if _, err := controller.database.Exec("INSERT INTO cpu_usage (time, percent) VALUES ('123', '45.6')"); err != nil {
		t.Fatal(err)
	}

	response := performRequest(controller, http.MethodGet, "/api/stats", cfg.Token)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}

	var body struct {
		TableSizes []struct {
			TableName string `json:"table_name"`
			SizeKB    string `json:"size_kb"`
		} `json:"table_sizes"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, table := range body.TableSizes {
		if table.TableName == "cpu_usage" {
			sizeKB, err := strconv.ParseFloat(table.SizeKB, 64)
			if err != nil || sizeKB <= 0 {
				t.Fatalf("cpu_usage size_kb = %q, want a positive size", table.SizeKB)
			}
			return
		}
	}
	t.Fatal("cpu_usage stats not found")
}
