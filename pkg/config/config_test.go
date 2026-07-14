package config

import (
	"os"
	"testing"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"DEBUG",
		"PUSH_INTERVAL_SECONDS",
		"COLLECTOR_ENABLED",
		"COLLECTOR_REFRESH_RATE_SECONDS",
		"COLLECTOR_RETENTION_PERIOD_DAYS",
		"PORT",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("TOKEN", "test-token")
	t.Setenv("PUSH_ENDPOINT", "https://coolify.example.com")
}

func TestLoadUsesBackwardCompatibleDefaults(t *testing.T) {
	setRequiredEnv(t)

	got, err := Load(false)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if got.BindAddr != ":8888" {
		t.Fatalf("BindAddr = %q, want :8888", got.BindAddr)
	}
	if got.CollectorEnabled {
		t.Fatal("CollectorEnabled = true, want false")
	}
	if got.RefreshRateSeconds != 5 {
		t.Fatalf("RefreshRateSeconds = %d, want 5", got.RefreshRateSeconds)
	}
	if got.PushUrl != "https://coolify.example.com/api/v1/sentinel/push" {
		t.Fatalf("PushUrl = %q", got.PushUrl)
	}
}

func TestLoadSupportsCustomPort(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PORT", "9090")

	got, err := Load(false)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.BindAddr != ":9090" {
		t.Fatalf("BindAddr = %q, want :9090", got.BindAddr)
	}
}

func TestLoadRejectsInvalidIntervals(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PUSH_INTERVAL_SECONDS", "0")

	if _, err := Load(false); err == nil {
		t.Fatal("Load() error = nil, want invalid interval error")
	}
}

func TestLoadRejectsInvalidPushEndpoint(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PUSH_ENDPOINT", "coolify.example.com")

	if _, err := Load(false); err == nil {
		t.Fatal("Load() error = nil, want invalid endpoint error")
	}
}

func TestLoadRejectsPushEndpointWithQueryOrCredentials(t *testing.T) {
	for _, endpoint := range []string{
		"https://coolify.example.com?target=other",
		"https://user:password@coolify.example.com",
		"https://coolify.example.com#fragment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("PUSH_ENDPOINT", endpoint)
			if _, err := Load(false); err == nil {
				t.Fatal("Load() error = nil, want invalid endpoint error")
			}
		})
	}
}

func TestLoadUsesDevelopmentEndpointWhenMissing(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PUSH_ENDPOINT", "")

	got, err := Load(true)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Endpoint != "http://localhost:8000" {
		t.Fatalf("Endpoint = %q, want development endpoint", got.Endpoint)
	}
}

func TestBuildVersionCanBeInjected(t *testing.T) {
	expected := os.Getenv("SENTINEL_EXPECT_VERSION")
	if expected == "" {
		t.Skip("build-version injection is tested separately")
	}
	if Version != expected {
		t.Fatalf("Version = %q, want injected version %q", Version, expected)
	}
	if got := NewDefaultConfig().Version; got != expected {
		t.Fatalf("Config.Version = %q, want injected version %q", got, expected)
	}
}
