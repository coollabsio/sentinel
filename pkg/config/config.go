package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

var Version = "0.0.22"

type Config struct {
	Version                      string
	Debug                        bool
	RefreshRateSeconds           int
	PushEnabled                  bool
	PushIntervalSeconds          int
	PushPath                     string
	PushUrl                      string
	Token                        string
	Endpoint                     string
	MetricsFile                  string
	CollectorEnabled             bool
	CollectorRetentionPeriodDays int
	BindAddr                     string
}

func NewDefaultConfig() *Config {
	return &Config{
		Version:                      Version,
		Debug:                        false,
		RefreshRateSeconds:           5,
		PushEnabled:                  true,
		PushIntervalSeconds:          60,
		PushPath:                     "/api/v1/sentinel/push",
		PushUrl:                      "",
		Token:                        "",
		Endpoint:                     "",
		MetricsFile:                  "/app/db/metrics.sqlite",
		CollectorEnabled:             false,
		CollectorRetentionPeriodDays: 7,
		BindAddr:                     ":8888",
	}
}

func Load(development bool) (*Config, error) {
	config := NewDefaultConfig()
	if development {
		config.MetricsFile = "./db/metrics.sqlite"
	}

	var err error
	if value := os.Getenv("DEBUG"); value != "" {
		config.Debug, err = strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("invalid DEBUG: %w", err)
		}
	}
	if value := os.Getenv("COLLECTOR_ENABLED"); value != "" {
		config.CollectorEnabled, err = strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("invalid COLLECTOR_ENABLED: %w", err)
		}
	}

	if config.PushIntervalSeconds, err = positiveIntFromEnv("PUSH_INTERVAL_SECONDS", config.PushIntervalSeconds); err != nil {
		return nil, err
	}
	if config.RefreshRateSeconds, err = positiveIntFromEnv("COLLECTOR_REFRESH_RATE_SECONDS", config.RefreshRateSeconds); err != nil {
		return nil, err
	}
	if config.CollectorRetentionPeriodDays, err = positiveIntFromEnv("COLLECTOR_RETENTION_PERIOD_DAYS", config.CollectorRetentionPeriodDays); err != nil {
		return nil, err
	}

	if value := os.Getenv("PORT"); value != "" {
		port, parseErr := strconv.Atoi(value)
		if parseErr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("PORT must be an integer between 1 and 65535")
		}
		config.BindAddr = fmt.Sprintf(":%d", port)
	}

	config.Token = os.Getenv("TOKEN")
	if config.Token == "" {
		return nil, fmt.Errorf("TOKEN environment variable is required")
	}

	config.Endpoint = strings.TrimRight(os.Getenv("PUSH_ENDPOINT"), "/")
	if config.Endpoint == "" && development {
		config.Endpoint = "http://localhost:8000"
	}
	if config.Endpoint == "" {
		return nil, fmt.Errorf("PUSH_ENDPOINT environment variable is required")
	}
	if err := validateEndpoint(config.Endpoint); err != nil {
		return nil, err
	}
	config.PushUrl = config.Endpoint + config.PushPath

	return config, nil
}

func positiveIntFromEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func validateEndpoint(endpoint string) error {
	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("PUSH_ENDPOINT must be a valid HTTP or HTTPS URL")
	}
	return nil
}
