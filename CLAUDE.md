# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Sentinel is an experimental API for gathering Linux server and Docker Engine metrics, built for integration with Coolify.io. It's a Go-based service that collects system metrics (CPU, memory) and Docker container stats, storing them in SQLite and pushing them to a configured endpoint.

## Development Commands

### Building and Running
```bash
# Run with hot reload (using Air)
air

# Build the binary
go build -o sentinel .

# Build Docker image
docker build -t sentinel .

# Run Go application directly
go run main.go
```

### Dependencies Management
```bash
# Download dependencies
go mod download

# Update dependencies
go mod tidy
```

## Architecture

### Core Services Structure
The application follows a service-oriented architecture with these main components:

1. **API Server** (`pkg/api/`) - Gin-based HTTP server exposing metrics endpoints
   - Controllers handle HTTP routes for CPU, memory, and container metrics
   - Debug routes available when DEBUG=true

2. **Collector Service** (`pkg/collector/`) - Background service that periodically collects system and Docker metrics
   - Runs on configurable interval (COLLECTOR_REFRESH_RATE_SECONDS)
   - Stores metrics in SQLite database with retention policy

3. **Push Service** (`pkg/push/`) - Sends collected metrics to external endpoint
   - Pushes container states to configured PUSH_ENDPOINT
   - Runs on interval defined by PUSH_INTERVAL_SECONDS

4. **Database Layer** (`pkg/db/`) - SQLite storage for metrics
   - Automatic cleanup based on COLLECTOR_RETENTION_PERIOD_DAYS
   - Stores CPU, memory, and container metrics in separate tables

### Service Initialization Flow
The `cmd/cmd.go` orchestrates service startup:
1. Loads configuration from environment variables
2. Initializes SQLite database
3. Starts concurrent services using errgroup:
   - API server
   - Push service
   - Collector service (if enabled)
   - Database cleanup routine
   - Signal handler for graceful shutdown

### Key Dependencies
- **gin-gonic/gin**: HTTP web framework
- **docker/docker**: Docker API client for container metrics
- **shirou/gopsutil**: System metrics collection (CPU, memory)
- **mattn/go-sqlite3**: SQLite database driver
- **golang.org/x/sync/errgroup**: Concurrent service management

## Environment Configuration

Required environment variables:
- `TOKEN`: Authentication token (required)
- `PUSH_ENDPOINT`: URL to push metrics to (required in production)

Optional configuration:
- `DEBUG`: Enable debug mode and routes
- `PUSH_INTERVAL_SECONDS`: Interval for pushing metrics (default varies)
- `COLLECTOR_ENABLED`: Enable/disable metrics collection
- `COLLECTOR_REFRESH_RATE_SECONDS`: Metrics collection interval
- `COLLECTOR_RETENTION_PERIOD_DAYS`: How long to keep metrics in database

## Docker Integration
The application connects to Docker daemon via Unix socket to collect container statistics. It uses a custom HTTP client with connection pooling for efficient Docker API communication.