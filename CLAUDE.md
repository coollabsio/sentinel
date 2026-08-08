# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Sentinel is an experimental API for gathering Linux server and Docker Engine metrics, built for integration with Coolify.io. It's a Rust-based service that collects system metrics (CPU, memory) and Docker container stats, storing them in SQLite and pushing them to a configured endpoint.

## Development Commands

### Building and Running
```bash
cargo watch -x run     # hot reload (replaces air)
cargo build --release  # build
cargo test --workspace # test
docker build -t sentinel .
```

## Architecture

### Core Services Structure
The application follows a service-oriented architecture with these main components:

1. **API Server** (`crates/api/`) - Axum-based HTTP server exposing metrics endpoints
   - Routes handle CPU, memory, and container metrics
   - Debug routes available when DEBUG=true

2. **Collector Service** (`crates/collector/`) - Background service that periodically collects system and Docker metrics
   - Runs on configurable interval (COLLECTOR_REFRESH_RATE_SECONDS)
   - Stores metrics in SQLite database with retention policy

3. **Push Service** (`crates/push/`) - Sends collected metrics to external endpoint
   - Pushes container states to configured PUSH_ENDPOINT
   - Runs on interval defined by PUSH_INTERVAL_SECONDS

4. **Database Layer** (`crates/store/`) - SQLite storage for metrics (rusqlite, bundled)
   - Automatic cleanup based on COLLECTOR_RETENTION_PERIOD_DAYS
   - Stores CPU, memory, and container metrics in separate tables

5. **Docker Client** (`crates/docker/`) - bollard-based Docker Engine client with cgroup v1/v2 fallback

6. **Configuration** (`crates/config/`) - environment-variable driven configuration and validation

### Service Initialization Flow
`src/main.rs` orchestrates service startup:
1. Loads configuration from environment variables
2. Initializes SQLite database
3. Starts concurrent services on a `tokio::task::JoinSet`:
   - API server
   - Push service
   - Collector service (if enabled)
   - Database cleanup routine
4. A `tokio::sync::watch::Receiver<bool>` broadcasts shutdown to every task, signal handling triggers a 5-second graceful shutdown window
5. Any task failure (e.g. a bind failure) propagates out and exits the process non-zero

### Key Dependencies
- **axum**: HTTP web framework
- **bollard**: Docker API client for container metrics
- **sysinfo**: System metrics collection (CPU, memory)
- **rusqlite** (bundled): SQLite database driver
- **tokio**: Async runtime and concurrent service management

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

## Release Process

### Version Locations (all must be updated together)
1. `Cargo.toml` — `[workspace.package] version = "X.Y.Z"`
2. `openapi.yaml:12` — `version: X.Y.Z` (info block)
3. `openapi.yaml:69` — `example: X.Y.Z` (version endpoint response)
4. `API.md:74` — `X.Y.Z` (version endpoint example response)

### Steps
1. **Bump version** in all 4 locations above, then verify:
   - `grep -r "OLD_VERSION" .` returns nothing
   - `grep -r "NEW_VERSION" .` shows all 4 locations
   - `cargo build --release --locked` passes
2. **Commit & push to `next`** — triggers `release-next.yaml` workflow
   - Builds multi-arch Docker images (amd64 + aarch64)
   - Pushes to Docker Hub & GHCR with `next` tag
   - Sends Discord notification (dev channel)
3. **PR `next` → `main`** and merge
4. **Create GitHub Release** with tag `vX.Y.Z` — triggers `release.yaml` workflow
   - Builds multi-arch Docker images tagged with version
   - Pushes to Docker Hub (`coollabsio/sentinel`) and GHCR
   - Sends Discord notification (production channel)
