# Sentinel

An API for gathering Linux server / Docker Engine metrics.

> This will be used in [coolify.io](https://coolify.io).

## Features

- Real-time system metrics collection (CPU, Memory)
- Docker container metrics tracking
- Historical metrics storage with SQLite
- REST API for querying metrics
- Configurable data retention
- Push metrics to external endpoints
- Debug mode with verbose logging and a database statistics endpoint
- Optional on-box web/traffic analytics computed from the reverse-proxy access log (see [Traffic Analytics](#traffic-analytics))

## Quick Start

### Prerequisites

- Rust 1.97 or higher (for development)
- Docker (for container metrics)
- Linux environment (production deployment)

### Installation

#### Using Docker (Recommended)

```bash
docker run -d \
  -p 8888:8888 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e TOKEN=your-secret-token \
  -e PUSH_ENDPOINT=https://coolify.example.com \
  ghcr.io/coollabsio/sentinel:latest
```

#### Using Cargo

```bash
# Clone the repository
git clone https://github.com/coollabsio/sentinel.git
cd sentinel

# Run the application
TOKEN=your-secret-token cargo run
```

#### Using cargo-watch (Development with hot reload)

```bash
# Install cargo-watch if not already installed
cargo install cargo-watch

# Run with hot reload
TOKEN=your-secret-token cargo watch -x run
```

## Configuration

Sentinel is configured using environment variables:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TOKEN` | Authentication token for API access | `your-secret-token` |
| `PUSH_ENDPOINT` | Coolify base URL that receives Sentinel pushes | `https://coolify.example.com` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PUSH_INTERVAL_SECONDS` | 60 | Interval for pushing metrics |
| `COLLECTOR_ENABLED` | `false` | Enable/disable metrics collection |
| `COLLECTOR_REFRESH_RATE_SECONDS` | 5 | Metrics collection interval |
| `COLLECTOR_RETENTION_PERIOD_DAYS` | 7 | How long to keep metrics in database |
| `STORAGE_ENABLED` | `true` | Enable/disable storage (disk + container storage) collection |
| `STORAGE_REFRESH_RATE_SECONDS` | 300 | Interval for the cheap per-mount filesystem stats |
| `STORAGE_VOLUMES_ENABLED` | `true` | Enable/disable the per-container volume `du`-walk |
| `STORAGE_VOLUMES_REFRESH_RATE_SECONDS` | 900 | Interval for the expensive volume walk (kept separate so it can't hammer host I/O) |
| `HOST_MOUNT_PREFIX` | *(empty)* | Path prefix under which host paths are mounted into Sentinel's container, used to resolve volume/bind sources |
| `DEBUG` | `false` | Enable verbose logging, `human_friendly_time` fields, and the `/api/stats` route |
| `PORT` | `8888` | HTTP server port |

#### Traffic Analytics Variables

Inert unless Sentinel is built with the `traffic` Cargo feature. See [Traffic Analytics](#traffic-analytics) below for the full feature description.

| Variable | Default | Description |
|----------|---------|-------------|
| `TRAFFIC_ENABLED` | `false` | Opt-in toggle for the whole subsystem (mirrors `COLLECTOR_ENABLED`) |
| `TRAFFIC_ACCESS_LOG_PATH` | `/data/coolify/proxy/access.log` | Reverse-proxy JSON access log to tail |
| `TRAFFIC_PROXY_TYPE` | `auto` | `traefik`, `caddy`, or `auto` (sniffs the format; Nginx is deferred) |
| `TRAFFIC_TOPN` | `50` | Top-N cap per dimension (paths, countries, browsers, ...); overflow folds into a `__other__` row |
| `TRAFFIC_SAMPLE_THRESHOLD` | `0` (off) | Events/sec above which to start sampling under extreme load |
| `TRAFFIC_RETENTION_1M_HOURS` | `48` | Safety net, **not** a queryable window — see note below |
| `TRAFFIC_RETENTION_1H_DAYS` | `30` | How long hourly rollups are kept; this is your real fine-grained history |
| `TRAFFIC_RETENTION_1D_DAYS` | `395` | How long daily rollups are kept before deletion (~13 months) |
| `GEOIP_ENABLED` | `true` | Enable/disable country enrichment |
| `GEOIP_DB_URL` | *(unset)* | Explicit GeoIP database URL; when set, used with no fallback |
| `GEOIP_MAXMIND_LICENSE_KEY` | *(unset)* | MaxMind license key; when set, GeoLite2 is downloaded directly from MaxMind, taking priority over `GEOIP_DB_URL` |
| `GEOIP_MAXMIND_EDITION` | `GeoLite2-Country` | MaxMind edition ID used when `GEOIP_MAXMIND_LICENSE_KEY` is set |
| `GEOIP_REFRESH_DAYS` | `30` | How often to re-check the GeoIP database for updates (a conditional request; cheap even when unchanged) |

> **Note:** `TRAFFIC_RETENTION_1M_HOURS` is a backlog safety net, not a queryable window. Hourly compaction deletes per-minute rows as it folds them into the hourly tier, so the minute table normally holds only the last hour or two — this cap just bounds how far it can grow if compaction falls behind. Longer ranges are served from the hourly and daily tiers.

In development mode (`cargo run`/`cargo build` debug profile, or `SENTINEL_DEVELOPMENT=1`), `PUSH_ENDPOINT` defaults to `http://localhost:8000`.

> **Storage collection & host paths.** Disk stats only cover filesystems Sentinel's container can see. To size **volumes/bind mounts**, mount the host paths (read-only is fine) — typically `/var/lib/docker/volumes` plus any bind-mount roots — and point `HOST_MOUNT_PREFIX` at them (e.g. `/host`). Inaccessible paths contribute `0` with a warning. Large trees (`/`, `/var`, home dirs) are walked every cycle and can be slow; the walk is capped, or set `STORAGE_VOLUMES_ENABLED=false` to skip it.

### Example Configuration

```bash
export TOKEN=your-secret-token
export PUSH_ENDPOINT=https://coolify.example.com
export COLLECTOR_REFRESH_RATE_SECONDS=30
export COLLECTOR_RETENTION_PERIOD_DAYS=14
export DEBUG=false

./sentinel
```

## API Reference

Sentinel provides a comprehensive REST API for retrieving system and Docker container metrics.

### Quick API Overview

- `GET /api/health` - Health check
- `GET /api/version` - Get service version
- `GET /api/cpu/current` - Current CPU usage
- `GET /api/cpu/history` - Historical CPU data
- `GET /api/memory/current` - Current memory usage
- `GET /api/memory/history` - Historical memory data
- `GET /api/container/:id/cpu/history` - Container CPU history
- `GET /api/container/:id/memory/history` - Container memory history

### Authentication

Metrics and debug API requests require a Bearer token. Health and version endpoints remain public for probes:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/cpu/current
```

### Complete API Documentation

For detailed API documentation including request/response examples, query parameters, and error responses, see [API.md](./API.md).

### OpenAPI Specification

An OpenAPI 3.0 specification is available at [openapi.yaml](./openapi.yaml) for use with Swagger UI and other API tools.

## Traffic Analytics

Sentinel can optionally compute Cloudflare-style web analytics (requests, bandwidth, status classes, latency percentiles, unique visitors, geo, browser/OS/device, bot classification, referers, top paths) on the server from the reverse-proxy's JSON access log (Traefik or Caddy).

Only per-minute aggregate rollups are stored, never raw request rows, so storage doesn't grow with traffic. Rollups compact minute → hourly → daily with per-tier retention. Coolify pulls the aggregates the same way it does CPU/memory metrics; see [API.md](./API.md#traffic-analytics) for the query endpoints.

The feature is opt-in at runtime (`TRAFFIC_ENABLED=true`) and gated at compile time by the `traffic` Cargo feature. The published Docker images already build with `--features traffic`; if you build Sentinel yourself, pass `cargo build --features traffic` or the traffic endpoints will 404.

### Coolify integration

This repo implements the agent side only. Wiring it into Coolify — JSON access logs on the proxy, retaining Cloudflare headers, mounting the log into the container, passing the `TRAFFIC_*`/`GEOIP_*` env vars, and the pull/render UI — is tracked separately.

**App attribution.** Traffic is keyed per app. For Traefik the app UUID is parsed from the router name. For Caddy, if the access-log entry carries a `coolify_app_id` field (a custom log field Coolify can inject), that UUID is used — identical semantics to Traefik; otherwise attribution falls back to the request host, so hand-configured Caddy sites still work.

## Architecture

Sentinel follows a service-oriented architecture with these components:

### Core Services

1. **API Server** (`crates/api/`) - Axum-based HTTP server exposing metrics endpoints
2. **Collector Service** (`crates/collector/`) - Periodically collects system and Docker metrics
3. **Push Service** (`crates/push/`) - Sends metrics to external endpoints
4. **Database Layer** (`crates/store/`) - SQLite storage (rusqlite, bundled) with automatic cleanup

### Data Flow

```
Docker Engine ──┐
                ├──> Collector Service ──> SQLite Database ──> API Server ──> Clients
System Stats ───┘                              │
                                               └──> Push Service ──> External Endpoint
```

## Development

### Project Structure

```
sentinel/
├── src/               # Application entry point (main.rs)
├── crates/
│   ├── api/          # HTTP API and routes (axum)
│   ├── collector/    # Metrics collection service
│   ├── push/         # Push service
│   ├── store/        # Database layer (rusqlite)
│   ├── config/       # Configuration management
│   └── docker/       # Docker Engine client (bollard)
├── Cargo.toml         # Workspace manifest
├── Dockerfile          # Docker build configuration
├── API.md              # API documentation
└── openapi.yaml        # OpenAPI specification
```

### Building

```bash
# Build binary
cargo build --release

# Build Docker image
docker build -t sentinel .

# Run tests
cargo test --workspace

# Format code
cargo fmt --all

# Run linter
cargo clippy --workspace --all-targets -- -D warnings
```

### Test with Coolify development

Coolify's development testing host uses the same Docker daemon, and its Sentinel page already accepts a custom development image.

```bash
# Start Coolify development first from the Coolify repository.
spin up

# Build Sentinel in this repository.
./scripts/coolify-dev.sh build
```

The image receives a build-time version such as `1.0.0-dev+9b1cd1a.dirty`, so startup logs and `/api/version` clearly distinguish it from a release build. Set `SENTINEL_DEV_VERSION` to override this value.

In Coolify, open **Servers → localhost → Sentinel**, set **Custom Sentinel Docker Image (Dev Only)** to `sentinel:dev`, then enable or restart Sentinel. Verify the running container afterwards:

```bash
./scripts/coolify-dev.sh smoke
docker logs coolify-sentinel
```

The smoke command checks Docker health plus authenticated history access from inside the Sentinel container. The Coolify UI heartbeat confirms that push delivery to `/api/v1/sentinel/push` succeeds.

For an isolated end-to-end check, keep the Coolify-managed `coolify-sentinel` container running and execute:

```bash
./scripts/coolify-dev.sh integration
```

This starts a temporary candidate container using the development server's existing token and endpoint, then checks a custom listener port, health, authentication, collection, and a real push to Coolify before removing the container.

### Dependencies

Key dependencies used in the project:

- **axum**: HTTP web framework
- **bollard**: Docker API client
- **sysinfo**: System metrics collection
- **rusqlite** (bundled): SQLite database driver
- **tokio**: Async runtime and concurrent service management

## Deployment

### Docker Compose Example

```yaml
version: '3.8'

services:
  sentinel:
    image: ghcr.io/coollabsio/sentinel:latest
    ports:
      - "8888:8888"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sentinel-data:/app/db
    environment:
      TOKEN: ${SENTINEL_TOKEN}
      PUSH_ENDPOINT: ${PUSH_ENDPOINT}
      COLLECTOR_ENABLED: "true"
      COLLECTOR_REFRESH_RATE_SECONDS: 30
      COLLECTOR_RETENTION_PERIOD_DAYS: 14
    restart: unless-stopped

volumes:
  sentinel-data:
```

### Systemd Service Example

```ini
[Unit]
Description=Sentinel Metrics Service
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=sentinel
Environment="TOKEN=your-secret-token"
Environment="PUSH_ENDPOINT=https://coolify.example.com"
ExecStart=/usr/local/bin/sentinel
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Monitoring and Debugging

### Health Check

```bash
curl http://localhost:8888/api/health
```

### Database Statistics (Debug Mode)

When `DEBUG=true`, access database statistics:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/stats
```

## Contributing

This project is built for Coolify.io. Contributions are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

See [LICENSE](./LICENSE) file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/coollabsio/sentinel/issues
- Coolify Discord: https://discord.gg/coolify
