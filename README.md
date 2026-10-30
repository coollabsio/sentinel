# Sentinel

An API for gathering Linux server / Docker Engine metrics.

> It is used in [coolify.io](https://coolify.io).

## Features

- Host metrics: CPU, memory, load average, network, and disk usage
- Docker container metrics: CPU, memory, network, and disk (volume and bind mount sizes)
- Historical metrics storage in SQLite, with history queries bucketed to a requested resolution
- REST API for querying current and historical metrics (described in [openapi.json](./openapi.json))
- Configurable data retention
- Push metrics to external endpoints
- Debug mode with verbose logging and a database statistics endpoint
- Optional on-box web/traffic analytics computed from the reverse-proxy access log (see [Traffic Analytics](#traffic-analytics))

## Quick Start

### Prerequisites

- Rust 1.97 or higher (for development; pinned in `rust-toolchain.toml`)
- Docker Engine, or Podman with its Docker-compatible socket (for container metrics)
- Linux environment (production deployment)

### Installation

#### Using Docker (Recommended)

```bash
docker run -d \
  -p 8888:8888 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v sentinel-data:/app/db \
  -e BIND_ADDRESS=:: \
  -e TOKEN=your-secret-token \
  -e PUSH_ENDPOINT=https://coolify.example.com \
  -e COLLECTOR_ENABLED=true \
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

# Or use the just recipe: it disables push and watches only the source trees
just dev
```

In development mode, the SQLite database is written to `./db/` instead of `/app/db/`.

## Configuration

Sentinel is configured using environment variables:

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TOKEN` | Authentication token for API access | `your-secret-token` |
| `PUSH_ENDPOINT` | Coolify base URL that receives Sentinel pushes. Sentinel appends `/api/v1/sentinel/push` | `https://coolify.example.com` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PUSH_ENABLED` | `true` | Enable/disable the push service |
| `PUSH_INTERVAL_SECONDS` | 60 | Interval for pushing metrics |
| `COLLECTOR_ENABLED` | `false` | Enable/disable metrics collection |
| `COLLECTOR_REFRESH_RATE_SECONDS` | 5 | Metrics collection interval |
| `COLLECTOR_RETENTION_PERIOD_DAYS` | 7 | How long to keep metrics in database |
| `STORAGE_ENABLED` | `true` | Enable/disable storage (disk + container storage) collection |
| `STORAGE_REFRESH_RATE_SECONDS` | 300 | Interval for the cheap per-mount filesystem stats |
| `STORAGE_VOLUMES_ENABLED` | `true` | Enable/disable per-container volume and bind mount sizes |
| `STORAGE_VOLUMES_REFRESH_RATE_SECONDS` | 900 | Interval for the expensive volume walk (kept separate so it can't hammer host I/O) |
| `HOST_MOUNT_PREFIX` | *(empty)* | Path prefix under which host paths are mounted into Sentinel's container. When set, bind mount sources are `du`-walked under it; when empty, bind mounts are not sized |
| `DOCKER_HOST` | `/var/run/docker.sock` | Docker Engine API socket; `unix://` URLs and bare paths only — e.g. `unix:///run/user/1000/podman/podman.sock` for rootless Podman |
| `DEBUG` | `false` | Enable verbose logging, `human_friendly_time` fields, and the `/api/stats` route |
| `PORT` | `8888` | HTTP server port |
| `BIND_ADDRESS` | `127.0.0.1` | IP address the HTTP server listens on. The default accepts only connections from inside the container. Set `::` (all interfaces, IPv4 and IPv6) when you publish the port or call the API from another container |

#### Traffic Analytics Variables

Inert unless Sentinel is built with the `traffic` Cargo feature. See [Traffic Analytics](#traffic-analytics) below for the full feature description.

| Variable | Default | Description |
|----------|---------|-------------|
| `TRAFFIC_ENABLED` | `false` | Opt-in toggle for the whole subsystem (mirrors `COLLECTOR_ENABLED`) |
| `TRAFFIC_ACCESS_LOG_PATH` | `/data/coolify/proxy/access.log` | Reverse-proxy JSON access log to tail |
| `TRAFFIC_PROXY_TYPE` | `auto` | `traefik`, `caddy`, or `auto` (sniffs the format; Nginx is deferred) |
| `TRAFFIC_TOPN` | `50` | Top-N cap per dimension (paths, countries, browsers, ...); overflow folds into a `__other__` row |
| `TRAFFIC_IP_MODE` | `full` | How the `ip` dimension stores client IPs: `full`, `anonymized` (only the IPv4 /24 or IPv6 /48 network, as `1.2.3.0/24`), or `off` (no `ip` rows, and no city either). At start, Sentinel deletes stored `ip` rows that the mode does not allow, and with `off` also the stored cities. Unique-visitor counts always use a HyperLogLog sketch, which stores no IPs |
| `TRAFFIC_SAMPLE_THRESHOLD` | `0` (off) | Events/sec above which to start sampling under extreme load |
| `TRAFFIC_RETENTION_1M_HOURS` | `48` | Safety net, **not** a queryable window — see note below |
| `TRAFFIC_RETENTION_1H_DAYS` | `30` | How long hourly rollups are kept; this is your real fine-grained history |
| `TRAFFIC_RETENTION_1D_DAYS` | `395` | How long daily rollups are kept before deletion (~13 months) |
| `GEOIP_ENABLED` | `true` | Enable/disable country and city enrichment. The database downloads in the background and is reused from disk on the next start |
| `GEOIP_DB_URL` | *(unset)* | Explicit GeoIP database URL; when set, used with no fallback |
| `GEOIP_MAXMIND_LICENSE_KEY` | *(unset)* | MaxMind license key; when set, GeoLite2 is downloaded directly from MaxMind, taking priority over `GEOIP_DB_URL` |
| `GEOIP_MAXMIND_EDITION` | `GeoLite2-City` | MaxMind edition ID used when `GEOIP_MAXMIND_LICENSE_KEY` is set. A country edition gives country data only |
| `GEOIP_REFRESH_DAYS` | `30` | How often to re-check the GeoIP database for updates (a conditional request; cheap even when unchanged) |

> **Note:** `TRAFFIC_RETENTION_1M_HOURS` is a backlog safety net, not a queryable window. Hourly compaction deletes per-minute rows as it folds them into the hourly tier, so the minute table normally holds only the last hour or two — this cap just bounds how far it can grow if compaction falls behind. Longer ranges are served from the hourly and daily tiers.

In development mode (`cargo run`/`cargo build` debug profile, or `SENTINEL_DEVELOPMENT=1`), `PUSH_ENDPOINT` defaults to `http://localhost:8000`.

> **Storage collection & host paths.** Disk stats only cover filesystems Sentinel's container can see. **Named volumes** are sized by the Docker daemon (`/system/df`), so they need no host mounts (volumes of drivers other than `local` count as `0`). **Bind mounts** count as `0` unless you mount their host paths (read-only is fine) and point `HOST_MOUNT_PREFIX` at them (e.g. `/host`); a missing path then logs one warning. Large trees (`/`, `/var`, home dirs) are walked every cycle and can be slow; the walk is capped, or set `STORAGE_VOLUMES_ENABLED=false` to skip all volume sizing.

### Example Configuration

```bash
export TOKEN=your-secret-token
export PUSH_ENDPOINT=https://coolify.example.com
export COLLECTOR_ENABLED=true
export COLLECTOR_REFRESH_RATE_SECONDS=30
export COLLECTOR_RETENTION_PERIOD_DAYS=14
export DEBUG=false

./sentinel
```

## API Reference

Sentinel provides a comprehensive REST API for retrieving system and Docker container metrics.

### Quick API Overview

Public:

- `GET /api/health` - Health check
- `GET /api/version` - Service version

Host metrics:

- `GET /api/cpu/current`, `GET /api/cpu/history` - CPU usage
- `GET /api/memory/current`, `GET /api/memory/history` - Memory usage
- `GET /api/load/current`, `GET /api/load/history` - Load average
- `GET /api/network/current`, `GET /api/network/history` - Network throughput
- `GET /api/disk/current`, `GET /api/disk/history` - Disk usage per mount
- `GET /api/summary` - Latest host CPU, memory, disk, network, load, uptime, and swap in one response

Containers:

- `GET /api/containers/current` - Current stats for all containers
- `GET /api/container/{containerId}/cpu/history` - Container CPU history
- `GET /api/container/{containerId}/memory/history` - Container memory history
- `GET /api/container/{containerId}/network/history` - Container network history
- `GET /api/container/{containerId}/disk/current`, `GET /api/container/{containerId}/disk/history` - Container volume and bind mount sizes

Other:

- `GET /api/push-status` - State of the last push to Coolify
- `GET /api/stats` - Database statistics (only when `DEBUG=true`)
- `GET /api/traffic/...`, `/api/app/{uuid}/traffic/...`, `/api/resource/{uuid}/traffic/...` - Traffic analytics (only with the `traffic` feature; see [Traffic Analytics](#traffic-analytics))

### Authentication

Metrics and debug API requests require a Bearer token. Health and version endpoints remain public for probes:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/cpu/current
```

### Complete API Documentation

For detailed API documentation including request/response examples, query parameters, and error responses, see [API.md](./API.md) and the OpenAPI spec [openapi.json](./openapi.json).

### OpenAPI Specification

[openapi.json](./openapi.json) is **generated from the route annotations in code**, and a test fails in CI when it drifts. Open it in any OpenAPI tool (for example <https://editor.swagger.io>). See [API.md](./API.md) for how to regenerate it.

## Traffic Analytics

Sentinel can optionally compute Cloudflare-style web analytics (requests, bandwidth, status classes, latency percentiles, unique visitors, geo, browser/OS/device, bot classification, referers, top paths) on the server from the reverse-proxy's JSON access log (Traefik or Caddy).

Only per-minute aggregate rollups are stored, never raw request rows, so storage doesn't grow with traffic. Rollups compact minute → hourly → daily with per-tier retention. Coolify pulls the aggregates the same way it does CPU/memory metrics; see the *Traffic Analytics* tag in [openapi.json](./openapi.json) for the query endpoints.

The feature is opt-in at runtime (`TRAFFIC_ENABLED=true`) and gated at compile time by the `traffic` Cargo feature. The published Docker images already build with `--features traffic`; if you build Sentinel yourself, pass `cargo build --features traffic` or the traffic endpoints will 404.

### Coolify integration

This repo implements the agent side only. Wiring it into Coolify — JSON access logs on the proxy, retaining Cloudflare headers, mounting the log into the container, passing the `TRAFFIC_*`/`GEOIP_*` env vars, and the pull/render UI — is tracked separately.

**App attribution.** Traffic is keyed per app. For Traefik the app UUID is parsed from the router name. For Caddy, if the access-log entry carries a `coolify_app_id` field (a custom log field Coolify can inject), that UUID is used — identical semantics to Traefik; otherwise attribution falls back to the request host, so hand-configured Caddy sites still work.

## Architecture

Sentinel follows a service-oriented architecture with these components:

### Core Services

1. **API Server** (`crates/api/`) - Axum-based HTTP server exposing metrics endpoints
2. **Collector Service** (`crates/collector/`) - Periodically collects host, container, and storage metrics
3. **Push Service** (`crates/push/`) - Sends container states and metrics to Coolify
4. **Database Layer** (`crates/store/`) - SQLite storage (rusqlite, bundled) with automatic cleanup
5. **Docker Client** (`crates/docker/`) - bollard-based Docker Engine client with cgroup v1/v2 fallback
6. **Configuration** (`crates/config/`) - Environment-variable configuration and validation
7. **Traffic Analytics** (`crates/traffic/`) - Optional access-log tailer and rollup engine (`traffic` feature)

`src/main.rs` starts all services on one Tokio `JoinSet`. A shutdown signal gives the services a 5-second window to stop. If one service fails (for example, the port is already in use), the process exits with a non-zero code.

### Data Flow

```
Docker Engine ──┐
                ├──> Collector Service ──> SQLite Database ──> API Server ──> Clients
System Stats ───┘                              │
                                               └──> Push Service ──> Coolify

Proxy access log ──> Traffic Analytics ──> SQLite rollups ──> API Server   (optional)
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
│   ├── docker/       # Docker Engine client (bollard)
│   ├── traffic/      # Traffic analytics (feature-gated)
│   └── sentinel-bench/ # HTTP load and latency benchmark harness
├── tests/             # Integration tests (startup, parity)
├── scripts/           # Coolify development helpers (coolify-dev.sh)
├── docs/              # Design specs and benchmark results
├── Cargo.toml         # Workspace manifest
├── justfile           # Development recipes (dev, openapi)
├── Dockerfile         # Docker build configuration
├── API.md             # API documentation
├── BENCHMARK.md       # How to benchmark Sentinel
└── openapi.json       # OpenAPI spec, generated from route annotations
```

### Building

```bash
# Build binary (add --features traffic for traffic analytics)
cargo build --release

# Regenerate openapi.json after you change a route
just openapi

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
services:
  sentinel:
    image: ghcr.io/coollabsio/sentinel:latest
    ports:
      - "8888:8888"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sentinel-data:/app/db
    environment:
      BIND_ADDRESS: "::"
      TOKEN: ${SENTINEL_TOKEN}
      PUSH_ENDPOINT: ${PUSH_ENDPOINT}
      COLLECTOR_ENABLED: "true"
      COLLECTOR_REFRESH_RATE_SECONDS: 30
      COLLECTOR_RETENTION_PERIOD_DAYS: 14
    restart: unless-stopped

volumes:
  sentinel-data:
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
- GitHub Issues: <https://github.com/coollabsio/sentinel/issues>
- Coolify Discord: <https://discord.gg/coolify>
