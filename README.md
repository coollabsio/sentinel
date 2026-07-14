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
- Debug and profiling endpoints

## Quick Start

### Prerequisites

- Go 1.25 or higher (for development)
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

#### Using Go

```bash
# Clone the repository
git clone https://github.com/coollabsio/sentinel.git
cd sentinel

# Install dependencies
go mod download

# Run the application
TOKEN=your-secret-token go run main.go
```

#### Using Air (Development with hot reload)

```bash
# Install Air if not already installed
go install github.com/cosmtrek/air@latest

# Run with hot reload
air
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
| `DEBUG` | `false` | Enable debug mode and profiling endpoints |
| `PORT` | `8888` | HTTP server port |

When running directly in Gin development mode, `PUSH_ENDPOINT` defaults to `http://localhost:8000`.

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

## Architecture

Sentinel follows a service-oriented architecture with these components:

### Core Services

1. **API Server** (`pkg/api/`) - Gin-based HTTP server exposing metrics endpoints
2. **Collector Service** (`pkg/collector/`) - Periodically collects system and Docker metrics
3. **Push Service** (`pkg/push/`) - Sends metrics to external endpoints
4. **Database Layer** (`pkg/db/`) - SQLite storage with automatic cleanup

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
├── cmd/              # Application entry points
├── pkg/
│   ├── api/         # HTTP API and controllers
│   ├── collector/   # Metrics collection service
│   ├── push/        # Push service
│   ├── db/          # Database layer
│   └── config/      # Configuration management
├── main.go          # Application main
├── go.mod           # Go dependencies
├── Dockerfile       # Docker build configuration
├── API.md           # API documentation
└── openapi.yaml     # OpenAPI specification
```

### Building

```bash
# Build binary
go build -o sentinel .

# Build Docker image
docker build -t sentinel .

# Run tests
go test ./...

# Format code
go fmt ./...

# Run linter
golangci-lint run
```

### Test with Coolify development

Coolify's development testing host uses the same Docker daemon, and its Sentinel page already accepts a custom development image.

```bash
# Start Coolify development first from the Coolify repository.
spin up

# Build Sentinel in this repository.
./scripts/coolify-dev.sh build
```

The image receives a build-time version such as `0.0.22-dev+9b1cd1a.dirty`, so startup logs and `/api/version` clearly distinguish it from a release build. Set `SENTINEL_DEV_VERSION` to override this value.

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

- **gin-gonic/gin**: HTTP web framework
- **docker/docker**: Docker API client
- **shirou/gopsutil**: System metrics collection
- **mattn/go-sqlite3**: SQLite database driver
- **golang.org/x/sync/errgroup**: Concurrent service management

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

### Profiling Endpoints (Debug Mode)

Go profiling endpoints are available at `/debug/pprof/*` when debug mode is enabled.

## Contributing

This is an experimental project for Coolify.io. Contributions are welcome!

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
