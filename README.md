# Sentinel

An experimental API for gathering Linux server / Docker Engine metrics.

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

- Go 1.21 or higher (for development)
- Docker (for container metrics)
- Linux environment (production deployment)

### Installation

#### Using Docker (Recommended)

```bash
docker run -d \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e TOKEN=your-secret-token \
  -e PUSH_ENDPOINT=https://your-endpoint.com/metrics \
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

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PUSH_ENDPOINT` | - | URL to push metrics to |
| `PUSH_INTERVAL_SECONDS` | 60 | Interval for pushing metrics |
| `COLLECTOR_ENABLED` | `true` | Enable/disable metrics collection |
| `COLLECTOR_REFRESH_RATE_SECONDS` | 10 | Metrics collection interval |
| `COLLECTOR_RETENTION_PERIOD_DAYS` | 7 | How long to keep metrics in database |
| `DEBUG` | `false` | Enable debug mode and profiling endpoints |
| `PORT` | `8080` | HTTP server port |

### Example Configuration

```bash
export TOKEN=your-secret-token
export PUSH_ENDPOINT=https://coolify.io/api/metrics
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

All API requests require a Bearer token:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/cpu/current
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
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - sentinel-data:/data
    environment:
      TOKEN: ${SENTINEL_TOKEN}
      PUSH_ENDPOINT: ${PUSH_ENDPOINT}
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
Environment="PUSH_ENDPOINT=https://your-endpoint.com/metrics"
ExecStart=/usr/local/bin/sentinel
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Monitoring and Debugging

### Health Check

```bash
curl http://localhost:8080/api/health
```

### Database Statistics (Debug Mode)

When `DEBUG=true`, access database statistics:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/stats
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
