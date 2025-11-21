# Sentinel API Reference

Sentinel provides a REST API for retrieving system and Docker container metrics. All metrics can be queried both for current values and historical data.

## Table of Contents

- [Authentication](#authentication)
- [Base URL](#base-url)
- [Date/Time Format](#datetime-format)
- [Core Endpoints](#core-endpoints)
- [System Metrics](#system-metrics)
  - [CPU Metrics](#cpu-metrics)
  - [Memory Metrics](#memory-metrics)
- [Docker Container Metrics](#docker-container-metrics)
- [Debug Endpoints](#debug-endpoints)
- [Error Responses](#error-responses)

## Authentication

All API endpoints require authentication using a Bearer token. Set the `TOKEN` environment variable when running Sentinel, and include it in your requests:

```bash
Authorization: Bearer YOUR_TOKEN_HERE
```

## Base URL

The default base URL is:
```
http://localhost:8080/api
```

## Date/Time Format

All date/time parameters use ISO 8601 format in UTC timezone:
```
YYYY-MM-DDTHH:MM:SSZ
```

Example: `2024-01-15T10:30:00Z`

Time values in responses are Unix timestamps in milliseconds.

---

## Core Endpoints

### Health Check

Check if the service is running.

**Endpoint:** `GET /api/health`

**Response:**
```
ok
```

**Example:**
```bash
curl http://localhost:8080/api/health
```

---

### Version

Get the current version of Sentinel.

**Endpoint:** `GET /api/version`

**Response:**
```
0.0.18
```

**Example:**
```bash
curl http://localhost:8080/api/version
```

---

## System Metrics

### CPU Metrics

#### Get Current CPU Usage

Retrieve the current CPU usage percentage.

**Endpoint:** `GET /api/cpu/current`

**Response:**
```json
{
  "time": "1700000000000",
  "percent": 25.5
}
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `percent` (number): CPU usage percentage (0-100)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/cpu/current
```

---

#### Get CPU Usage History

Retrieve historical CPU usage data.

**Endpoint:** `GET /api/cpu/history`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

**Response:**
```json
[
  {
    "time": "1700000000000",
    "percent": "25.5",
    "human_friendly_time": "2024-01-15T10:00:00Z"
  },
  {
    "time": "1700000060000",
    "percent": "28.3",
    "human_friendly_time": "2024-01-15T10:01:00Z"
  }
]
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `percent` (string): CPU usage percentage
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
# Get CPU history for the last 24 hours
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8080/api/cpu/history?from=2024-01-14T10:00:00Z&to=2024-01-15T10:00:00Z"
```

---

### Memory Metrics

#### Get Current Memory Usage

Retrieve the current memory usage statistics.

**Endpoint:** `GET /api/memory/current`

**Response:**
```json
{
  "time": "1700000000000",
  "total": 16000000000,
  "available": 8000000000,
  "used": 8000000000,
  "usedPercent": 50.00,
  "free": 8000000000
}
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `total` (number): Total memory in bytes
- `available` (number): Available memory in bytes
- `used` (number): Used memory in bytes
- `usedPercent` (number): Memory usage percentage (0-100)
- `free` (number): Free memory in bytes

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/memory/current
```

---

#### Get Memory Usage History

Retrieve historical memory usage data.

**Endpoint:** `GET /api/memory/history`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

**Response:**
```json
[
  {
    "time": "1700000000000",
    "total": 16000000000,
    "available": 8000000000,
    "used": 8000000000,
    "usedPercent": 50.00,
    "free": 8000000000,
    "human_friendly_time": "2024-01-15T10:00:00Z"
  }
]
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `total` (number): Total memory in bytes
- `available` (number): Available memory in bytes
- `used` (number): Used memory in bytes
- `usedPercent` (number): Memory usage percentage
- `free` (number): Free memory in bytes
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
# Get memory history for a specific time range
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8080/api/memory/history?from=2024-01-15T00:00:00Z&to=2024-01-15T12:00:00Z"
```

---

## Docker Container Metrics

### Get Container CPU History

Retrieve CPU usage history for a specific Docker container.

**Endpoint:** `GET /api/container/:containerId/cpu/history`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Docker container ID (alphanumeric characters only) |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:01Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

**Response:**
```json
[
  {
    "time": "1700000000000",
    "percent": "12.5",
    "human_friendly_time": "2024-01-15T10:00:00Z"
  }
]
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `percent` (string): CPU usage percentage for the container
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8080/api/container/abc123def456/cpu/history?from=2024-01-15T09:00:00Z"
```

---

### Get Container Memory History

Retrieve memory usage history for a specific Docker container.

**Endpoint:** `GET /api/container/:containerId/memory/history`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Docker container ID (alphanumeric characters only) |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:01Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

**Response:**
```json
[
  {
    "time": "1700000000000",
    "total": 4000000000,
    "available": 2000000000,
    "used": 2000000000,
    "usedPercent": 50.00,
    "free": 2000000000,
    "human_friendly_time": "2024-01-15T10:00:00Z"
  }
]
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `total` (number): Total container memory limit in bytes
- `available` (number): Available memory in bytes
- `used` (number): Used memory in bytes
- `usedPercent` (number): Memory usage percentage
- `free` (number): Free memory in bytes
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8080/api/container/abc123def456/memory/history?from=2024-01-15T00:00:00Z&to=2024-01-15T12:00:00Z"
```

---

## Debug Endpoints

Debug endpoints are only available when the `DEBUG` environment variable is set to `true`.

### Get Database Statistics

Retrieve database storage statistics and table sizes.

**Endpoint:** `GET /api/stats`

**Response:**
```json
{
  "row_count": 10000,
  "storage_usage_kb": "1024.50",
  "storage_usage_mb": "1.00",
  "memory_usage": {
    "total": 16000000000,
    "available": 8000000000,
    "used": 8000000000,
    "usedPercent": 50.00,
    "free": 8000000000
  },
  "table_sizes": [
    {
      "table_name": "cpu_usage",
      "size_mb": "0.50",
      "size_kb": "512.00"
    },
    {
      "table_name": "memory_usage",
      "size_mb": "0.30",
      "size_kb": "307.20"
    }
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8080/api/stats
```

### Profiling Endpoints

Additional debug endpoints for Go profiling (requires `DEBUG=true`):

- `GET /debug/pprof` - pprof index
- `GET /debug/cmdline` - Command line invocation
- `GET /debug/profile` - CPU profile
- `GET /debug/symbol` - Symbol lookup
- `GET /debug/trace` - Execution trace
- `GET /debug/heap` - Heap profile
- `GET /debug/goroutine` - Goroutine profile
- `GET /debug/block` - Block profile

---

## Error Responses

### 400 Bad Request
Returned when query parameters are invalid (e.g., malformed date format).

```json
{
  "error": "Invalid date format for 'from' parameter"
}
```

### 401 Unauthorized
Returned when authentication token is missing or invalid.

```json
{
  "error": "Unauthorized"
}
```

### 404 Not Found
Returned when the requested resource doesn't exist.

```json
{
  "error": "Container not found"
}
```

### 500 Internal Server Error
Returned when an unexpected server error occurs.

```json
{
  "error": "Internal server error"
}
```

---

## Data Retention

Historical metrics are stored in SQLite and automatically cleaned up based on the `COLLECTOR_RETENTION_PERIOD_DAYS` environment variable. By default, metrics older than the retention period are deleted.

## Rate Limiting

There is currently no rate limiting implemented. Consider implementing rate limiting in production environments.

## CORS

CORS is not configured by default. Configure CORS middleware if needed for browser-based clients.
