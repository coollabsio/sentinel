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
- [Traffic Analytics](#traffic-analytics)
- [Debug Endpoints](#debug-endpoints)
- [Error Responses](#error-responses)

## Authentication

Metrics and debug endpoints require authentication using a Bearer token. The health and version endpoints are public so container and orchestration probes can use them. Set the `TOKEN` environment variable when running Sentinel, and include it in protected requests:

```bash
Authorization: Bearer YOUR_TOKEN_HERE
```

## Base URL

The default base URL is:
```
http://localhost:8888/api
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
curl http://localhost:8888/api/health
```

---

### Version

Get the current version of Sentinel.

**Endpoint:** `GET /api/version`

**Response:**
```
1.0.0
```

**Example:**
```bash
curl http://localhost:8888/api/version
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
  http://localhost:8888/api/cpu/current
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
  "http://localhost:8888/api/cpu/history?from=2024-01-14T10:00:00Z&to=2024-01-15T10:00:00Z"
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
  http://localhost:8888/api/memory/current
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
  "http://localhost:8888/api/memory/history?from=2024-01-15T00:00:00Z&to=2024-01-15T12:00:00Z"
```

---

### Disk Metrics

#### Get Current Disk Usage

Retrieve the latest stored filesystem usage, one entry per real mountpoint.

**Endpoint:** `GET /api/disk/current`

**Response:**
```json
[
  {
    "time": "1700000000000",
    "mount": "/",
    "total": 500000000000,
    "used": 250000000000,
    "available": 250000000000,
    "usedPercent": 50.00
  }
]
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `mount` (string): Filesystem mountpoint
- `total` (number): Total capacity in bytes
- `used` (number): Used space in bytes
- `available` (number): Available space in bytes
- `usedPercent` (number): Disk usage percentage
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/disk/current
```

---

#### Get Disk Usage History

Retrieve historical filesystem usage across mountpoints.

**Endpoint:** `GET /api/disk/history`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

Response items use the same shape as `/api/disk/current`.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/disk/history?from=2024-01-15T00:00:00Z&to=2024-01-15T12:00:00Z"
```

---

## Docker Container Metrics

### Get Container CPU History

Retrieve CPU usage history for a specific Docker container.

**Endpoint:** `GET /api/container/:containerId/cpu/history`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Exact container display name recorded by Sentinel |

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
  "http://localhost:8888/api/container/postgres-db/cpu/history?from=2024-01-15T09:00:00Z"
```

---

### Get Container Memory History

Retrieve memory usage history for a specific Docker container.

**Endpoint:** `GET /api/container/:containerId/memory/history`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Exact container display name recorded by Sentinel |

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
  "http://localhost:8888/api/container/postgres-db/memory/history?from=2024-01-15T00:00:00Z&to=2024-01-15T12:00:00Z"
```

---

### Get Container Storage (Current)

Retrieve the latest stored storage row for a container. Returns `null` when nothing has been recorded yet.

**Endpoint:** `GET /api/container/:containerId/disk/current`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Exact container display name recorded by Sentinel |

**Response:**
```json
{
  "time": "1700000000000",
  "writableLayer": 12000000,
  "volumesTotal": 340000000
}
```

**Fields:**
- `time` (string): Unix timestamp in milliseconds
- `writableLayer` (number): Docker writable-layer size in bytes (`SizeRw`)
- `volumesTotal` (number): Summed size in bytes of the container's volume/bind mounts (0 when `STORAGE_VOLUMES_ENABLED=false` or host paths aren't mounted)
- `human_friendly_time` (string): ISO 8601 formatted timestamp (debug mode only)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/container/postgres-db/disk/current
```

---

### Get Container Storage History

Retrieve historical writable-layer and volume sizes for a container.

**Endpoint:** `GET /api/container/:containerId/disk/history`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `containerId` | string | Yes | Exact container display name recorded by Sentinel |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:01Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

Response items use the same shape as `/api/container/:containerId/disk/current`.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/container/postgres-db/disk/history?from=2024-01-15T00:00:00Z"
```

---

## Traffic Analytics

On-box, aggregate-only web/traffic analytics computed from the reverse-proxy access log (Traefik/Caddy JSON logs). No raw request rows are stored — only per-minute rollups, compacted to hourly and daily tiers over time.

**These endpoints only exist when Sentinel is built with the `traffic` Cargo feature *and* `TRAFFIC_ENABLED=true` at runtime.** Otherwise every endpoint below returns `404` (with `{"error": "traffic analytics not enabled"}` when the feature is built but disabled).

Queries sum across every tier the range touches, so results are always complete and up-to-the-minute. The only caveat is granularity: once data is rolled up, a `from` partway through an hour or day snaps to that bucket's boundary.

### Get Recorded Apps

List every app UUID (or host, for Caddy — see [Coolify integration](./README.md#coolify-integration)) that traffic analytics has recorded data for.

**Endpoint:** `GET /api/traffic/apps`

**Response:**
```json
["jc4wsgs", "another-app-uuid"]
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/traffic/apps
```

---

### Get App Traffic Overview

Retrieve request/bandwidth totals, status-class counts, latency percentiles, and estimated unique visitors for one app, merged across every host it was served on.

**Endpoint:** `GET /api/app/:uuid/traffic/overview`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uuid` | string | Yes | Coolify app UUID (or host, for Caddy) |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

**Response:**
```json
{
  "requests": 128340,
  "bytes_in": 15200000,
  "bytes_out": 981000000,
  "status": {
    "s2xx": 124000,
    "s3xx": 3200,
    "s4xx": 1100,
    "s5xx": 40
  },
  "latency": {
    "p50": 42.0,
    "p95": 210.5,
    "p99": 480.0
  },
  "unique_visitors": 8421
}
```

**Fields:**
- `requests` (number): Total request count in range
- `bytes_in` / `bytes_out` (number): Total request/response bytes in range
- `status.s2xx` / `s3xx` / `s4xx` / `s5xx` (number): Request counts by HTTP status class
- `latency.p50` / `p95` / `p99` (number): Approximate latency percentiles in milliseconds (t-digest estimate); `0.0` when the range has no decodable latency data
- `unique_visitors` (number): Approximate distinct client IPs (HyperLogLog++ estimate, ~1-2% error)

An app with no data in the requested range returns a `200` with every counter zeroed, not a `404` — `404` is reserved for "traffic analytics isn't enabled at all".

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/app/jc4wsgs/traffic/overview?from=2024-01-15T00:00:00Z&to=2024-01-16T00:00:00Z"
```

---

### Get App Top Paths

Retrieve the busiest request paths for one app, summed across every bucket in range, with per-path latency.

**Endpoint:** `GET /api/app/:uuid/traffic/paths`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uuid` | string | Yes | Coolify app UUID (or host, for Caddy) |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |
| `limit` | integer | No | `50` | Number of paths to return (max `1000`), applied after summing across buckets |

**Response:**
```json
[
  {
    "path": "/api/checkout",
    "requests": 5210,
    "bytes_out": 41200000,
    "p50": 38.0,
    "p95": 190.0
  }
]
```

**Fields:**
- `path` (string): Request path. A synthetic `__other__` entry absorbs the long tail past the server's top-N cap (`TRAFFIC_TOPN`)
- `requests` (number): Total request count for this path in range
- `bytes_out` (number): Total response bytes for this path in range
- `p50` / `p95` (number): Approximate per-path latency percentiles in milliseconds (`p99` is available from the overview endpoint)

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/app/jc4wsgs/traffic/paths?from=2024-01-15T00:00:00Z&limit=10"
```

---

### Get App Dimension Breakdown

Retrieve the top values of one dimension (status, method, country, referer, browser, OS, device, protocol, scheme, TLS version, cache status, or bot classification) for one app, summed across every bucket in range.

**Endpoint:** `GET /api/app/:uuid/traffic/breakdown/:dimension`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uuid` | string | Yes | Coolify app UUID (or host, for Caddy) |
| `dimension` | string | Yes | One of `status`, `method`, `country`, `referer`, `browser`, `os`, `device`, `protocol`, `scheme`, `tls`, `cache`, `bot`. An unrecognized dimension returns an empty array, not an error |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |
| `limit` | integer | No | `50` | Number of values to return (max `1000`), applied after summing across buckets |

**Response:**
```json
[
  {
    "value": "US",
    "requests": 42000,
    "bytes_out": 320000000
  }
]
```

**Fields:**
- `value` (string): The dimension's value (e.g. a country ISO code, a browser name, `true`/`false` for `bot`). A synthetic `__other__` entry absorbs the long tail past the server's top-N cap (`TRAFFIC_TOPN`)
- `requests` (number): Total request count for this value in range
- `bytes_out` (number): Total response bytes for this value in range

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/app/jc4wsgs/traffic/breakdown/country?from=2024-01-15T00:00:00Z&limit=20"
```

---

### Get Server-Wide Traffic Overview

Same shape as [Get App Traffic Overview](#get-app-traffic-overview), but merged across **every app and host** on the box. Latency percentiles (t-digest) and unique visitors (HyperLogLog++) are merged server-side from the stored sketches, so they are a true cross-app merge — not a sum of per-app estimates.

**Endpoint:** `GET /api/traffic/overview`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |

Response body is identical to the per-app overview. An empty range returns a `200` with every counter zeroed, not a `404`.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/traffic/overview?from=2024-01-15T00:00:00Z&to=2024-01-16T00:00:00Z"
```

---

### Get Server-Wide Top Paths

Busiest request paths across **every app** on the box, summed over the range with per-path latency. The same path served by multiple apps is merged into a single entry, giving a correct top-N across all apps rather than a merge of per-app top-N lists.

**Endpoint:** `GET /api/traffic/paths`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |
| `limit` | integer | No | `50` | Number of paths to return (max `1000`), applied after summing across apps and buckets |

Response body is identical to the per-app top-paths endpoint.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/traffic/paths?from=2024-01-15T00:00:00Z&limit=10"
```

---

### Get Server-Wide Dimension Breakdown

Top values of one dimension across **every app** on the box, summed over the range.

**Endpoint:** `GET /api/traffic/breakdown/:dimension`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `dimension` | string | Yes | One of `status`, `method`, `country`, `referer`, `browser`, `os`, `device`, `protocol`, `scheme`, `tls`, `cache`, `bot`. An unrecognized dimension returns an empty array, not an error |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `from` | string | No | `1970-01-01T00:00:00Z` | Start date in ISO 8601 format |
| `to` | string | No | Current time | End date in ISO 8601 format |
| `limit` | integer | No | `50` | Number of values to return (max `1000`), applied after summing across apps and buckets |

Response body is identical to the per-app breakdown endpoint.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/traffic/breakdown/country?from=2024-01-15T00:00:00Z&limit=20"
```

---

### Get App Status-Class Time Series

Per-bucket request counts by HTTP status class for one app, for charting. The response is a fixed-length, zero-filled array: 24 hourly buckets for `range=24h`, and 7 or 30 daily buckets for `range=7d`/`range=30d`.

**Endpoint:** `GET /api/app/:uuid/traffic/series`

**Path Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `uuid` | string | Yes | Coolify app UUID (or host, for Caddy) |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `range` | string | No | `24h` | Window + granularity: `24h` (hourly), `7d`/`30d` (daily) |

Each element is `{ "bucket", "s2xx", "s3xx", "s4xx", "s5xx" }`, where `bucket` is the unix-millis start of the bucket. An app with no data in range returns a `200` with every bucket zeroed, not a `404`.

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/app/jc4wsgs/traffic/series?range=24h"
```

```json
[
  { "bucket": 1723334400000, "s2xx": 42, "s3xx": 3, "s4xx": 1, "s5xx": 0 },
  { "bucket": 1723338000000, "s2xx": 0, "s3xx": 0, "s4xx": 0, "s5xx": 0 }
]
```

---

### Get Server-Wide Status-Class Time Series

Same shape as [Get App Status-Class Time Series](#get-app-status-class-time-series), merged across **every app and host** on the box.

**Endpoint:** `GET /api/traffic/series`

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `range` | string | No | `24h` | Window + granularity: `24h` (hourly), `7d`/`30d` (daily) |

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://localhost:8888/api/traffic/series?range=7d"
```

---

### Get GeoIP Attribution

Retrieve the license attribution string for whichever GeoIP data source is currently active, so it can be surfaced in a UI.

**Endpoint:** `GET /api/traffic/attribution`

**Response:**
```json
{
  "attribution": "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com"
}
```

**Fields:**
- `attribution` (string or null): The active source's required attribution string, or `null` when GeoIP is disabled, still resolving, or using an unrecognized `GEOIP_DB_URL` override

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/traffic/attribution
```

---

## Debug Endpoints

Debug endpoints are only available when the `DEBUG` environment variable is set to `true`.

### Get Database Statistics

Retrieve database storage statistics and estimated logical table sizes.

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
      "row_count": 600,
      "size_mb": "0.50",
      "size_kb": "512.00"
    },
    {
      "table_name": "memory_usage",
      "row_count": 600,
      "size_mb": "0.30",
      "size_kb": "307.20"
    }
  ]
}
```

**Example:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8888/api/stats
```

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
