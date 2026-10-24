# Sentinel API Reference

Sentinel provides a REST API for retrieving system and Docker container metrics. All metrics can be queried both for current values and historical data.

## OpenAPI specification (source of truth)

The full API is described in [`openapi.json`](./openapi.json). The file is
**generated from the route annotations in code**: a test fails in CI when the
file and the code do not match, so it can never drift from the implementation.
Sentinel does not serve the spec or a docs UI at runtime.

To browse it, open `openapi.json` in any OpenAPI tool, for example
<https://editor.swagger.io>, Scalar, Postman, or Insomnia.

To regenerate it after you change a route:

```bash
cargo run -p api --features traffic --example openapi   # or: just openapi
```

## Authentication

Metrics and debug endpoints require a Bearer token. The health and version
endpoints are public so container and orchestration probes can use them. Set
the `TOKEN` environment variable when running Sentinel, and include it in
protected requests:

```bash
Authorization: Bearer YOUR_TOKEN_HERE
```

## Conditional routes

Some documented routes are only served under specific build/runtime
configuration and return `404` otherwise (their descriptions say so too):

- **Traffic Analytics** (`/api/traffic/*`, `/api/app/{uuid}/traffic/*`,
  `/api/resource/{uuid}/traffic/*`):
  require a binary built with the `traffic` Cargo feature **and**
  `TRAFFIC_ENABLED=true` at runtime. Release and Docker builds always include
  the feature.
- **`/api/stats`**: only served when `DEBUG=true`.

## Date/Time format

All date/time query parameters use ISO 8601 in UTC: `YYYY-MM-DDTHH:MM:SSZ`.

## History windows

Metric history endpoints (`/api/{cpu,memory,disk,load,network}/history` and
`/api/container/{id}/{cpu,memory,disk,network}/history`) return every stored row
by default. Add `bucket_ms=<positive integer>` to average rows per
epoch-aligned window of that width: each row's `time` is the window start,
and disk keeps one row per mount per window. The row shape does not change.
Use it for long ranges: a 7-day read with `bucket_ms=600000` returns about 1000
rows per series instead of tens of thousands.

## Errors

Error responses share one shape: `{"error": "<message>"}` with status `400`
(invalid query parameters), `401` (missing/invalid token), `404` (route
gated off, see above), or `500` (internal error).
