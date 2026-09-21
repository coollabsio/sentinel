# Sentinel API Reference

Sentinel provides a REST API for retrieving system and Docker container metrics. All metrics can be queried both for current values and historical data.

## Interactive documentation (source of truth)

The API is documented by an OpenAPI specification **generated from the route
annotations in code** — it can never drift from the implementation. A running
Sentinel instance serves it in three forms, all without authentication:

| URL | What |
|-----|------|
| `/scalar` | [Scalar](https://scalar.com) interactive API reference |
| `/swagger-ui` | Swagger UI interactive explorer |
| `/api-docs/openapi.json` | The raw OpenAPI document (JSON) |

For example, with the default port: <http://localhost:8888/scalar>

## Authentication

Metrics and debug endpoints require a Bearer token. The health/version
endpoints and the documentation routes are public. Set the `TOKEN`
environment variable when running Sentinel, and include it in protected
requests:

```bash
Authorization: Bearer YOUR_TOKEN_HERE
```

Both frontends have an "Authorize" control where you can paste the token once
to call protected endpoints interactively.

## Conditional routes

Some documented routes are only served under specific build/runtime
configuration and return `404` otherwise (their descriptions say so too):

- **Traffic Analytics** (`/api/traffic/*`, `/api/app/{uuid}/traffic/*`):
  require a binary built with the `traffic` Cargo feature **and**
  `TRAFFIC_ENABLED=true` at runtime. Release and Docker builds always include
  the feature.
- **`/api/stats`**: only served when `DEBUG=true`.

## Date/Time format

All date/time query parameters use ISO 8601 in UTC: `YYYY-MM-DDTHH:MM:SSZ`.

## Errors

Error responses share one shape: `{"error": "<message>"}` with status `400`
(invalid query parameters), `401` (missing/invalid token), `404` (route
gated off, see above), or `500` (internal error).
