use serde::Serialize;

/// WIRE FORMAT IS FROZEN. `percent` is a string here (history endpoints) but a
/// number in /api/cpu/current. Do not "fix" this — Coolify parses it as-is.
#[derive(Debug, Clone, Serialize)]
pub struct CpuUsage {
    pub time: String,
    pub percent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

/// WIRE FORMAT IS FROZEN. `usedPercent` is the only camelCase key in the API.
#[derive(Debug, Clone, Serialize)]
pub struct MemUsage {
    pub time: String,
    pub total: u64,
    pub available: u64,
    pub used: u64,
    #[serde(rename = "usedPercent")]
    pub used_percent: f64,
    pub free: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

/// Server filesystem usage for one mountpoint. These endpoints are new (not
/// part of the frozen Go wire format), so `time` is a stringified millis for
/// consistency with the other series while byte fields stay numeric.
#[derive(Debug, Clone, Serialize)]
pub struct DiskUsage {
    pub time: String,
    pub mount: String,
    pub total: u64,
    pub used: u64,
    pub available: u64,
    #[serde(rename = "usedPercent")]
    pub used_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

/// Per-container storage: Docker writable-layer size plus summed volume sizes.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerDiskUsage {
    pub time: String,
    #[serde(rename = "writableLayer")]
    pub writable_layer: u64,
    #[serde(rename = "volumesTotal")]
    pub volumes_total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_friendly_time: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

// --- Traffic analytics (design spec §7) -------------------------------------
//
// These four types are NEW wire format — nothing in the frozen Go API
// corresponds to them — so they use plain snake_case and numeric fields
// throughout rather than inheriting `CpuUsage`/`MemUsage`'s stringified and
// camelCase quirks. They are declared unconditionally (not behind the
// `traffic` feature), like `AppState::analytics`, to keep the module shape
// stable across builds.

/// App-level traffic totals for a query range, merged across *every* host
/// that served the app (per-host detail is deliberately not exposed here).
#[derive(Debug, Clone, Serialize)]
pub struct TrafficOverview {
    pub requests: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub status: TrafficStatusBreakdown,
    pub latency: TrafficLatency,
    /// Approximate distinct client IPs (HyperLogLog++ estimate, ~1-2% error).
    pub unique_visitors: u64,
}

/// Request counts by HTTP status class.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficStatusBreakdown {
    pub s2xx: i64,
    pub s3xx: i64,
    pub s4xx: i64,
    pub s5xx: i64,
}

/// Approximate latency quantiles in milliseconds (t-digest estimate). `0.0`
/// on every field when the range holds no decodable latency sketch.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficLatency {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

/// One row of the top-paths table, summed over every bucket in the range.
/// Carries only p50/p95 — p99 is omitted deliberately to keep a 50-row
/// payload small, and the app-level p99 is available from the overview.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficPath {
    pub path: String,
    /// The app (Coolify app UUID, or host for Caddy) that served this path,
    /// so a server-wide response can attribute each path back to its owning
    /// app/domain. On a per-app endpoint every row carries the queried app.
    pub app: String,
    pub requests: i64,
    pub bytes_out: i64,
    pub p50: f64,
    pub p95: f64,
}

/// One value of a breakdown dimension (country, device, status class, ...),
/// summed over every bucket in the range.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficBreakdownEntry {
    pub value: String,
    pub requests: i64,
    pub bytes_out: i64,
}

/// One time bucket of status-class request counts, for the series endpoints.
/// `bucket` is the unix-millis start of the bucket (hour- or day-aligned by
/// the request's `range`). Counts are zero for buckets with no traffic.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficSeriesBucket {
    pub bucket: i64,
    pub s2xx: i64,
    pub s3xx: i64,
    pub s4xx: i64,
    pub s5xx: i64,
}

/// The attribution string required by the license of whichever GeoIP source
/// is currently active (design spec §6), or `null` when none applies (GeoIP
/// disabled, not yet resolved, or an unrecognized `GEOIP_DB_URL` override).
#[derive(Debug, Clone, Serialize)]
pub struct TrafficAttribution {
    pub attribution: Option<String>,
}
