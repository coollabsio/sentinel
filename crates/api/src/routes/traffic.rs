//! Traffic-analytics query endpoints (design spec §7).
//!
//! Structurally these mirror `routes::container`: path param + `Query`,
//! `resolve_range`, the `history_queries` semaphore, and `spawn_blocking`
//! around the SQLite call. Two things are specific to this module:
//!
//! 1. **The whole module is `#[cfg(feature = "traffic")]`.** It is the only
//!    place in `api` that needs the `traffic` crate, because merging the
//!    persisted t-digest / HyperLogLog BLOBs requires those sketch types.
//!    `AppState::analytics` is *not* gated, so the compile-time gate only
//!    decides whether the routes exist; whether they have a database behind
//!    them is a runtime question every handler answers first (404).
//! 2. **Rows come back per bucket, not pre-aggregated.** `stats_range`,
//!    `paths_range` and `breakdown_range` return one row per (bucket, key),
//!    so summing across buckets — and merging each key's sketches — happens
//!    here, in [`summarize_stats`] / [`top_paths`] / [`top_breakdown`].

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use store::traffic::{BreakdownRow, PathRow, StatsRow, Tier};
use traffic::compaction::effective_topn;
use traffic::sketches::{LatencyDigest, Uniques};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::types::{
    ErrorBody, TrafficAttribution, TrafficBreakdownEntry, TrafficLatency, TrafficOverview,
    TrafficPath, TrafficStatusBreakdown,
};

const MINUTE_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Matches the *host* endpoints' default (`routes::cpu`), not `container`'s
/// `…:01Z`. That one-second asymmetry only exists to preserve the Go
/// implementation's behaviour, and these endpoints are new.
///
/// Note the interaction with [`tier_for_span`]: an unbounded `from` makes the
/// span ~56 years, which selects the `1d` tier. That is the intended
/// behaviour — "all of history" is a daily-resolution question — but it does
/// mean a caller who omits `from` on a fresh install sees nothing until
/// compaction has produced `1d` rows. Callers wanting recent, fine-grained
/// data are expected to pass a `from`.
const DEFAULT_FROM: &str = "1970-01-01T00:00:00Z";

const DEFAULT_LIMIT: usize = 50;
/// Upper bound on the caller-supplied `limit`, so one request cannot ask the
/// handler to materialize an unbounded result set.
const MAX_LIMIT: usize = 1_000;

/// Last-resort ceiling on the row budget computed by [`scan_budget`], purely
/// as a memory backstop against a pathological span/top-N combination (an
/// unbounded `from` at the `1d` tier with a huge `TRAFFIC_TOPN`, say). It is
/// deliberately far above what any tier can legitimately emit for a sane
/// configuration — the budget is meant to be governed by [`scan_budget`]'s
/// arithmetic, not by this number. Hitting it is logged, so truncation is
/// observable rather than silent.
const MAX_SCAN_ROWS: usize = 1_000_000;

/// Row budget handed to `paths_range`/`breakdown_range`, deliberately *not*
/// the caller's `limit`.
///
/// Those queries limit raw per-bucket rows, but the caller's `limit` means
/// "top N keys after summing across buckets" — applying it in SQL would
/// truncate the input to the grouping and can pick the wrong keys entirely
/// (a value with 4+5 requests across two buckets outranks one with 6 in a
/// single bucket, but only the grouped view can see that). So the store call
/// is bounded by this budget purely as a memory guard, and the caller's limit
/// is applied after grouping.
///
/// The budget is therefore sized to what the writers can *legitimately*
/// produce for the queried span at the resolved tier, rather than to a guess
/// at typical usage: `TopN` emits at most `cap` keys plus one `__other__`
/// roll-up row per (bucket, app, key-space), so a full-depth window is
/// `buckets × (cap + 1)` rows. A fixed constant instead truncates real
/// queries — at `topn = 50` a 100_000-row cap covers only ~1961 of the `1m`
/// tier's 2880 buckets, and since these queries order by bucket ascending the
/// rows it drops are the *newest* ones.
///
/// `cap` is *not* the same across tiers. `1m` rows come straight from
/// `flush_window` and are capped at the configured `topn` by the aggregator.
/// `1h`/`1d` rows are produced only by compaction, which re-caps at
/// [`traffic::compaction::effective_topn`] — deliberately wider, because a
/// coarse bucket unions up to 60 (or 24) finer ones and so legitimately holds
/// more distinct keys than any single one of them. Budgeting the coarse tiers
/// at `topn + 1` would truncate them: at `topn = 50` a 7-day path query gets
/// 168 × 51 = 8568 rows against up to 168 × 201 = 33_768 real ones.
fn scan_budget(tier: Tier, from: i64, to: i64, topn: u32) -> usize {
    let bucket_ms = match tier {
        Tier::M1 => MINUTE_MS,
        Tier::H1 => HOUR_MS,
        Tier::D1 => DAY_MS,
    } as u128;
    let cap = match tier {
        Tier::M1 => topn as usize,
        Tier::H1 | Tier::D1 => effective_topn(topn as usize),
    } as u128;
    let span = to.saturating_sub(from).max(0) as u128;
    // A partial bucket is still a bucket, and a zero-width span still admits
    // the one bucket its bound falls in.
    let buckets = span.div_ceil(bucket_ms).max(1);
    let budget = buckets.saturating_mul(cap + 1);
    budget.min(MAX_SCAN_ROWS as u128) as usize
}

/// Logs when a scan came back exactly at its budget, i.e. the SQL `LIMIT`
/// may have cut rows out of the grouping. With a tier-aware [`scan_budget`]
/// this should only ever happen when [`MAX_SCAN_ROWS`] clamped the budget.
fn warn_if_truncated(query: &str, app: &str, rows: usize, budget: usize) {
    if rows >= budget {
        tracing::warn!(
            query,
            app,
            rows,
            budget,
            "traffic scan hit its row budget; results may be truncated"
        );
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // axum 0.8 requires braced params; "/:uuid" panics at build time.
        .route("/api/traffic/apps", get(apps))
        .route("/api/app/{uuid}/traffic/overview", get(overview))
        .route("/api/app/{uuid}/traffic/paths", get(paths))
        .route(
            "/api/app/{uuid}/traffic/breakdown/{dimension}",
            get(breakdown),
        )
        .route("/api/traffic/attribution", get(attribution))
}

/// `from`/`to` plus a top-N cap, for the two ranked endpoints.
///
/// A separate struct rather than an extension of `HistoryQuery`: that type is
/// shared by every host and container history endpoint, none of which take a
/// limit.
#[derive(Debug, Deserialize)]
pub struct TopQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    /// A `String`, not a `usize`, so `?limit=` (empty) can be treated as
    /// absent rather than rejected by the extractor — the same courtesy
    /// `resolve_range` extends to `?from=`.
    pub limit: Option<String>,
}

impl TopQuery {
    fn range(&self) -> HistoryQuery {
        HistoryQuery {
            from: self.from.clone(),
            to: self.to.clone(),
        }
    }
}

/// Finest tier whose retention window plausibly covers the requested span
/// (design spec §7): `1m` data is kept 48h and `1h` data 30d, so a query
/// wider than either would read a partially-expired series.
fn tier_for_span(from: i64, to: i64) -> Tier {
    let span = to.saturating_sub(from);
    if span < 48 * HOUR_MS {
        Tier::M1
    } else if span < 30 * DAY_MS {
        Tier::H1
    } else {
        Tier::D1
    }
}

#[allow(clippy::result_large_err)]
fn resolve_limit(raw: Option<&str>) -> Result<usize, Response> {
    let Some(s) = raw.filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_LIMIT);
    };
    match s.parse::<usize>() {
        Ok(0) | Err(_) => Err(bad_limit()),
        Ok(n) => Ok(n.min(MAX_LIMIT)),
    }
}

fn bad_limit() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: format!("Invalid 'limit'. Use a positive integer up to {MAX_LIMIT}"),
        }),
    )
        .into_response()
}

/// The subsystem is compiled in but has no database — either `TRAFFIC_ENABLED`
/// is off or the analytics store failed to open. Distinct from "enabled, but
/// nothing recorded in this range", which is a `200` with an empty/zeroed body.
fn analytics_disabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody {
            error: "traffic analytics not enabled".to_string(),
        }),
    )
        .into_response()
}

async fn apps(State(state): State<Arc<AppState>>) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || analytics.apps()).await;
    drop(permit);
    match result {
        Ok(Ok(rows)) => Json(rows).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Reports the license attribution string for whichever GeoIP source is
/// currently active (design spec §6), so operators/UIs can surface it
/// without grepping the boot log. Gated on `analytics` like every other
/// route here, even though the value technically lives outside the
/// analytics store, because GeoIP is part of the same opt-in subsystem.
async fn attribution(State(state): State<Arc<AppState>>) -> Response {
    if state.analytics.is_none() {
        return analytics_disabled();
    }
    let attribution = state.geoip_attribution.get().cloned().flatten();
    Json(TrafficAttribution { attribution }).into_response()
}

async fn overview(
    Path(app): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let tier = tier_for_span(from, to);

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    // The sketch decode/merge runs inside the blocking task too: it is CPU
    // work over potentially thousands of BLOBs and has no business on the
    // async runtime's worker threads.
    let result = tokio::task::spawn_blocking(move || {
        analytics
            .stats_range(tier, &app, from, to)
            .map(summarize_stats)
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

async fn paths(
    Path(app): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<TopQuery>,
) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    let (from, to) = match resolve_range(&q.range(), DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let limit = match resolve_limit(q.limit.as_deref()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let tier = tier_for_span(from, to);
    let budget = scan_budget(tier, from, to, state.config.traffic.topn);

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        analytics
            .paths_range(tier, &app, from, to, budget)
            .map(|rows| {
                warn_if_truncated("paths", &app, rows.len(), budget);
                top_paths(rows, limit)
            })
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

async fn breakdown(
    Path((app, dimension)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<TopQuery>,
) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    let (from, to) = match resolve_range(&q.range(), DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let limit = match resolve_limit(q.limit.as_deref()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let tier = tier_for_span(from, to);
    let budget = scan_budget(tier, from, to, state.config.traffic.topn);

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        analytics
            .breakdown_range(tier, &app, &dimension, from, to, budget)
            .map(|rows| {
                warn_if_truncated("breakdown", &app, rows.len(), budget);
                top_breakdown(rows, limit)
            })
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Collapses every (bucket, host) row of one app into a single app-level
/// summary: plain sums for the counters, a t-digest merge for the latency
/// quantiles, and an HLL union for the visitor estimate.
///
/// A row whose sketch BLOB fails to decode contributes its counters but is
/// skipped for that sketch, and logged. One corrupted page must not turn a
/// dashboard query into a 500 — the same "skip malformed data, don't crash"
/// rule the parser and compaction paths follow.
fn summarize_stats(rows: Vec<StatsRow>) -> TrafficOverview {
    let mut requests = 0i64;
    let mut bytes_in = 0i64;
    let mut bytes_out = 0i64;
    let mut s2xx = 0i64;
    let mut s3xx = 0i64;
    let mut s4xx = 0i64;
    let mut s5xx = 0i64;

    let mut digests: Vec<LatencyDigest> = Vec::with_capacity(rows.len());
    // Starting from an empty sketch rather than the first decodable row keeps
    // this a plain fold; an HLL union with an empty sketch is a no-op.
    let mut visitors = Uniques::new();

    for r in &rows {
        requests = requests.saturating_add(r.requests);
        bytes_in = bytes_in.saturating_add(r.bytes_in);
        bytes_out = bytes_out.saturating_add(r.bytes_out);
        s2xx = s2xx.saturating_add(r.s2xx);
        s3xx = s3xx.saturating_add(r.s3xx);
        s4xx = s4xx.saturating_add(r.s4xx);
        s5xx = s5xx.saturating_add(r.s5xx);

        match LatencyDigest::from_bytes(&r.latency_tdigest) {
            Ok(d) => digests.push(d),
            Err(e) => tracing::warn!(
                error = %e, app = %r.app, host = %r.host, bucket = r.bucket,
                "skipping undecodable latency sketch"
            ),
        }
        match Uniques::from_bytes(&r.uniques_hll) {
            Ok(u) => visitors.merge_from(&u),
            Err(e) => tracing::warn!(
                error = %e, app = %r.app, host = %r.host, bucket = r.bucket,
                "skipping undecodable uniques sketch"
            ),
        }
    }

    // `merge` of an empty slice yields an empty digest, whose quantiles are
    // 0.0 — so a range with no rows (or no decodable ones) needs no special
    // case here.
    let latency = LatencyDigest::merge(&digests);
    TrafficOverview {
        requests,
        bytes_in,
        bytes_out,
        status: TrafficStatusBreakdown {
            s2xx,
            s3xx,
            s4xx,
            s5xx,
        },
        latency: TrafficLatency {
            p50: latency.quantile(0.5),
            p95: latency.quantile(0.95),
            p99: latency.quantile(0.99),
        },
        unique_visitors: visitors.count(),
    }
}

/// Groups per-bucket path rows by path, summing counters and merging each
/// path's latency digests, then returns the `limit` busiest paths.
///
/// Each path's digests are folded *incrementally*, one row at a time, rather
/// than collected into a `Vec` and merged once at the end. Accumulating them
/// would hold one decoded digest per (path, bucket) resident simultaneously —
/// at the `1m` tier's full depth that is hundreds of thousands of ≤100-centroid
/// digests, tens to hundreds of MB, times up to `MAX_CONCURRENT_HISTORY_QUERIES`
/// in flight. Folding as we go bounds resident sketch memory by the number of
/// *distinct paths* instead. `LatencyDigest::merge` re-compresses to its
/// centroid cap on every call, so repeated pairwise folding costs a little
/// accuracy drift and no memory.
fn top_paths(rows: Vec<PathRow>, limit: usize) -> Vec<TrafficPath> {
    struct Acc {
        requests: i64,
        bytes_out: i64,
        latency: LatencyDigest,
    }

    let mut by_path: HashMap<String, Acc> = HashMap::new();
    for r in rows {
        let acc = by_path.entry(r.path).or_insert_with(|| Acc {
            requests: 0,
            bytes_out: 0,
            latency: LatencyDigest::new(),
        });
        acc.requests = acc.requests.saturating_add(r.requests);
        acc.bytes_out = acc.bytes_out.saturating_add(r.bytes_out);
        match LatencyDigest::from_bytes(&r.latency_tdigest) {
            // `merge` of an empty digest with `d` is `d`, so the first row of
            // a path needs no special case.
            Ok(d) => {
                let so_far = std::mem::take(&mut acc.latency);
                acc.latency = LatencyDigest::merge(&[so_far, d]);
            }
            Err(e) => tracing::warn!(
                error = %e, app = %r.app, bucket = r.bucket,
                "skipping undecodable path latency sketch"
            ),
        }
    }

    let mut out: Vec<TrafficPath> = by_path
        .into_iter()
        .map(|(path, acc)| TrafficPath {
            path,
            requests: acc.requests,
            bytes_out: acc.bytes_out,
            p50: acc.latency.quantile(0.5),
            p95: acc.latency.quantile(0.95),
        })
        .collect();
    sort_and_truncate(&mut out, limit, |p| (p.requests, &p.path));
    out
}

/// Groups per-bucket breakdown rows by value, summing counters, then returns
/// the `limit` busiest values. No sketches on this table.
fn top_breakdown(rows: Vec<BreakdownRow>, limit: usize) -> Vec<TrafficBreakdownEntry> {
    let mut by_value: HashMap<String, (i64, i64)> = HashMap::new();
    for r in rows {
        let acc = by_value.entry(r.value).or_insert((0, 0));
        acc.0 = acc.0.saturating_add(r.requests);
        acc.1 = acc.1.saturating_add(r.bytes_out);
    }

    let mut out: Vec<TrafficBreakdownEntry> = by_value
        .into_iter()
        .map(|(value, (requests, bytes_out))| TrafficBreakdownEntry {
            value,
            requests,
            bytes_out,
        })
        .collect();
    sort_and_truncate(&mut out, limit, |e| (e.requests, &e.value));
    out
}

/// Sorts by request count descending, breaking ties on the key ascending so
/// the response is deterministic (the `HashMap` grouping above is not), then
/// keeps the top `limit`.
fn sort_and_truncate<T, F>(rows: &mut Vec<T>, limit: usize, key: F)
where
    F: Fn(&T) -> (i64, &String),
{
    rows.sort_by(|a, b| {
        let (a_reqs, a_key) = key(a);
        let (b_reqs, b_key) = key(b);
        b_reqs.cmp(&a_reqs).then_with(|| a_key.cmp(b_key))
    });
    rows.truncate(limit);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::net::{IpAddr, Ipv4Addr};
    use store::traffic::AnalyticsStore;
    use tower::ServiceExt;
    use traffic::sketches::{LatencyDigest, Uniques};

    /// 2023-11-14T22:13:20Z. Both seeded buckets sit inside RANGE below.
    const BUCKET: i64 = 1_700_000_000_000;
    const NEXT_BUCKET: i64 = BUCKET + 60_000;
    /// A 24h window (< 48h) so tier selection lands on the `1m` tier, which
    /// is the only one `flush_window` writes.
    const RANGE: &str = "from=2023-11-14T00:00:00Z&to=2023-11-15T00:00:00Z";

    fn digest_bytes(values: &[f64]) -> Vec<u8> {
        let mut d = LatencyDigest::new();
        d.add(values);
        d.to_bytes()
    }

    fn uniques_bytes(range: std::ops::Range<u32>) -> Vec<u8> {
        let mut u = Uniques::new();
        for i in range {
            u.add_ip(IpAddr::V4(Ipv4Addr::from(i)));
        }
        u.to_bytes()
    }

    fn ramp(lo: u32, hi: u32) -> Vec<f64> {
        (lo..=hi).map(f64::from).collect()
    }

    fn stats(
        bucket: i64,
        app: &str,
        host: &str,
        requests: i64,
        latency: Vec<u8>,
        uniques: Vec<u8>,
    ) -> StatsRow {
        StatsRow {
            bucket,
            app: app.into(),
            host: host.into(),
            requests,
            bytes_in: requests * 10,
            bytes_out: requests * 100,
            s2xx: requests - 2,
            s3xx: 1,
            s4xx: 1,
            s5xx: 0,
            latency_tdigest: latency,
            uniques_hll: uniques,
        }
    }

    fn path_row(bucket: i64, app: &str, path: &str, requests: i64, latency: Vec<u8>) -> PathRow {
        PathRow {
            bucket,
            app: app.into(),
            path: path.into(),
            requests,
            bytes_out: requests * 100,
            latency_tdigest: latency,
        }
    }

    fn bd(bucket: i64, app: &str, value: &str, requests: i64) -> BreakdownRow {
        BreakdownRow {
            bucket,
            app: app.into(),
            dimension: "country".into(),
            value: value.into(),
            requests,
            bytes_out: requests * 100,
        }
    }

    /// Two hosts of `app-a` in one bucket plus a second bucket's paths and
    /// breakdown, so grouping across buckets is exercised for real.
    fn seeded() -> AnalyticsStore {
        let a = AnalyticsStore::open_in_memory().unwrap();
        a.flush_window(
            &[
                stats(
                    BUCKET,
                    "app-a",
                    "h1",
                    10,
                    digest_bytes(&ramp(1, 100)),
                    uniques_bytes(0..500),
                ),
                stats(
                    BUCKET,
                    "app-a",
                    "h2",
                    30,
                    digest_bytes(&ramp(101, 200)),
                    uniques_bytes(250..750),
                ),
                stats(
                    BUCKET,
                    "app-b",
                    "h1",
                    7,
                    digest_bytes(&ramp(1, 10)),
                    uniques_bytes(0..10),
                ),
            ],
            &[
                path_row(BUCKET, "app-a", "/a", 5, digest_bytes(&ramp(1, 10))),
                path_row(BUCKET, "app-a", "/b", 2, digest_bytes(&ramp(1, 10))),
                path_row(NEXT_BUCKET, "app-a", "/a", 3, digest_bytes(&ramp(1, 10))),
                path_row(NEXT_BUCKET, "app-a", "/b", 20, digest_bytes(&ramp(1, 10))),
            ],
            &[
                bd(BUCKET, "app-a", "US", 5),
                bd(BUCKET, "app-a", "DE", 3),
                bd(NEXT_BUCKET, "app-a", "US", 4),
                bd(NEXT_BUCKET, "app-a", "FR", 10),
            ],
        )
        .unwrap();
        a
    }

    fn state(analytics: Option<AnalyticsStore>) -> Arc<AppState> {
        let mut config = config::Config::load_for_test();
        config.token = "secret".into();
        Arc::new(AppState {
            auth_header: format!("Bearer {}", config.token),
            config: Arc::new(config),
            store: store::Store::open_in_memory().unwrap(),
            sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
            memory: Arc::new(crate::CachedMemory::new(
                collector::HostSampler::new().sample_memory(),
            )),
            history_queries: Arc::new(tokio::sync::Semaphore::new(
                crate::MAX_CONCURRENT_HISTORY_QUERIES,
            )),
            analytics,
            geoip_attribution: Arc::new(std::sync::OnceLock::new()),
        })
    }

    async fn get_with(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
        let res = crate::router(state)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn get(uri: &str) -> (StatusCode, serde_json::Value) {
        get_with(state(Some(seeded())), uri).await
    }

    #[test]
    fn tier_is_selected_by_span() {
        // Boundaries are exclusive at the low end: exactly 48h is already
        // too wide for the 1m tier, exactly 30d too wide for 1h.
        assert_eq!(tier_for_span(0, 48 * HOUR_MS - 1), Tier::M1);
        assert_eq!(tier_for_span(0, 48 * HOUR_MS), Tier::H1);
        assert_eq!(tier_for_span(0, 30 * DAY_MS - 1), Tier::H1);
        assert_eq!(tier_for_span(0, 30 * DAY_MS), Tier::D1);
        assert_eq!(tier_for_span(0, 400 * DAY_MS), Tier::D1);
        // Offset windows are judged on width, not absolute position.
        assert_eq!(tier_for_span(BUCKET, BUCKET + HOUR_MS), Tier::M1);
    }

    #[tokio::test]
    async fn apps_lists_recorded_apps() {
        let (s, j) = get("/api/traffic/apps").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j, serde_json::json!(["app-a", "app-b"]));
    }

    #[tokio::test]
    async fn attribution_is_null_when_geoip_has_not_resolved_yet() {
        // Mirrors real startup: the OnceLock is created empty and only ever
        // filled in once GeoIp::bootstrap succeeds, which can take a while
        // (or never happen, e.g. GEOIP_ENABLED=false).
        let (s, j) = get("/api/traffic/attribution").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j["attribution"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn attribution_reports_the_resolved_string() {
        let st = state(Some(seeded()));
        st.geoip_attribution
            .set(Some(
                "IP Geolocation by DB-IP (https://db-ip.com)".to_string(),
            ))
            .unwrap();
        let (s, j) = get_with(st, "/api/traffic/attribution").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            j["attribution"],
            "IP Geolocation by DB-IP (https://db-ip.com)"
        );
    }

    #[tokio::test]
    async fn overview_merges_every_host_of_the_app() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/overview?{RANGE}")).await;
        assert_eq!(s, StatusCode::OK);

        assert_eq!(j["requests"], 40, "10 (h1) + 30 (h2)");
        assert_eq!(j["bytes_in"], 400);
        assert_eq!(j["bytes_out"], 4000);
        assert_eq!(j["status"]["s2xx"], 36, "8 + 28");
        assert_eq!(j["status"]["s3xx"], 2);
        assert_eq!(j["status"]["s4xx"], 2);
        assert_eq!(j["status"]["s5xx"], 0);

        // h1 saw latencies 1..=100, h2 saw 101..=200: the merged digest must
        // describe 1..=200, not either half alone.
        let p50 = j["latency"]["p50"].as_f64().unwrap();
        let p95 = j["latency"]["p95"].as_f64().unwrap();
        let p99 = j["latency"]["p99"].as_f64().unwrap();
        assert!((90.0..=112.0).contains(&p50), "p50 was {p50}");
        assert!((180.0..=200.0).contains(&p95), "p95 was {p95}");
        assert!(p99 >= p95 && p99 <= 201.0, "p99 was {p99}");

        // 0..500 unioned with 250..750 is 750 distinct IPs; HLL++ at
        // precision 14 is well inside 5% of that.
        let uniq = j["unique_visitors"].as_u64().unwrap();
        assert!((712..=788).contains(&uniq), "unique_visitors was {uniq}");
    }

    #[tokio::test]
    async fn overview_of_an_app_without_data_is_zeroed_not_404() {
        let (s, j) = get(&format!("/api/app/nosuch/traffic/overview?{RANGE}")).await;
        assert_eq!(s, StatusCode::OK, "no data in range is not 'not enabled'");
        assert_eq!(j["requests"], 0);
        assert_eq!(j["latency"]["p50"], 0.0);
        assert_eq!(j["unique_visitors"], 0);
    }

    #[tokio::test]
    async fn overview_skips_undecodable_sketches_without_failing() {
        let a = AnalyticsStore::open_in_memory().unwrap();
        a.flush_window(
            &[
                stats(BUCKET, "app-a", "good", 4, digest_bytes(&[50.0; 20]), {
                    let mut u = Uniques::new();
                    u.add_ip(IpAddr::V4(Ipv4Addr::from(1u32)));
                    u.to_bytes()
                }),
                // Truncated postcard varints: neither blob can decode.
                stats(
                    BUCKET,
                    "app-a",
                    "corrupt",
                    6,
                    vec![0xff, 0xff],
                    vec![0xff, 0xff],
                ),
            ],
            &[],
            &[],
        )
        .unwrap();

        let (s, j) = get_with(
            state(Some(a)),
            &format!("/api/app/app-a/traffic/overview?{RANGE}"),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::OK,
            "one corrupt blob must not fail the query"
        );
        assert_eq!(j["requests"], 10, "counters from both rows still count");
        let p50 = j["latency"]["p50"].as_f64().unwrap();
        assert!(
            (49.0..=51.0).contains(&p50),
            "the decodable digest must still drive the quantiles, got {p50}"
        );
        assert_eq!(j["unique_visitors"], 1);
    }

    #[tokio::test]
    async fn paths_sum_across_buckets_and_sort_by_requests() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}")).await;
        assert_eq!(s, StatusCode::OK);
        let rows = j.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["path"], "/b", "22 requests must outrank /a's 8");
        assert_eq!(rows[0]["requests"], 22);
        assert_eq!(rows[0]["bytes_out"], 2200);
        assert_eq!(rows[1]["path"], "/a");
        assert_eq!(rows[1]["requests"], 8);
        assert!(rows[0]["p50"].as_f64().unwrap() > 0.0);
        assert!(rows[0]["p95"].as_f64().unwrap() > 0.0);
        assert!(rows[0].get("p99").is_none(), "p99 is deliberately omitted");
    }

    #[tokio::test]
    async fn paths_limit_applies_after_grouping() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}&limit=1")).await;
        assert_eq!(s, StatusCode::OK);
        let rows = j.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]["requests"], 22,
            "the limit must cut the grouped top-N, not the raw bucket rows"
        );
    }

    #[tokio::test]
    async fn breakdown_sums_across_buckets_sorts_and_limits() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/breakdown/country?{RANGE}")).await;
        assert_eq!(s, StatusCode::OK);
        let rows = j.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        // US is 5 + 4 = 9 across two buckets; FR is 10 in one. Summing first
        // is what puts FR ahead of US and DE last.
        assert_eq!(rows[0]["value"], "FR");
        assert_eq!(rows[0]["requests"], 10);
        assert_eq!(rows[1]["value"], "US");
        assert_eq!(rows[1]["requests"], 9);
        assert_eq!(rows[1]["bytes_out"], 900);
        assert_eq!(rows[2]["value"], "DE");

        let (s, j) = get(&format!(
            "/api/app/app-a/traffic/breakdown/country?{RANGE}&limit=2"
        ))
        .await;
        assert_eq!(s, StatusCode::OK);
        let rows = j.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["value"], "FR");
        assert_eq!(rows[1]["value"], "US");
    }

    #[tokio::test]
    async fn unknown_dimension_returns_an_empty_array() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/breakdown/nosuch?{RANGE}")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j, serde_json::json!([]));
    }

    #[tokio::test]
    async fn every_endpoint_404s_when_analytics_is_disabled() {
        for uri in [
            "/api/traffic/apps",
            "/api/app/app-a/traffic/overview",
            "/api/app/app-a/traffic/paths",
            "/api/app/app-a/traffic/breakdown/country",
            "/api/traffic/attribution",
        ] {
            let (s, j) = get_with(state(None), uri).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(j["error"], "traffic analytics not enabled", "{uri}");
        }
    }

    #[tokio::test]
    async fn malformed_bounds_and_limits_are_rejected() {
        for uri in [
            "/api/app/app-a/traffic/overview?from=bogus",
            "/api/app/app-a/traffic/paths?to=bogus",
            "/api/app/app-a/traffic/paths?limit=abc",
            "/api/app/app-a/traffic/breakdown/country?limit=0",
        ] {
            let (s, _) = get(uri).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    /// `?from=&to=&limit=` (a caller interpolating empty optionals) must be
    /// treated as absent, exactly as `resolve_range` already does for the
    /// host endpoints — never rejected as malformed.
    #[tokio::test]
    async fn empty_query_values_fall_back_to_defaults() {
        let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}&limit=")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            j.as_array().unwrap().len(),
            2,
            "an empty limit must fall back to the default, not cap at 0"
        );

        let (s, _) = get("/api/app/app-a/traffic/paths?from=&to=&limit=").await;
        assert_eq!(s, StatusCode::OK, "empty bounds must default, not 400");
    }

    /// 2023-11-14T00:00:00Z, the start of WIDE_RANGE below.
    const WIDE_FROM: i64 = 1_699_920_000_000;
    /// 47h — inside the `1m` tier's 48h ceiling, so the widest window the
    /// finest tier can be asked for: 2820 one-minute buckets.
    const WIDE_BUCKETS: i64 = 47 * 60;
    const WIDE_RANGE: &str = "from=2023-11-14T00:00:00Z&to=2023-11-15T23:00:00Z";
    /// Distinct paths per bucket. 40 × 2820 = 112,800 rows, comfortably over
    /// the 100_000 fixed budget this used to be capped at, and under the
    /// tier-aware budget of 2820 × (topn + 1) = 143,820.
    const WIDE_PATHS: i64 = 40;

    /// A realistic worst case for the `1m` tier: every bucket of a 47h window
    /// carrying a full set of per-path rows. The old fixed `MAX_SCAN_ROWS`
    /// (100_000) truncated this at 2500 buckets, silently dropping the newest
    /// 320 buckets — `paths_range` orders by bucket ascending, so the rows the
    /// LIMIT discards are the most recent ones.
    #[tokio::test]
    async fn a_full_width_1m_window_is_not_truncated_by_the_scan_budget() {
        let a = AnalyticsStore::open_in_memory().unwrap();
        let latency = digest_bytes(&[5.0]);
        let mut rows = Vec::with_capacity((WIDE_BUCKETS * WIDE_PATHS) as usize);
        for b in 0..WIDE_BUCKETS {
            for p in 0..WIDE_PATHS {
                rows.push(path_row(
                    WIDE_FROM + b * 60_000,
                    "app-a",
                    &format!("/p{p}"),
                    1,
                    latency.clone(),
                ));
            }
        }
        assert!(
            rows.len() > 100_000,
            "the fixture must exceed the old fixed budget to be a regression test"
        );
        a.flush_window(&[], &rows, &[]).unwrap();

        let (s, j) = get_with(
            state(Some(a)),
            &format!("/api/app/app-a/traffic/paths?{WIDE_RANGE}&limit=1000"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let out = j.as_array().unwrap();
        assert_eq!(out.len(), WIDE_PATHS as usize, "every path must survive");
        for row in out {
            assert_eq!(
                row["requests"], WIDE_BUCKETS,
                "{} lost buckets to truncation",
                row["path"]
            );
        }
    }

    /// 7 days — over the `1m` tier's 48h ceiling and under the `1h` tier's
    /// 30d one, so this resolves to `Tier::H1`: 168 one-hour buckets.
    const COARSE_BUCKETS: i64 = 7 * 24;
    const COARSE_RANGE: &str = "from=2023-11-14T00:00:00Z&to=2023-11-21T00:00:00Z";
    /// Distinct paths per *coarse* bucket. Above the configured `topn` (50)
    /// and below the compaction floor (200), i.e. squarely in the band a
    /// `buckets × (topn + 1)` budget wrongly rules out. 150 × 168 = 25,200
    /// rows, versus a `topn`-sized budget of 168 × 51 = 8,568.
    const COARSE_PATHS: i64 = 150;

    /// Compaction re-caps each coarse `(bucket, app)` group at
    /// `effective_topn(topn)`, not at `topn` — a 1h bucket unions up to 60
    /// minute buckets, so it legitimately holds more distinct paths than any
    /// one of them. A budget of `buckets × (topn + 1)` therefore undersizes
    /// the `1h`/`1d` tiers, and since `paths_range` orders by bucket ascending
    /// the rows the SQL LIMIT drops are the *newest* ones.
    #[tokio::test]
    async fn a_compacted_1h_window_is_not_truncated_by_the_scan_budget() {
        let a = AnalyticsStore::open_in_memory().unwrap();
        let latency = digest_bytes(&[5.0]);
        let mut rows = Vec::with_capacity((COARSE_BUCKETS * COARSE_PATHS) as usize);
        for b in 0..COARSE_BUCKETS {
            for p in 0..COARSE_PATHS {
                rows.push(path_row(
                    WIDE_FROM + b * HOUR_MS,
                    "app-a",
                    &format!("/p{p}"),
                    1,
                    latency.clone(),
                ));
            }
        }
        // These are compaction's output, so they go straight into the `1h`
        // tier — `flush_window` only ever writes `1m`.
        a.write_rows(Tier::H1, &[], &rows, &[]).unwrap();
        assert!(
            rows.len() as i64 > COARSE_BUCKETS * 51,
            "the fixture must exceed a topn-sized budget to be a regression test"
        );

        let (s, j) = get_with(
            state(Some(a)),
            &format!("/api/app/app-a/traffic/paths?{COARSE_RANGE}&limit=1000"),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let out = j.as_array().unwrap();
        assert_eq!(out.len(), COARSE_PATHS as usize, "every path must survive");
        for row in out {
            assert_eq!(
                row["requests"], COARSE_BUCKETS,
                "{} lost buckets to truncation",
                row["path"]
            );
        }
    }

    /// The scan budget is derived from what the resolved tier can legitimately
    /// emit for the queried span, not from a fixed guess.
    #[test]
    fn scan_budget_covers_what_the_tier_can_emit() {
        // 47h of 1m buckets at topn=50 (+1 `__other__` row) = 143_820.
        assert_eq!(
            scan_budget(Tier::M1, WIDE_FROM, WIDE_FROM + 47 * HOUR_MS, 50),
            2820 * 51
        );
        // The coarse tiers have fewer buckets but a *wider* per-bucket cap:
        // compaction re-caps at `effective_topn(topn)`, not at `topn`.
        assert_eq!(scan_budget(Tier::H1, 0, 47 * HOUR_MS, 50), 47 * 201);
        assert_eq!(scan_budget(Tier::D1, 0, 47 * HOUR_MS, 50), 2 * 201);
        // Partial buckets round up, and a zero-width span still admits one.
        assert_eq!(scan_budget(Tier::M1, 0, 1, 50), 51);
        assert_eq!(scan_budget(Tier::M1, 0, 0, 50), 51);
        assert_eq!(scan_budget(Tier::M1, 10, 0, 50), 51);
        // A configured top-N is honoured rather than assumed.
        assert_eq!(scan_budget(Tier::M1, 0, 10 * 60_000, 200), 10 * 201);
        // …and a configured top-N *above* the compaction floor widens the
        // coarse tiers too, exactly as `effective_topn` widens the cap.
        assert_eq!(scan_budget(Tier::M1, 0, 10 * HOUR_MS, 500), 600 * 501);
        assert_eq!(scan_budget(Tier::H1, 0, 10 * HOUR_MS, 500), 10 * 501);
        assert_eq!(scan_budget(Tier::D1, 0, 10 * DAY_MS, 500), 10 * 501);
        // The backstop caps a pathological span/top-N combination.
        assert_eq!(scan_budget(Tier::D1, 0, i64::MAX, 1_000_000), MAX_SCAN_ROWS);
    }

    /// Proves the incremental fold in [`top_paths`] is behaviourally identical
    /// to the all-at-once merge it replaced: every bucket's latencies have to
    /// reach the final digest, not just the last one folded in.
    #[test]
    fn top_paths_merges_the_latencies_of_every_bucket() {
        let rows = vec![
            path_row(BUCKET, "app-a", "/a", 1, digest_bytes(&ramp(1, 50))),
            path_row(
                BUCKET + 60_000,
                "app-a",
                "/a",
                1,
                digest_bytes(&ramp(51, 100)),
            ),
            path_row(
                BUCKET + 120_000,
                "app-a",
                "/a",
                1,
                digest_bytes(&ramp(101, 150)),
            ),
            path_row(
                BUCKET + 180_000,
                "app-a",
                "/a",
                1,
                digest_bytes(&ramp(151, 200)),
            ),
        ];
        let out = top_paths(rows, 10);
        assert_eq!(out.len(), 1);
        // 1..=200 across four buckets: a digest holding only the last bucket
        // (151..=200) would put p50 near 175, and one holding only the first
        // would put p95 near 48.
        assert!(
            (90.0..=112.0).contains(&out[0].p50),
            "p50 was {}, which is not the median of 1..=200",
            out[0].p50
        );
        assert!(
            (180.0..=200.0).contains(&out[0].p95),
            "p95 was {}, which is not the p95 of 1..=200",
            out[0].p95
        );
    }

    /// Pins the documented consequence of `DEFAULT_FROM`: omitting `from`
    /// asks for all of history, which is a `1d`-tier question, so freshly
    /// flushed `1m` rows are deliberately not visible until compaction has
    /// rolled them up. This is behaviour, not a bug — but it is surprising
    /// enough to be worth a test that fails loudly if either the default or
    /// the tier thresholds are changed without thinking about it.
    #[tokio::test]
    async fn an_unbounded_range_reads_the_daily_tier() {
        let (s, j) = get("/api/app/app-a/traffic/paths").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            j,
            serde_json::json!([]),
            "1m rows must not surface in a 1d-tier query"
        );

        let a = seeded();
        // The same rows written to the 1d tier are visible to that query.
        a.write_rows(
            Tier::D1,
            &[],
            &[path_row(
                BUCKET,
                "app-a",
                "/a",
                5,
                digest_bytes(&ramp(1, 10)),
            )],
            &[],
        )
        .unwrap();
        let (s, j) = get_with(state(Some(a)), "/api/app/app-a/traffic/paths").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(j.as_array().unwrap().len(), 1);
        assert_eq!(j.as_array().unwrap()[0]["path"], "/a");
    }
}
