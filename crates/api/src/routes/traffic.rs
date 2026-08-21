//! Traffic-analytics query endpoints. Rows are merged across buckets here,
//! including sketch values, rather than in SQL.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use store::traffic::{AnalyticsStore, BreakdownRow, PathRow, StatsRow, Tier};
use traffic::sketches::{LatencyDigest, Uniques};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::now_ms;
use crate::types::{
    ErrorBody, TrafficAppEntry, TrafficAttribution, TrafficBreakdownEntry, TrafficBreakdowns,
    TrafficDashboard, TrafficLatency, TrafficOverview, TrafficPath, TrafficSeriesBucket,
    TrafficStatusBreakdown,
};

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Matches the host endpoints' default. With `from` omitted the range spans all
/// history; the tier union (see [`tier_reads`]) then returns every tier's data —
/// day, hour, and current-minute — so even a brand-new agent with only `1m`
/// rows answers immediately rather than waiting a day for the `1d` tier to fill.
const DEFAULT_FROM: &str = "1970-01-01T00:00:00Z";

const DEFAULT_LIMIT: usize = 50;
/// Upper bound on the caller-supplied `limit`, so one request cannot ask the
/// handler to materialize an unbounded result set.
const MAX_LIMIT: usize = 1_000;

/// Default cap on the dashboard's app leaderboard when `apps_limit` is absent.
const DEFAULT_APPS_LIMIT: usize = 200;

/// SQL `LIMIT` on `paths_range`/`breakdown_range`, purely a memory backstop
/// against a pathological span. Real queries fall far below it; hitting it is
/// logged, so any truncation is observable rather than silent.
const MAX_SCAN_ROWS: usize = 1_000_000;

/// Logs when a scan came back exactly at its budget, i.e. the SQL `LIMIT` may
/// have cut rows out of the grouping — which should only happen at the
/// [`MAX_SCAN_ROWS`] ceiling.
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
        .route("/api/app/{uuid}/traffic/series", get(app_series))
        .route("/api/app/{uuid}/traffic/dashboard", get(app_dashboard))
        // Server-wide variants: same shapes, merged across every app/host.
        .route("/api/traffic/overview", get(server_overview))
        .route("/api/traffic/paths", get(server_paths))
        .route("/api/traffic/breakdown/{dimension}", get(server_breakdown))
        .route("/api/traffic/series", get(series))
        .route("/api/traffic/attribution", get(attribution))
        // One request that bundles every shape above, for Coolify's dashboard.
        .route("/api/traffic/dashboard", get(server_dashboard))
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

/// The only knob for the series endpoints: `24h` (hourly) or `7d`/`30d` (daily).
#[derive(Debug, Deserialize)]
pub struct SeriesQuery {
    pub range: Option<String>,
}

/// Every windowing knob the dashboard bundles: `from`/`to` drive the overview,
/// paths, and breakdowns; `range` drives the series (independently, like the
/// standalone `/series`); the three limits cap each ranked member. All are
/// `Option<String>` so `?from=` / `?paths_limit=` (empty) fall back to the
/// default rather than being rejected — the same courtesy the other endpoints
/// extend.
#[derive(Debug, Deserialize)]
pub struct DashboardQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub range: Option<String>,
    pub paths_limit: Option<String>,
    pub breakdown_limit: Option<String>,
    pub apps_limit: Option<String>,
}

/// Floors `ts` to the start of its containing `width`-wide bucket. `div_euclid`
/// (not `/`) so a pre-epoch `ts` rounds *down* into the earlier bucket rather
/// than towards zero, matching `traffic::compaction::floor_to`.
fn floor_to(ts: i64, width: i64) -> i64 {
    ts.div_euclid(width) * width
}

/// The three tier reads a range query must union to see its whole range, each
/// floored to that tier's own bucket width so a range starting mid-bucket still
/// includes the bucket it falls in (the standard "covering buckets" semantics
/// of any rolled-up store) rather than dropping it.
///
/// Compaction *moves* a window between tiers in one transaction — writes the
/// coarser row and deletes the finer ones together (see
/// `traffic::compaction`), and readers see a WAL snapshot, never a half-applied
/// move. So at any instant a given timestamp lives in exactly one tier: the
/// current hour in `1m`, earlier hours of today in `1h`, older days in `1d`.
/// Summing all three therefore reassembles the full range with each part fresh
/// to its own granularity and *never* double-counts. This is what makes a
/// "last hour" query whole again — the current minutes from `1m` plus the hour
/// compaction has already folded into `1h` — and what lets the default
/// all-history query answer without waiting for the coarse tiers to fill.
///
/// A late `1m` row for an already-folded hour is disjoint from that hour's `1h`
/// total (it arrived after the fold), so the sum stays correct until the next
/// sweep re-merges it; it can never inflate a count.
fn tier_reads(from: i64, to: i64) -> [(Tier, i64, i64); 3] {
    [
        (Tier::M1, floor_to(from, MIN_MS), to),
        (Tier::H1, floor_to(from, HOUR_MS), to),
        (Tier::D1, floor_to(from, DAY_MS), to),
    ]
}

/// Maps the `range` query value to an output bucket width (ms) and a fixed
/// output length. `24h` → 24 hourly buckets; `7d`/`30d` → 7/30 daily buckets.
/// Empty or absent → `24h`. Anything else is a 400.
#[allow(clippy::result_large_err)]
fn resolve_series(range: Option<&str>) -> Result<(i64, usize), Response> {
    match range.filter(|s| !s.is_empty()) {
        None | Some("24h") => Ok((HOUR_MS, 24)),
        Some("7d") => Ok((DAY_MS, 7)),
        Some("30d") => Ok((DAY_MS, 30)),
        Some(_) => Err(bad_range()),
    }
}

fn bad_range() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: "Invalid 'range'. Use one of: 24h, 7d, 30d".to_string(),
        }),
    )
        .into_response()
}

/// Tiers to read for a series at the given output `width`. Only tiers at or
/// finer than the output bucket are read, so every source bucket floors
/// cleanly and completely into one output bucket:
///   - hourly output (`HOUR_MS`): `M1` + `H1`. `D1` is skipped so a whole
///     day's counts can't collapse into a single hour. This is safe because
///     `1h→1d` compaction holds `1h` rows for a full day past the UTC
///     boundary (see `traffic::compaction::compact_1h_to_1d`), so every hour
///     in the rolling 24h window is still present in `H1`.
///   - daily output (`DAY_MS`): `M1` + `H1` + `D1`; day is the coarsest tier,
///     so no over-coarse rows can exist.
fn tier_reads_for(width: i64, from: i64, to: i64) -> Vec<(Tier, i64, i64)> {
    let all = tier_reads(from, to);
    if width == HOUR_MS {
        all[..2].to_vec()
    } else {
        all.to_vec()
    }
}

/// Re-buckets per-bucket stats rows into a fixed-length, zero-filled series of
/// `count` buckets, each `width` ms wide, ending at the bucket containing
/// `now`. Rows outside that window are dropped. Pure — `now` is passed in so
/// the aggregation is deterministic and testable.
///
/// Counters sum; `unique_visitors` and `p95` are true sketch merges *within*
/// each output bucket (an HLL union and a t-digest merge over just that
/// bucket's rows), so a bucket spanning several finer input rows still reports
/// one honest distinct-visitor estimate and quantile. An undecodable sketch
/// contributes its counters but is skipped for that sketch, and logged.
fn aggregate_series(
    rows: Vec<StatsRow>,
    now: i64,
    width: i64,
    count: usize,
) -> Vec<TrafficSeriesBucket> {
    let end = floor_to(now, width);
    let first = end - (count as i64 - 1) * width;
    let mut out: Vec<TrafficSeriesBucket> = (0..count)
        .map(|i| TrafficSeriesBucket {
            bucket: first + i as i64 * width,
            requests: 0,
            bytes_in: 0,
            bytes_out: 0,
            s2xx: 0,
            s3xx: 0,
            s4xx: 0,
            s5xx: 0,
            unique_visitors: 0,
            p95: 0.0,
        })
        .collect();

    // Sketch accumulators, one per output bucket, parallel to `out`. Kept out
    // of the wire struct (which carries only finalized estimates) and folded
    // into it after the scan.
    let mut visitors: Vec<Uniques> = (0..count).map(|_| Uniques::new()).collect();
    let mut digests: Vec<Vec<LatencyDigest>> = (0..count).map(|_| Vec::new()).collect();

    for r in &rows {
        // `b` and `first` are both multiples of `width`, so the division is
        // exact; a row before the window yields a negative index and is skipped.
        let b = floor_to(r.bucket, width);
        let idx = (b - first) / width;
        if idx < 0 || idx as usize >= count {
            continue;
        }
        let idx = idx as usize;
        let slot = &mut out[idx];
        slot.requests = slot.requests.saturating_add(r.requests);
        slot.bytes_in = slot.bytes_in.saturating_add(r.bytes_in);
        slot.bytes_out = slot.bytes_out.saturating_add(r.bytes_out);
        slot.s2xx = slot.s2xx.saturating_add(r.s2xx);
        slot.s3xx = slot.s3xx.saturating_add(r.s3xx);
        slot.s4xx = slot.s4xx.saturating_add(r.s4xx);
        slot.s5xx = slot.s5xx.saturating_add(r.s5xx);

        match Uniques::from_bytes(&r.uniques_hll) {
            Ok(u) => visitors[idx].merge_from(&u),
            Err(e) => tracing::warn!(
                error = %e, app = %r.app, host = %r.host, bucket = r.bucket,
                "skipping undecodable uniques sketch"
            ),
        }
        match LatencyDigest::from_bytes(&r.latency_tdigest) {
            Ok(d) => digests[idx].push(d),
            Err(e) => tracing::warn!(
                error = %e, app = %r.app, host = %r.host, bucket = r.bucket,
                "skipping undecodable latency sketch"
            ),
        }
    }

    for (i, slot) in out.iter_mut().enumerate() {
        slot.unique_visitors = visitors[i].count();
        slot.p95 = LatencyDigest::merge(&digests[i]).quantile(0.95);
    }
    out
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

/// Like [`resolve_limit`] but defaults to [`DEFAULT_APPS_LIMIT`] when absent.
/// Shares the `0`/non-numeric rejection and the [`MAX_LIMIT`] ceiling.
#[allow(clippy::result_large_err)]
fn resolve_apps_limit(raw: Option<&str>) -> Result<usize, Response> {
    let Some(s) = raw.filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_APPS_LIMIT);
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

    let permit = match state.analytics_queries.clone().acquire_owned().await {
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
    let attribution = state
        .geoip_attribution
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Json(TrafficAttribution { attribution }).into_response()
}

/// Server-wide status-class time series: per-bucket 2xx/3xx/4xx/5xx counts
/// across every app/host, zero-filled to a fixed length by `range`.
async fn series(State(state): State<Arc<AppState>>, Query(q): Query<SeriesQuery>) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    run_series(state, q.range, move |tier, lo, hi| {
        analytics.stats_rows_between(tier, lo, hi)
    })
    .await
}

/// Per-app variant of [`series`], filtered to one app via `stats_range`.
async fn app_series(
    Path(app): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<SeriesQuery>,
) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    run_series(state, q.range, move |tier, lo, hi| {
        analytics.stats_range(tier, &app, lo, hi)
    })
    .await
}

/// Shared body for the two series endpoints. Resolves `range`, bounds the DB
/// read to the rolling window, and re-buckets via [`aggregate_series`]. The
/// only per-endpoint difference is `fetch`, which pulls one tier's stats rows
/// either server-wide or filtered to an app.
async fn run_series<F>(state: Arc<AppState>, range: Option<String>, fetch: F) -> Response
where
    F: Fn(Tier, i64, i64) -> Result<Vec<StatsRow>, store::StoreError> + Send + 'static,
{
    let (width, count) = match resolve_series(range.as_deref()) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let now = now_ms();
    let end = floor_to(now, width);
    let from = end - (count as i64 - 1) * width;

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads_for(width, from, now) {
            rows.extend(fetch(tier, lo, hi)?);
        }
        Ok::<_, store::StoreError>(aggregate_series(rows, now, width, count))
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
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

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    // The sketch decode/merge runs inside the blocking task too: it is CPU
    // work over potentially thousands of BLOBs and has no business on the
    // async runtime's worker threads.
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            rows.extend(analytics.stats_range(tier, &app, lo, hi)?);
        }
        Ok::<_, store::StoreError>(summarize_stats(&rows))
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
    let budget = MAX_SCAN_ROWS;

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            let r = analytics.paths_range(tier, &app, lo, hi, budget)?;
            warn_if_truncated("paths", &app, r.len(), budget);
            rows.extend(r);
        }
        Ok::<_, store::StoreError>(top_paths(rows, limit))
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
    let budget = MAX_SCAN_ROWS;

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            let r = analytics.breakdown_range(tier, &app, &dimension, lo, hi, budget)?;
            warn_if_truncated("breakdown", &app, r.len(), budget);
            rows.extend(r);
        }
        Ok::<_, store::StoreError>(top_breakdown(rows, limit))
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Server-wide overview: [`overview`] over every app/host on the box. Uses the
/// un-app-filtered `stats_rows_between` scan (the same one compaction reads),
/// then the identical `summarize_stats` merge — so the percentiles and visitor
/// count are a true sketch merge across all apps, not a sum of per-app estimates.
async fn server_overview(
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

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            rows.extend(analytics.stats_rows_between(tier, lo, hi)?);
        }
        Ok::<_, store::StoreError>(summarize_stats(&rows))
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Server-wide top paths: [`paths`] across every app. `top_paths` groups by
/// `(app, path)`, so the same path served by different apps (e.g. `/`) stays a
/// separate row per app, each carrying its owning app — a correct top-N over
/// all apps that preserves per-app attribution, not a merge of per-app lists.
async fn server_paths(State(state): State<Arc<AppState>>, Query(q): Query<TopQuery>) -> Response {
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

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            rows.extend(analytics.paths_rows_between(tier, lo, hi)?);
        }
        Ok::<_, store::StoreError>(top_paths(rows, limit))
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Server-wide breakdown: [`breakdown`] for one dimension across every app.
async fn server_breakdown(
    Path(dimension): Path<String>,
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
    let budget = MAX_SCAN_ROWS;

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(from, to) {
            let r = analytics.breakdown_dim_rows_between(tier, &dimension, lo, hi, budget)?;
            warn_if_truncated("server_breakdown", "*", r.len(), budget);
            rows.extend(r);
        }
        Ok::<_, store::StoreError>(top_breakdown(rows, limit))
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
fn summarize_stats(rows: &[StatsRow]) -> TrafficOverview {
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

    for r in rows {
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

/// Groups per-bucket path rows by `(app, path)`, summing counters and merging
/// each group's latency digests, then returns the `limit` busiest paths.
///
/// Keying by `(app, path)` rather than `path` alone keeps per-app attribution
/// on the server-wide endpoint: the same path (e.g. `/`) served by two apps
/// stays two rows, each labelled with its owning app, instead of collapsing
/// into one. The per-app endpoint is unaffected — every row shares one app, so
/// the tuple degenerates to grouping by path.
///
/// Digests are folded *incrementally*, one row at a time, so resident sketch
/// memory is bounded by the number of distinct paths rather than by (path,
/// bucket) pairs — the latter is tens to hundreds of MB at the `1m` tier's
/// full depth. `LatencyDigest::merge` re-compresses on every call, so this
/// costs a little accuracy drift and no memory.
fn top_paths(rows: Vec<PathRow>, limit: usize) -> Vec<TrafficPath> {
    struct Acc {
        requests: i64,
        bytes_out: i64,
        latency: LatencyDigest,
    }

    let mut by_path: HashMap<(String, String), Acc> = HashMap::new();
    for r in rows {
        let acc = by_path
            .entry((r.app.clone(), r.path))
            .or_insert_with(|| Acc {
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
        .map(|((app, path), acc)| TrafficPath {
            path,
            app,
            requests: acc.requests,
            bytes_out: acc.bytes_out,
            p50: acc.latency.quantile(0.5),
            p95: acc.latency.quantile(0.95),
        })
        .collect();
    sort_and_truncate(&mut out, limit, |p| {
        (p.requests, (p.app.clone(), p.path.clone()))
    });
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
    sort_and_truncate(&mut out, limit, |e| (e.requests, e.value.clone()));
    out
}

/// Sorts by request count descending, breaking ties on the key ascending so
/// the response is deterministic (the `HashMap` grouping above is not), then
/// keeps the top `limit`. The tie-break key is generic so paths can break ties
/// on `(app, path)` while breakdowns break on the single `value`.
fn sort_and_truncate<T, K, F>(rows: &mut Vec<T>, limit: usize, key: F)
where
    K: Ord,
    F: Fn(&T) -> (i64, K),
{
    // `Reverse` on the request count sorts it descending while the owned
    // tie-break key stays ascending. `sort_by_cached_key` computes each row's
    // key once, so the per-row key allocation is O(rows), not O(rows log rows).
    rows.sort_by_cached_key(|t| {
        let (reqs, k) = key(t);
        (std::cmp::Reverse(reqs), k)
    });
    rows.truncate(limit);
}

// --- Aggregate dashboard ----------------------------------------------------

/// Selects whether a dashboard query runs server-wide (every app/host) or is
/// filtered to one app, unifying the two store method families behind one
/// interface so [`build_dashboard`] keeps a single code path. Each method is
/// exactly the call the corresponding standalone handler already makes.
enum Target {
    Server,
    App(String),
}

impl Target {
    /// Label for the truncation warning: `*` server-wide, else the app.
    fn label(&self) -> &str {
        match self {
            Target::Server => "*",
            Target::App(app) => app,
        }
    }

    fn stats(
        &self,
        a: &AnalyticsStore,
        tier: Tier,
        lo: i64,
        hi: i64,
    ) -> Result<Vec<StatsRow>, store::StoreError> {
        match self {
            Target::Server => a.stats_rows_between(tier, lo, hi),
            Target::App(app) => a.stats_range(tier, app, lo, hi),
        }
    }

    fn paths(
        &self,
        a: &AnalyticsStore,
        tier: Tier,
        lo: i64,
        hi: i64,
        budget: usize,
    ) -> Result<Vec<PathRow>, store::StoreError> {
        match self {
            Target::Server => a.paths_rows_between(tier, lo, hi),
            Target::App(app) => a.paths_range(tier, app, lo, hi, budget),
        }
    }

    fn breakdown(
        &self,
        a: &AnalyticsStore,
        tier: Tier,
        dim: &str,
        lo: i64,
        hi: i64,
        budget: usize,
    ) -> Result<Vec<BreakdownRow>, store::StoreError> {
        match self {
            Target::Server => a.breakdown_dim_rows_between(tier, dim, lo, hi, budget),
            Target::App(app) => a.breakdown_range(tier, app, dim, lo, hi, budget),
        }
    }
}

/// The already-resolved windowing for one dashboard query. `from`/`to` bound
/// the overview/paths/breakdowns; `series_width`/`series_count` come from
/// `range` and drive only the series (whose window is derived from `now`).
struct DashboardParams {
    from: i64,
    to: i64,
    now: i64,
    paths_limit: usize,
    breakdown_limit: usize,
    series_width: i64,
    series_count: usize,
    apps_limit: usize,
}

/// Assembles the whole dashboard in one blocking pass, reusing the exact
/// merge helpers the standalone endpoints use — nothing is re-summed. Returns
/// `attribution: None`; the handler fills it in from `AppState` afterwards.
fn build_dashboard(
    analytics: &AnalyticsStore,
    target: &Target,
    p: &DashboardParams,
    include_apps: bool,
) -> Result<TrafficDashboard, store::StoreError> {
    // Overview — same tier union + sketch merge as `overview`/`server_overview`.
    // On the server-wide target these rows span every app, so the leaderboard
    // below reuses them (grouped by app) instead of re-querying per app.
    let mut stats_rows = Vec::new();
    for (tier, lo, hi) in tier_reads(p.from, p.to) {
        stats_rows.extend(target.stats(analytics, tier, lo, hi)?);
    }
    let overview = summarize_stats(&stats_rows);

    // Paths.
    let mut path_rows = Vec::new();
    for (tier, lo, hi) in tier_reads(p.from, p.to) {
        let r = target.paths(analytics, tier, lo, hi, MAX_SCAN_ROWS)?;
        warn_if_truncated("dashboard_paths", target.label(), r.len(), MAX_SCAN_ROWS);
        path_rows.extend(r);
    }
    let paths = top_paths(path_rows, p.paths_limit);

    // Breakdowns — one ranked list per dimension. The dimension set is the
    // struct's own fields, so it stays in lockstep with Coolify's list.
    let dim = |name: &str| -> Result<Vec<TrafficBreakdownEntry>, store::StoreError> {
        let mut rows = Vec::new();
        for (tier, lo, hi) in tier_reads(p.from, p.to) {
            let r = target.breakdown(analytics, tier, name, lo, hi, MAX_SCAN_ROWS)?;
            warn_if_truncated(
                "dashboard_breakdown",
                target.label(),
                r.len(),
                MAX_SCAN_ROWS,
            );
            rows.extend(r);
        }
        Ok(top_breakdown(rows, p.breakdown_limit))
    };
    let breakdowns = TrafficBreakdowns {
        country: dim("country")?,
        referer: dim("referer")?,
        browser: dim("browser")?,
        os: dim("os")?,
        device: dim("device")?,
        protocol: dim("protocol")?,
        cache: dim("cache")?,
        status: dim("status")?,
        agent: dim("agent")?,
        ip: dim("ip")?,
        useragent: dim("useragent")?,
    };

    // Series — its window derives from `now`, independent of `from`/`to`.
    let series_end = floor_to(p.now, p.series_width);
    let series_from = series_end - (p.series_count as i64 - 1) * p.series_width;
    let mut series_rows = Vec::new();
    for (tier, lo, hi) in tier_reads_for(p.series_width, series_from, p.now) {
        series_rows.extend(target.stats(analytics, tier, lo, hi)?);
    }
    let series = aggregate_series(series_rows, p.now, p.series_width, p.series_count);

    // `include_apps` is only ever set for the server-wide target, whose
    // `stats_rows` already covers every app — so grouping them by app costs no
    // extra query, however many apps exist.
    let apps = if include_apps {
        Some(app_leaderboard(stats_rows, p.apps_limit))
    } else {
        None
    };

    Ok(TrafficDashboard {
        overview,
        paths,
        breakdowns,
        series,
        attribution: None,
        apps,
    })
}

/// Builds the leaderboard from the server-wide stats rows already fetched for
/// the overview: groups them by app, merges each group into a per-app overview
/// (a real sketch merge — grouping by `app` reproduces exactly what a per-app
/// `stats_range` scan would have returned), then ranks by requests desc (ties
/// broken by uuid asc for determinism) and caps at `apps_limit`.
///
/// Only apps with traffic in the range appear — an idle app is simply absent
/// from a request-ranked leaderboard rather than a zeroed tail entry.
fn app_leaderboard(rows: Vec<StatsRow>, apps_limit: usize) -> Vec<TrafficAppEntry> {
    let mut by_app: HashMap<String, Vec<StatsRow>> = HashMap::new();
    for r in rows {
        by_app.entry(r.app.clone()).or_default().push(r);
    }
    let mut entries: Vec<TrafficAppEntry> = by_app
        .into_iter()
        .map(|(uuid, rows)| TrafficAppEntry {
            uuid,
            overview: summarize_stats(&rows),
        })
        .collect();
    entries.sort_by(|a, b| {
        b.overview
            .requests
            .cmp(&a.overview.requests)
            .then_with(|| a.uuid.cmp(&b.uuid))
    });
    entries.truncate(apps_limit);
    entries
}

/// Server-wide dashboard: every member merged across all apps, plus the app
/// leaderboard.
async fn server_dashboard(
    State(state): State<Arc<AppState>>,
    Query(q): Query<DashboardQuery>,
) -> Response {
    run_dashboard(state, Target::Server, true, q).await
}

/// Per-app dashboard: same members filtered to one app, `apps` omitted.
async fn app_dashboard(
    Path(app): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<DashboardQuery>,
) -> Response {
    run_dashboard(state, Target::App(app), false, q).await
}

/// Shared body for both dashboard handlers: resolve every knob (any invalid
/// one is a 400), snapshot the GeoIP attribution, then build the payload in a
/// single blocking task under one query permit. A missing analytics store is
/// the only 404 — an empty range still returns 200 with zeroed/empty members.
async fn run_dashboard(
    state: Arc<AppState>,
    target: Target,
    include_apps: bool,
    q: DashboardQuery,
) -> Response {
    let Some(analytics) = state.analytics.clone() else {
        return analytics_disabled();
    };
    let (from, to) = match resolve_range(
        &HistoryQuery {
            from: q.from,
            to: q.to,
        },
        DEFAULT_FROM,
    ) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let paths_limit = match resolve_limit(q.paths_limit.as_deref()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let breakdown_limit = match resolve_limit(q.breakdown_limit.as_deref()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    // Only meaningful on the server-wide variant, so the per-app endpoint must
    // ignore it entirely — even an invalid value — matching the documented
    // "ignored for this variant" contract.
    let apps_limit = if include_apps {
        match resolve_apps_limit(q.apps_limit.as_deref()) {
            Ok(n) => n,
            Err(resp) => return resp,
        }
    } else {
        DEFAULT_APPS_LIMIT
    };
    let (series_width, series_count) = match resolve_series(q.range.as_deref()) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let attribution = state
        .geoip_attribution
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let params = DashboardParams {
        from,
        to,
        now: now_ms(),
        paths_limit,
        breakdown_limit,
        series_width,
        series_count,
        apps_limit,
    };

    let permit = match state.analytics_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let result = tokio::task::spawn_blocking(move || {
        build_dashboard(&analytics, &target, &params, include_apps)
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(mut dash)) => {
            dash.attribution = attribution;
            Json(dash).into_response()
        }
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

#[cfg(test)]
mod tests;
