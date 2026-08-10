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
use store::traffic::{BreakdownRow, PathRow, StatsRow, Tier};
use traffic::sketches::{LatencyDigest, Uniques};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::types::{
    ErrorBody, TrafficAttribution, TrafficBreakdownEntry, TrafficLatency, TrafficOverview,
    TrafficPath, TrafficStatusBreakdown,
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
        // Server-wide variants: same shapes, merged across every app/host.
        .route("/api/traffic/overview", get(server_overview))
        .route("/api/traffic/paths", get(server_paths))
        .route("/api/traffic/breakdown/{dimension}", get(server_breakdown))
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
        Ok::<_, store::StoreError>(summarize_stats(rows))
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
        Ok::<_, store::StoreError>(summarize_stats(rows))
    })
    .await;
    drop(permit);
    match result {
        Ok(Ok(out)) => Json(out).into_response(),
        Ok(Err(e)) => internal_error(e),
        Err(e) => internal_error(e),
    }
}

/// Server-wide top paths: [`paths`] across every app. `top_paths` groups by path
/// string, so the same path served by different apps (e.g. `/`) merges into one
/// server-wide row — a correct top-N over all apps, not a merge of per-app lists.
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
mod tests;
