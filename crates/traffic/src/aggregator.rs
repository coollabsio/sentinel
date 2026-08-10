#![forbid(unsafe_code)]

//! Time-bucketed aggregation of traffic events. `Aggregator` folds events into
//! one-minute counters and mergeable sketches, caps top-N groups, then drains
//! the window into `store::traffic` rows.

use std::collections::HashMap;

use foldhash::fast::RandomState;
use store::traffic::{BreakdownRow, PathRow, StatsRow};

use crate::enrich::Enriched;
use crate::event::{RequestEvent, StatusClass, status_class};
use crate::sketches::{LatencyDigest, TopN, Uniques, truncate_key};

/// Per-`(app, host)` exact counters plus mergeable sketches, accumulated
/// over the current minute window.
#[derive(Default)]
struct StatsAcc {
    requests: i64,
    bytes_in: i64,
    bytes_out: i64,
    s2xx: i64,
    s3xx: i64,
    s4xx: i64,
    s5xx: i64,
    digest: LatencyDigest,
    uniques: Uniques,
}

/// Per-app breakdown map: dimension name -> its top-N. The dimension key is a
/// `&'static str` (every dimension is a string literal in [`Aggregator::record`]),
/// so folding an event allocates nothing for the dimension key.
type DimMap = HashMap<&'static str, TopN, RandomState>;

/// One minute-window's worth of aggregated rows, ready for
/// `AnalyticsStore::flush_window`.
pub struct WindowRollup {
    pub stats: Vec<StatsRow>,
    pub paths: Vec<PathRow>,
    pub breakdown: Vec<BreakdownRow>,
}

/// In-memory accumulator for the current 1-minute window.
///
/// Not clock-driven itself: callers (Task 12) decide when a minute has
/// elapsed and call [`Aggregator::take_rollup`] with the bucket timestamp
/// (computed via [`Aggregator::bucket_of`]) to drain it.
pub struct Aggregator {
    topn: usize,
    /// Exact counters + sketches per `(app, host)`.
    per_key: HashMap<(String, String), StatsAcc, RandomState>,
    /// Per-app top-N of paths (by request count).
    paths: HashMap<String, TopN, RandomState>,
    /// Per-`(app, path)` latency digest, independent of whether the path
    /// survives `paths`' top-N cap.
    path_latency: HashMap<(String, String), LatencyDigest, RandomState>,
    /// Per-app, per-dimension top-N of dimension values (by request count).
    /// Nested (app -> dimension -> top-N) so recording an event enters the
    /// per-app map once and then looks up each dimension by a `&'static str`,
    /// rather than allocating a fresh `(app, dimension)` key per dimension.
    breakdown: HashMap<String, DimMap, RandomState>,
}

impl Aggregator {
    /// Creates an empty aggregator that caps every top-N (paths, and each
    /// breakdown dimension) at `topn` entries in [`Self::take_rollup`].
    pub fn new(topn: usize) -> Self {
        Self {
            topn,
            per_key: HashMap::default(),
            paths: HashMap::default(),
            path_latency: HashMap::default(),
            breakdown: HashMap::default(),
        }
    }

    /// Floors a millisecond timestamp to its containing minute boundary.
    pub fn bucket_of(ts_ms: i64) -> i64 {
        (ts_ms / 60_000) * 60_000
    }

    /// Folds one already-enriched event into the current window.
    ///
    /// Every optional enrichment/event field (country, referer, tls,
    /// cache, browser/os/device, client_ip) is skipped cleanly when
    /// absent/empty rather than guessed at, matching the project's
    /// "skip incomplete data" convention.
    pub fn record(&mut self, ev: &RequestEvent, en: &Enriched) {
        let app = ev.app.to_string();
        let host = ev.host.to_string();

        let acc = self.per_key.entry((app.clone(), host)).or_default();
        acc.requests += 1;
        acc.bytes_in += ev.bytes_in as i64;
        acc.bytes_out += ev.bytes_out as i64;
        match status_class(ev.status) {
            StatusClass::S2xx => acc.s2xx += 1,
            StatusClass::S3xx => acc.s3xx += 1,
            StatusClass::S4xx => acc.s4xx += 1,
            StatusClass::S5xx => acc.s5xx += 1,
            StatusClass::Other => {}
        }
        acc.digest.add(&[ev.duration_ms]);
        if let Some(ip) = en.client_ip {
            acc.uniques.add_ip(ip);
        }

        // Per-app path top-N + per-(app,path) latency. The path is truncated
        // up front, with the *same* helper `TopN::add` uses, so the key stored
        // here matches the one `take_rollup` looks the digest back up by.
        let path = truncate_key(&ev.path);
        let paths = self.paths.entry(app.clone()).or_default();
        paths.add_bounded(path, 1, ev.bytes_out, self.topn);

        // Only keep a latency digest for a path still in the top-N candidate
        // set: one already folded into `__other__` has its digest discarded at
        // drain time regardless, and skipping it keeps `path_latency` bounded
        // by the same soft cap rather than growing without limit alongside it.
        if paths.counts.contains_key(path) {
            self.path_latency
                .entry((app.clone(), path.to_string()))
                .or_default()
                .add(&[ev.duration_ms]);
        }

        // Breakdown dimensions. `skip_empty=false` for the always-recorded
        // dimensions (required fields), `true` for the optional ones. Enter the
        // per-app map once (consuming `app`, its last use here) so each
        // dimension below is a plain `&'static str` lookup with no allocation.
        let bytes = ev.bytes_out;
        let topn = self.topn;
        let dims = self.breakdown.entry(app).or_default();
        let status_str = ev.status.to_string();
        record_breakdown(dims, "status", &status_str, bytes, topn, false);
        record_breakdown(dims, "method", &ev.method, bytes, topn, false);
        if let Some(country) = &en.country {
            record_breakdown(dims, "country", country, bytes, topn, true);
        }
        if let Some(referer) = ev.referer.as_deref() {
            record_breakdown(dims, "referer", referer, bytes, topn, true);
        }
        record_breakdown(dims, "browser", &en.ua.browser, bytes, topn, true);
        record_breakdown(dims, "os", &en.ua.os, bytes, topn, true);
        record_breakdown(dims, "device", &en.ua.device, bytes, topn, true);
        record_breakdown(dims, "protocol", &ev.protocol, bytes, topn, false);
        record_breakdown(dims, "scheme", &ev.scheme, bytes, topn, false);
        if let Some(tls) = &ev.tls_version {
            record_breakdown(dims, "tls", tls, bytes, topn, true);
        }
        if let Some(cache) = &en.cache {
            record_breakdown(dims, "cache", cache, bytes, topn, true);
        }
        let bot = if en.bot { "true" } else { "false" };
        record_breakdown(dims, "bot", bot, bytes, topn, false);
    }

    /// Drains the current window into row types for `bucket`, capping
    /// every top-N (paths, each breakdown dimension) at `self.topn` with
    /// overflow folded into a `value = "__other__"` row. Clears all
    /// internal state so the aggregator is ready for the next minute.
    pub fn take_rollup(&mut self, bucket: i64) -> WindowRollup {
        let mut stats = Vec::with_capacity(self.per_key.len());
        for ((app, host), acc) in self.per_key.drain() {
            stats.push(StatsRow {
                bucket,
                app,
                host,
                requests: acc.requests,
                bytes_in: acc.bytes_in,
                bytes_out: acc.bytes_out,
                s2xx: acc.s2xx,
                s3xx: acc.s3xx,
                s4xx: acc.s4xx,
                s5xx: acc.s5xx,
                latency_tdigest: acc.digest.to_bytes(),
                uniques_hll: acc.uniques.to_bytes(),
            });
        }

        let mut paths = Vec::new();
        for (app, mut topn) in self.paths.drain() {
            topn.cap(self.topn);
            for (path, (reqs, bytes)) in topn.counts.into_iter() {
                let digest = self
                    .path_latency
                    .remove(&(app.clone(), path.clone()))
                    .unwrap_or_default();
                paths.push(PathRow {
                    bucket,
                    app: app.clone(),
                    path,
                    requests: reqs as i64,
                    bytes_out: bytes as i64,
                    latency_tdigest: digest.to_bytes(),
                });
            }
            if topn.other.0 > 0 {
                paths.push(PathRow {
                    bucket,
                    app: app.clone(),
                    path: "__other__".to_string(),
                    requests: topn.other.0 as i64,
                    bytes_out: topn.other.1 as i64,
                    latency_tdigest: LatencyDigest::new().to_bytes(),
                });
            }
        }
        // Any per-path digests for paths folded into __other__ (or for
        // apps with no surviving top-N entries at all) are never removed
        // above; drop them here so the window fully resets.
        self.path_latency.clear();

        let mut breakdown = Vec::new();
        for (app, dims) in self.breakdown.drain() {
            for (dim, mut topn) in dims {
                topn.cap(self.topn);
                for (value, (reqs, bytes)) in topn.counts.into_iter() {
                    breakdown.push(BreakdownRow {
                        bucket,
                        app: app.clone(),
                        dimension: dim.to_string(),
                        value,
                        requests: reqs as i64,
                        bytes_out: bytes as i64,
                    });
                }
                if topn.other.0 > 0 {
                    breakdown.push(BreakdownRow {
                        bucket,
                        app: app.clone(),
                        dimension: dim.to_string(),
                        value: "__other__".to_string(),
                        requests: topn.other.0 as i64,
                        bytes_out: topn.other.1 as i64,
                    });
                }
            }
        }

        WindowRollup {
            stats,
            paths,
            breakdown,
        }
    }
}

/// Adds one value to a dimension's top-N within an app's [`DimMap`]. With
/// `skip_empty`, an empty
/// `value` (a woothee UA-parse fallback, or an absent event field) is dropped
/// rather than recorded — used by the seven optional dimensions (`country`,
/// `referer`, `browser`, `os`, `device`, `tls`, `cache`). The five
/// always-recorded dimensions (`status`, `method`, `protocol`, `scheme`,
/// `bot`), drawn from required fields, pass `skip_empty=false` so an empty
/// value is never silently dropped.
fn record_breakdown(
    dims: &mut DimMap,
    dim: &'static str,
    value: &str,
    bytes_out: u64,
    topn: usize,
    skip_empty: bool,
) {
    if skip_empty && value.is_empty() {
        return;
    }
    dims.entry(dim)
        .or_default()
        .add_bounded(value, 1, bytes_out, topn);
}

#[cfg(test)]
mod tests;
