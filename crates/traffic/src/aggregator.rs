#![forbid(unsafe_code)]

//! Time-bucketed aggregation of traffic events (1m, 1h, 1d).
//!
//! [`Aggregator`] folds [`RequestEvent`]/[`Enriched`] pairs into an
//! in-memory 1-minute window: exact per-`(app, host)` counters plus
//! mergeable sketches (t-digest latency, HyperLogLog++ uniques), a
//! per-app top-N of paths (each with its own per-path latency digest),
//! and a per-`(app, dimension)` top-N breakdown across twelve
//! cardinality-bound dimensions. [`Aggregator::take_rollup`] drains the
//! window into [`store::traffic`] row types, capping every top-N into an
//! `__other__` bucket, and resets internal state for the next minute.

use std::collections::HashMap;

use foldhash::fast::RandomState;
use store::traffic::{BreakdownRow, PathRow, StatsRow};

use crate::enrich::Enriched;
use crate::event::{RequestEvent, StatusClass, status_class};
use crate::sketches::{LatencyDigest, TopN, Uniques};

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
    /// Per-`(app, dimension)` top-N of dimension values (by request count).
    breakdown: HashMap<(String, String), TopN, RandomState>,
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

        // Per-app path top-N + per-(app,path) latency.
        self.paths
            .entry(app.clone())
            .or_default()
            .add(ev.path, 1, ev.bytes_out);
        self.path_latency
            .entry((app.clone(), ev.path.to_string()))
            .or_default()
            .add(&[ev.duration_ms]);

        // Breakdown dimensions.
        let status_str = ev.status.to_string();
        record_breakdown(
            &mut self.breakdown,
            &app,
            "status",
            &status_str,
            ev.bytes_out,
        );
        record_breakdown(&mut self.breakdown, &app, "method", ev.method, ev.bytes_out);
        if let Some(country) = &en.country {
            add_breakdown(&mut self.breakdown, &app, "country", country, ev.bytes_out);
        }
        if let Some(referer) = ev.referer {
            add_breakdown(&mut self.breakdown, &app, "referer", referer, ev.bytes_out);
        }
        add_breakdown(
            &mut self.breakdown,
            &app,
            "browser",
            &en.ua.browser,
            ev.bytes_out,
        );
        add_breakdown(&mut self.breakdown, &app, "os", &en.ua.os, ev.bytes_out);
        add_breakdown(
            &mut self.breakdown,
            &app,
            "device",
            &en.ua.device,
            ev.bytes_out,
        );
        record_breakdown(
            &mut self.breakdown,
            &app,
            "protocol",
            ev.protocol,
            ev.bytes_out,
        );
        record_breakdown(&mut self.breakdown, &app, "scheme", ev.scheme, ev.bytes_out);
        if let Some(tls) = &ev.tls_version {
            add_breakdown(&mut self.breakdown, &app, "tls", tls, ev.bytes_out);
        }
        if let Some(cache) = &en.cache {
            add_breakdown(&mut self.breakdown, &app, "cache", cache, ev.bytes_out);
        }
        record_breakdown(
            &mut self.breakdown,
            &app,
            "bot",
            if en.bot { "true" } else { "false" },
            ev.bytes_out,
        );
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
        for ((app, dim), mut topn) in self.breakdown.drain() {
            topn.cap(self.topn);
            for (value, (reqs, bytes)) in topn.counts.into_iter() {
                breakdown.push(BreakdownRow {
                    bucket,
                    app: app.clone(),
                    dimension: dim.clone(),
                    value,
                    requests: reqs as i64,
                    bytes_out: bytes as i64,
                });
            }
            if topn.other.0 > 0 {
                breakdown.push(BreakdownRow {
                    bucket,
                    app: app.clone(),
                    dimension: dim.clone(),
                    value: "__other__".to_string(),
                    requests: topn.other.0 as i64,
                    bytes_out: topn.other.1 as i64,
                });
            }
        }

        WindowRollup {
            stats,
            paths,
            breakdown,
        }
    }
}

/// Adds one `(app, dimension)` top-N entry, skipping empty values (a
/// woothee UA-parse fallback, or an event field that was simply absent)
/// rather than inventing a placeholder. Used by the seven dimensions that
/// are legitimately optional: `country`, `referer`, `browser`, `os`,
/// `device`, `tls`, `cache`.
fn add_breakdown(
    map: &mut HashMap<(String, String), TopN, RandomState>,
    app: &str,
    dim: &str,
    value: &str,
    bytes_out: u64,
) {
    if value.is_empty() {
        return;
    }
    record_breakdown(map, app, dim, value, bytes_out);
}

/// Adds one `(app, dimension)` top-N entry unconditionally, even if
/// `value` happens to be empty. Used by the five dimensions documented as
/// "always recorded": `status`, `method`, `protocol`, `scheme`, `bot`.
/// These are drawn from required `RequestEvent` fields (or computed, like
/// `bot`), so they must never be silently dropped the way an optional
/// enrichment field would be.
fn record_breakdown(
    map: &mut HashMap<(String, String), TopN, RandomState>,
    app: &str,
    dim: &str,
    value: &str,
    bytes_out: u64,
) {
    map.entry((app.to_string(), dim.to_string()))
        .or_default()
        .add(value, 1, bytes_out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::UaInfo;
    use std::net::IpAddr;

    fn base_event() -> RequestEvent<'static> {
        RequestEvent {
            ts_ms: 0,
            app: "app-1".into(),
            host: "example.com".into(),
            method: "GET",
            path: "/",
            status: 200,
            bytes_in: 0,
            bytes_out: 100,
            duration_ms: 10.0,
            protocol: "HTTP/1.1",
            scheme: "https",
            tls_version: None,
            client_ip: None,
            xff: None,
            user_agent: None,
            referer: None,
            cf_connecting_ip: None,
            cf_country: None,
            cf_cache_status: None,
            cf_verified_bot: None,
        }
    }

    fn base_enriched() -> Enriched {
        Enriched {
            country: None,
            ua: UaInfo::default(),
            client_ip: None,
            cache: None,
            bot: false,
        }
    }

    #[test]
    fn folds_requests_and_status() {
        let mut a = Aggregator::new(50);
        let en = base_enriched();

        let mut ev1 = base_event();
        ev1.status = 200;
        let mut ev2 = base_event();
        ev2.status = 200;
        let mut ev3 = base_event();
        ev3.status = 404;

        a.record(&ev1, &en);
        a.record(&ev2, &en);
        a.record(&ev3, &en);

        let rollup = a.take_rollup(60_000);
        assert_eq!(rollup.stats.len(), 1);
        let row = &rollup.stats[0];
        assert_eq!(row.requests, 3);
        assert_eq!(row.s2xx, 2);
        assert_eq!(row.s4xx, 1);
        assert_eq!(row.app, "app-1");
        assert_eq!(row.host, "example.com");
    }

    #[test]
    fn bucket_floors_to_minute() {
        assert_eq!(Aggregator::bucket_of(90_000), 60_000);
    }

    #[test]
    fn breakdown_caps_topn_into_other() {
        let mut a = Aggregator::new(2);

        for _ in 0..3 {
            let mut ev = base_event();
            ev.status = 200;
            let mut en = base_enriched();
            en.country = Some("AA".to_string());
            a.record(&ev, &en);
        }
        for _ in 0..2 {
            let ev = base_event();
            let mut en = base_enriched();
            en.country = Some("BB".to_string());
            a.record(&ev, &en);
        }
        {
            let ev = base_event();
            let mut en = base_enriched();
            en.country = Some("CC".to_string());
            a.record(&ev, &en);
        }

        let rollup = a.take_rollup(60_000);
        let country_rows: Vec<_> = rollup
            .breakdown
            .iter()
            .filter(|r| r.dimension == "country")
            .collect();

        assert_eq!(country_rows.len(), 3, "2 kept + 1 __other__ row");

        let other = country_rows
            .iter()
            .find(|r| r.value == "__other__")
            .expect("expected an __other__ row");
        assert_eq!(other.requests, 1, "the single CC request folded into other");

        let aa = country_rows.iter().find(|r| r.value == "AA").unwrap();
        assert_eq!(aa.requests, 3);
        let bb = country_rows.iter().find(|r| r.value == "BB").unwrap();
        assert_eq!(bb.requests, 2);
    }

    #[test]
    fn paths_get_per_path_latency() {
        let mut a = Aggregator::new(50);
        let en = base_enriched();

        let mut fast = base_event();
        fast.path = "/fast";
        fast.duration_ms = 5.0;

        let mut slow = base_event();
        slow.path = "/slow";
        slow.duration_ms = 500.0;

        for _ in 0..5 {
            a.record(&fast, &en);
        }
        for _ in 0..5 {
            a.record(&slow, &en);
        }

        let rollup = a.take_rollup(60_000);
        assert_eq!(rollup.paths.len(), 2);

        let fast_row = rollup.paths.iter().find(|p| p.path == "/fast").unwrap();
        let slow_row = rollup.paths.iter().find(|p| p.path == "/slow").unwrap();

        let fast_digest = LatencyDigest::from_bytes(&fast_row.latency_tdigest).unwrap();
        let slow_digest = LatencyDigest::from_bytes(&slow_row.latency_tdigest).unwrap();

        assert!(
            fast_digest.quantile(0.5) < slow_digest.quantile(0.5),
            "per-path digest must reflect that path's own latencies, not a pooled one"
        );
        assert_eq!(fast_row.requests, 5);
        assert_eq!(slow_row.requests, 5);
    }

    #[test]
    fn uniques_skip_when_client_ip_absent() {
        let mut a = Aggregator::new(50);
        let ev = base_event();
        let mut en = base_enriched();
        en.client_ip = None;
        a.record(&ev, &en);

        let mut en2 = base_enriched();
        en2.client_ip = Some("1.2.3.4".parse::<IpAddr>().unwrap());
        a.record(&ev, &en2);

        let rollup = a.take_rollup(60_000);
        assert_eq!(rollup.stats.len(), 1);
        // 1 of the 2 events had a resolvable client_ip; uniques counts ~1.
        let hll_bytes = &rollup.stats[0].uniques_hll;
        let mut u = Uniques::from_bytes(hll_bytes).unwrap();
        assert_eq!(u.count(), 1);
    }

    #[test]
    fn take_rollup_clears_state_for_next_window() {
        let mut a = Aggregator::new(50);
        let en = base_enriched();
        let ev = base_event();

        a.record(&ev, &en);
        let first = a.take_rollup(60_000);
        assert_eq!(first.stats[0].requests, 1);
        assert_eq!(first.paths.len(), 1);
        assert!(!first.breakdown.is_empty());

        // Nothing recorded in the second window: everything must come
        // back empty, not carry over stale counts from the first window.
        let second = a.take_rollup(120_000);
        assert!(second.stats.is_empty());
        assert!(second.paths.is_empty());
        assert!(second.breakdown.is_empty());

        // A fresh record in the third window must not be polluted by
        // anything left behind from the first.
        a.record(&ev, &en);
        let third = a.take_rollup(180_000);
        assert_eq!(third.stats.len(), 1);
        assert_eq!(third.stats[0].requests, 1);
    }

    #[test]
    fn always_recorded_dimensions_bypass_empty_skip() {
        // method is an "always recorded" dimension (status, method,
        // protocol, scheme, bot): it must be recorded even for an
        // edge-case empty value, unlike the skippable dimensions (e.g.
        // country) which drop empty values silently. A real Traefik/Caddy
        // parse would never produce an empty method, but the contract is
        // "always recorded", not "recorded unless empty".
        let mut a = Aggregator::new(50);
        let en = base_enriched();
        let mut ev = base_event();
        ev.method = "";

        a.record(&ev, &en);

        let rollup = a.take_rollup(60_000);
        let method_row = rollup
            .breakdown
            .iter()
            .find(|r| r.dimension == "method")
            .expect("method dimension must always produce a row, even for an empty value");
        assert_eq!(method_row.value, "");
        assert_eq!(method_row.requests, 1);
    }
}
