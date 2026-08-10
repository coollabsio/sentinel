#![forbid(unsafe_code)]

//! Main traffic analytics service orchestrator: the tail -> parse -> enrich
//! -> aggregate -> flush loop.
//!
//! [`TrafficService::run`] owns two tickers and a shutdown watch:
//! - a **poll** tick (250ms) drains complete [`Tailer`] lines and folds each
//!   through `detect`/`parse_line` -> [`Enricher`] -> [`Aggregator`];
//! - a **flush-check** tick (1s) drains and writes the just-closed window (via
//!   [`Aggregator::take_rollup`] / [`AnalyticsStore::flush_window`]) whenever
//!   the wall clock crosses into a new window;
//! - a **shutdown** change drains once more, flushes the partial window, and
//!   awaits that flush (the last chance to persist inside `main.rs`'s 5s grace).
//!
//! Nothing in the loop panics: every failure (tailer I/O, unparseable or
//! undetectable line, sampled-away event, failed flush) is logged/counted and
//! stepped over. A panic would abort the task, which `main.rs` turns into
//! process termination — traffic analytics must never take the agent down.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use store::traffic::AnalyticsStore;

use crate::TrafficError;
use crate::aggregator::{Aggregator, WindowRollup};
use crate::enrich::{CountryLookup, Enricher};
use crate::parser::{ProxyType, detect, parse_line};
use crate::tailer::Tailer;

/// Production window length: one minute, matching
/// [`Aggregator::bucket_of`] and the `_1m` storage tier.
const DEFAULT_WINDOW_MS: i64 = 60_000;
/// How often new access-log lines are drained from the tailer.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How often the window boundary is re-checked. Finer than the window itself
/// so a closed window is flushed within a second of closing.
const DEFAULT_FLUSH_CHECK_INTERVAL: Duration = Duration::from_secs(1);
/// User-Agent parse cache capacity. Not config-exposed: a few thousand
/// distinct UAs per minute is already atypical, and the entries are tiny.
const UA_CACHE_CAP: usize = 1024;

/// Floors `ts_ms` to its containing `window_ms`-wide bucket. Identical to
/// [`Aggregator::bucket_of`] at [`DEFAULT_WINDOW_MS`]; parameterized only so
/// tests can run a whole window cycle in milliseconds instead of a minute.
fn bucket_of(ts_ms: i64, window_ms: i64) -> i64 {
    if window_ms <= 0 {
        return Aggregator::bucket_of(ts_ms);
    }
    (ts_ms / window_ms) * window_ms
}

/// Wall-clock milliseconds since the UNIX epoch. Saturates to 0 rather than
/// panicking if the system clock is somehow before the epoch.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Resolves the configured `TRAFFIC_PROXY_TYPE` string. An unrecognized value
/// degrades to [`ProxyType::Auto`] (which detects the format from content
/// anyway) rather than failing startup over a cosmetic misconfiguration.
fn parse_proxy_type(s: &str) -> ProxyType {
    if s.eq_ignore_ascii_case("traefik") {
        ProxyType::Traefik
    } else if s.eq_ignore_ascii_case("caddy") {
        ProxyType::Caddy
    } else {
        if !s.eq_ignore_ascii_case("auto") {
            tracing::warn!(
                proxy_type = %s,
                "unrecognized TRAFFIC_PROXY_TYPE, falling back to auto-detection"
            );
        }
        ProxyType::Auto
    }
}

/// The traffic-analytics ingestion service.
pub struct TrafficService {
    store: AnalyticsStore,
    tailer: Tailer,
    enricher: Enricher,
    aggregator: Aggregator,
    /// Starts at whatever config resolved to (possibly [`ProxyType::Auto`]);
    /// once a line is successfully detected it is locked to that format.
    proxy: ProxyType,
    /// Hard cap on recorded events per wall-clock second. `0` disables it.
    sample_threshold: u32,
    /// Window length; `60_000` in production.
    window_ms: i64,
    poll_interval: Duration,
    flush_check_interval: Duration,
    /// The bucket currently being accumulated into.
    current_bucket: i64,
    /// Wall-clock second the sampling counter belongs to.
    sample_sec: i64,
    /// Events recorded so far within `sample_sec`.
    sample_count: u32,
    /// Lines skipped: undetectable format, parse failure, or sampled away.
    dropped: Arc<AtomicU64>,
    /// Events successfully folded into the aggregator.
    processed: Arc<AtomicU64>,
}

impl TrafficService {
    /// Builds the service with the production cadence (1-minute windows, a
    /// 250ms poll, a 1s flush check).
    ///
    /// Fails only if the access log at `cfg.traffic.access_log_path` cannot be
    /// opened; every other kind of failure is handled at runtime instead.
    pub async fn build(
        cfg: &config::Config,
        store: AnalyticsStore,
        geo: Arc<dyn CountryLookup>,
    ) -> Result<Self, TrafficError> {
        Self::build_with_intervals(
            cfg,
            store,
            geo,
            DEFAULT_WINDOW_MS,
            DEFAULT_POLL_INTERVAL,
            DEFAULT_FLUSH_CHECK_INTERVAL,
        )
        .await
    }

    /// [`Self::build`] with the cadence injected, so tests can drive a full
    /// window cycle in milliseconds. Production always goes through
    /// [`Self::build`].
    pub(crate) async fn build_with_intervals(
        cfg: &config::Config,
        store: AnalyticsStore,
        geo: Arc<dyn CountryLookup>,
        window_ms: i64,
        poll_interval: Duration,
        flush_check_interval: Duration,
    ) -> Result<Self, TrafficError> {
        let path = &cfg.traffic.access_log_path;
        let tailer = Tailer::open(path).map_err(|e| {
            tracing::error!(
                error = %e,
                path = %path.display(),
                "failed to open proxy access log"
            );
            TrafficError::Io(e)
        })?;

        let proxy = parse_proxy_type(&cfg.traffic.proxy_type);
        tracing::info!(
            path = %path.display(),
            ?proxy,
            topn = cfg.traffic.topn,
            sample_threshold = cfg.traffic.sample_threshold,
            "traffic service ready"
        );

        Ok(Self {
            store,
            tailer,
            enricher: Enricher::new(geo, UA_CACHE_CAP),
            aggregator: Aggregator::new(cfg.traffic.topn as usize),
            proxy,
            sample_threshold: cfg.traffic.sample_threshold,
            window_ms,
            poll_interval,
            flush_check_interval,
            current_bucket: bucket_of(now_ms(), window_ms),
            sample_sec: 0,
            sample_count: 0,
            dropped: Arc::new(AtomicU64::new(0)),
            processed: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Shared handle on the processed-event counter, taken before `run`
    /// consumes `self`. Lets a test wait for the loop to have folded a known
    /// number of events in rather than sleeping and hoping.
    #[cfg(test)]
    fn processed_counter(&self) -> Arc<AtomicU64> {
        self.processed.clone()
    }

    /// Runs until `shutdown` changes (or its sender is dropped), then flushes
    /// the partial window and returns. Never panics, never propagates an
    /// error: every failure mode is logged and stepped over.
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        self.current_bucket = bucket_of(now_ms(), self.window_ms);

        let mut poll = tokio::time::interval(self.poll_interval);
        let mut flush_check = tokio::time::interval(self.flush_check_interval);
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut logged_dropped = 0u64;

        loop {
            tokio::select! {
                // A `changed()` error means the sender was dropped, which is
                // shutdown just as much as a `true` is; both end the loop the
                // same way.
                _ = shutdown.changed() => {
                    // One last drain first: lines appended between the final
                    // poll tick and the signal would otherwise be lost, and
                    // this is the only remaining chance to pick them up.
                    self.drain_once(&mut lines);
                    let bucket = self.current_bucket;
                    let rollup = self.aggregator.take_rollup(bucket);
                    // Awaited, not spawned-and-forgotten: `run` returning is
                    // what lets main.rs's JoinSet consider this service
                    // stopped, so the write must have completed by then.
                    Self::flush(&self.store, rollup, bucket).await;
                    tracing::info!(
                        processed = self.processed.load(Ordering::Relaxed),
                        dropped = self.dropped.load(Ordering::Relaxed),
                        "traffic service stopped"
                    );
                    return;
                }
                _ = poll.tick() => {
                    self.drain_once(&mut lines);
                }
                _ = flush_check.tick() => {
                    let bucket_now = bucket_of(now_ms(), self.window_ms);
                    if let Some(closed) = self.take_closed_bucket(bucket_now) {
                        let rollup = self.aggregator.take_rollup(closed);
                        Self::flush(&self.store, rollup, closed).await;
                    }

                    let dropped = self.dropped.load(Ordering::Relaxed);
                    if dropped != logged_dropped {
                        tracing::warn!(
                            dropped,
                            processed = self.processed.load(Ordering::Relaxed),
                            "traffic lines skipped (unparseable, undetectable, or sampled away)"
                        );
                        logged_dropped = dropped;
                    }
                }
            }
        }
    }

    /// Reads whatever the tailer has and folds each line in. An I/O error is
    /// logged and swallowed -- the file may be mid-rotation, and the next
    /// poll will pick up where this one left off. Any lines the tailer did
    /// manage to hand back before erroring are still processed.
    fn drain_once(&mut self, lines: &mut Vec<Vec<u8>>) {
        lines.clear();
        if let Err(e) = self.tailer.poll_lines(lines) {
            tracing::warn!(error = %e, "access log poll failed");
        }
        for line in lines.iter() {
            self.process_line(line);
        }
        lines.clear();
    }

    /// If the clock has moved into a different window, adopt it and return the
    /// bucket that was open until now (which the caller must then flush).
    ///
    /// The comparison is `!=`, not `>`: a backward wall-clock step (NTP
    /// correction, snapshot restore, manual `date`) leaves `bucket_now` below
    /// `current_bucket`, and a `>` test would then never fire again — no window
    /// would ever close and the aggregator would grow unbounded. Treating any
    /// change as a close resynchronizes onto the clock's window instead;
    /// forward progress, the common case, is unchanged.
    fn take_closed_bucket(&mut self, bucket_now: i64) -> Option<i64> {
        if bucket_now == self.current_bucket {
            return None;
        }
        Some(std::mem::replace(&mut self.current_bucket, bucket_now))
    }

    /// Detect (once) -> parse -> sample -> enrich -> record for a single line.
    fn process_line(&mut self, line: &[u8]) {
        let proxy = if self.proxy == ProxyType::Auto {
            match detect(line) {
                Some(detected) => {
                    // Lock in only on an actual detection. A malformed first
                    // line must not decide the format for the whole process.
                    tracing::info!(?detected, "detected proxy access-log format");
                    self.proxy = detected;
                    detected
                }
                None => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        } else {
            self.proxy
        };

        let Some(ev) = parse_line(proxy, line) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        if !self.admit_sample() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let enriched = self.enricher.enrich(&ev);
        self.aggregator.record(&ev, &enriched);
        self.processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Graceful-degradation valve: a hard cap of `sample_threshold` recorded
    /// events per wall-clock second (`0` disables it). A plain cap, not
    /// probabilistic sampling, so it bounds per-second work with no RNG.
    fn admit_sample(&mut self) -> bool {
        if self.sample_threshold == 0 {
            return true;
        }
        let sec = now_ms() / 1_000;
        if sec != self.sample_sec {
            self.sample_sec = sec;
            self.sample_count = 0;
        }
        if self.sample_count >= self.sample_threshold {
            return false;
        }
        self.sample_count += 1;
        true
    }

    /// Writes one drained window on a blocking thread. A flush failure (or a
    /// panicking blocking task) is logged and dropped: losing a minute of
    /// analytics is vastly preferable to taking the agent down.
    async fn flush(store: &AnalyticsStore, rollup: WindowRollup, bucket: i64) {
        if rollup.stats.is_empty() && rollup.paths.is_empty() && rollup.breakdown.is_empty() {
            return;
        }
        let counts = (
            rollup.stats.len(),
            rollup.paths.len(),
            rollup.breakdown.len(),
        );
        let store = store.clone();
        let result = tokio::task::spawn_blocking(move || {
            store.flush_window(&rollup.stats, &rollup.paths, &rollup.breakdown)
        })
        .await;
        match result {
            Ok(Ok(())) => tracing::debug!(
                bucket,
                stats = counts.0,
                paths = counts.1,
                breakdown = counts.2,
                "traffic window flushed"
            ),
            Ok(Err(e)) => tracing::warn!(error = %e, bucket, "traffic window flush failed"),
            Err(e) => tracing::warn!(error = %e, bucket, "traffic flush task failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrich::NoGeo;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use store::traffic::{AnalyticsStore, Tier};

    const APP: &str = "jc4wsgs";

    fn traefik_line(path: &str, status: u16, secs: u32) -> String {
        format!(
            r#"{{"ClientAddr":"10.0.0.5:54321","ClientHost":"10.0.0.5","DownstreamContentSize":512,"DownstreamStatus":{status},"Duration":12500000,"RequestContentSize":0,"RequestHost":"app.example.com","RequestMethod":"GET","RequestPath":"{path}","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"https-0-{APP}@docker","StartUTC":"2026-08-09T12:00:{secs:02}.000000000Z","TLSVersion":"1.3","request_Cf-Connecting-Ip":"203.0.113.7","request_Cf-Ipcountry":"US","request_User-Agent":"curl/8.4.0","time":"2026-08-09T12:00:00Z"}}"#
        )
    }

    fn test_config(access_log_path: PathBuf, sample_threshold: u32) -> config::Config {
        config::Config {
            version: "0.0.0-test".into(),
            debug: false,
            refresh_rate_seconds: 5,
            push_enabled: false,
            push_interval_seconds: 60,
            push_path: "/api/v1/sentinel/push".into(),
            push_url: "http://localhost:8000".into(),
            token: "test-token".into(),
            endpoint: "http://localhost:8000".into(),
            metrics_file: PathBuf::from("./db/metrics.sqlite"),
            collector_enabled: false,
            collector_retention_period_days: 7,
            bind_addr: "127.0.0.1:0".parse::<SocketAddr>().expect("bind addr"),
            storage_enabled: false,
            storage_refresh_rate_seconds: 300,
            storage_volumes_enabled: false,
            storage_volumes_refresh_rate_seconds: 900,
            host_mount_prefix: String::new(),
            traffic: config::TrafficSettings {
                enabled: true,
                access_log_path,
                proxy_type: "auto".into(),
                topn: 50,
                sample_threshold,
                retention_1m_hours: 48,
                retention_1h_days: 30,
                retention_1d_days: 395,
                analytics_file: PathBuf::from("./db/analytics.sqlite"),
                geoip_enabled: false,
                geoip_db_url: None,
                geoip_maxmind_key: None,
                geoip_maxmind_edition: "GeoLite2-Country".into(),
                geoip_refresh_days: 30,
            },
        }
    }

    fn append(path: &std::path::Path, data: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open access log for append");
        f.write_all(data.as_bytes()).expect("write access log");
        f.flush().expect("flush access log");
    }

    fn total_requests(store: &AnalyticsStore) -> i64 {
        store
            .stats_range(Tier::M1, APP, 0, i64::MAX)
            .expect("stats_range")
            .iter()
            .map(|r| r.requests)
            .sum()
    }

    /// Polls `stats_range` until the requests total reaches `want` or the
    /// deadline passes, so the assertion never depends on a single fixed
    /// sleep being long enough under CI load.
    async fn wait_for_requests(store: &AnalyticsStore, want: i64, timeout: Duration) -> i64 {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let total = total_requests(store);
            if total >= want || tokio::time::Instant::now() >= deadline {
                return total;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Polls an atomic counter until it reaches `want` or the deadline passes.
    async fn wait_for_counter(
        counter: &std::sync::atomic::AtomicU64,
        want: u64,
        timeout: Duration,
    ) -> u64 {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let seen = counter.load(std::sync::atomic::Ordering::Relaxed);
            if seen >= want || tokio::time::Instant::now() >= deadline {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// The whole pipeline, end to end: a real file on disk -> `Tailer` ->
    /// `parse_line` (via auto-detect) -> `Enricher` -> `Aggregator` ->
    /// `AnalyticsStore::flush_window`, driven by `run`'s own tickers.
    #[tokio::test]
    async fn full_pipeline_flushes_tailed_lines_to_the_store() {
        const N: i64 = 5;

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("access.log");
        std::fs::File::create(&log).expect("create access log");

        let store = AnalyticsStore::open_in_memory().expect("open store");
        let cfg = test_config(log.clone(), 0);

        let svc = TrafficService::build_with_intervals(
            &cfg,
            store.clone(),
            Arc::new(NoGeo),
            100,
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .await
        .expect("build service");

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(svc.run(rx));

        for i in 0..N {
            append(
                &log,
                &format!("{}\n", traefik_line("/api/users", 200, i as u32)),
            );
        }

        let total = wait_for_requests(&store, N, Duration::from_secs(5)).await;
        assert_eq!(
            total, N,
            "every tailed line must reach the store's 1m stats tier"
        );

        tx.send(true).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run() must return promptly after shutdown")
            .expect("run() task must not panic");
    }

    /// Data recorded into a window that has not closed yet must still be
    /// persisted when shutdown arrives -- and `run` must not return until
    /// that final flush has actually completed.
    #[tokio::test]
    async fn shutdown_flushes_the_partial_window_before_returning() {
        const N: i64 = 3;

        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("access.log");
        std::fs::File::create(&log).expect("create access log");

        let store = AnalyticsStore::open_in_memory().expect("open store");
        let cfg = test_config(log.clone(), 0);

        // A 10-minute window: no boundary can be crossed during this test,
        // so the only thing that can persist these rows is the shutdown path.
        let svc = TrafficService::build_with_intervals(
            &cfg,
            store.clone(),
            Arc::new(NoGeo),
            600_000,
            Duration::from_millis(5),
            Duration::from_millis(5),
        )
        .await
        .expect("build service");
        let processed = svc.processed_counter();

        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(svc.run(rx));

        for i in 0..N {
            append(&log, &format!("{}\n", traefik_line("/", 200, i as u32)));
        }

        // Deterministic: wait until the loop has actually folded all N events
        // into the (still open) window, rather than sleeping and hoping.
        let seen = wait_for_counter(&processed, N as u64, Duration::from_secs(5)).await;
        assert_eq!(seen, N as u64, "all lines must be recorded before shutdown");
        assert_eq!(
            total_requests(&store),
            0,
            "the window is still open, nothing should have been flushed yet"
        );

        tx.send(true).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run() must return promptly after shutdown")
            .expect("run() task must not panic");

        assert_eq!(
            total_requests(&store),
            N,
            "the partial window must be flushed (and awaited) before run() returns"
        );
    }

    #[tokio::test]
    async fn auto_detect_locks_in_only_on_a_successful_detection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("access.log");
        std::fs::File::create(&log).expect("create access log");

        let store = AnalyticsStore::open_in_memory().expect("open store");
        let cfg = test_config(log, 0);
        let mut svc = TrafficService::build(&cfg, store, Arc::new(NoGeo))
            .await
            .expect("build service");

        assert_eq!(svc.proxy, ProxyType::Auto, "config said auto");

        svc.process_line(b"this is not json at all");
        assert_eq!(
            svc.proxy,
            ProxyType::Auto,
            "a failed detection must not lock the proxy type in"
        );
        assert_eq!(svc.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);

        let line = traefik_line("/", 200, 0);
        svc.process_line(line.as_bytes());
        assert_eq!(
            svc.proxy,
            ProxyType::Traefik,
            "a successful detection locks the proxy type in"
        );
        assert_eq!(svc.processed.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn sampling_hard_caps_events_per_second() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("access.log");
        std::fs::File::create(&log).expect("create access log");

        let store = AnalyticsStore::open_in_memory().expect("open store");
        let cfg = test_config(log, 2);
        let mut svc = TrafficService::build(&cfg, store, Arc::new(NoGeo))
            .await
            .expect("build service");

        let line = traefik_line("/", 200, 0);
        for _ in 0..5 {
            svc.process_line(line.as_bytes());
        }

        let rollup = svc.aggregator.take_rollup(0);
        let recorded: i64 = rollup.stats.iter().map(|r| r.requests).sum();
        assert_eq!(recorded, 2, "at most sample_threshold events per second");
        assert_eq!(
            svc.dropped.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "sampled-away events count as dropped"
        );
    }

    /// A backward wall-clock step must not wedge the flush gate shut. Under
    /// the previous `bucket_now > current_bucket` test, one NTP correction
    /// pushing the clock back a minute meant no window ever closed again —
    /// nothing was ever written, and the aggregator grew unbounded.
    #[tokio::test]
    async fn a_backward_clock_step_still_closes_the_window() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("access.log");
        std::fs::File::create(&log).expect("create access log");
        let store = AnalyticsStore::open_in_memory().expect("open store");
        let mut svc = TrafficService::build(&test_config(log, 0), store, Arc::new(NoGeo))
            .await
            .expect("build service");

        svc.current_bucket = 600_000;

        // Same window: nothing closes.
        assert_eq!(svc.take_closed_bucket(600_000), None);
        assert_eq!(svc.current_bucket, 600_000);

        // Forward, the ordinary case: the old window closes and is adopted.
        assert_eq!(svc.take_closed_bucket(660_000), Some(600_000));
        assert_eq!(svc.current_bucket, 660_000);

        // Backward: the open window must still close, and the service must
        // resynchronize onto the clock's new window rather than stalling.
        assert_eq!(
            svc.take_closed_bucket(540_000),
            Some(660_000),
            "a backward step must still close the open window"
        );
        assert_eq!(svc.current_bucket, 540_000);

        // …and it keeps working afterwards, rather than being wedged.
        assert_eq!(svc.take_closed_bucket(600_000), Some(540_000));
        assert_eq!(svc.current_bucket, 600_000);
    }

    #[test]
    fn proxy_type_parsing_is_case_insensitive_and_defaults_to_auto() {
        assert_eq!(parse_proxy_type("traefik"), ProxyType::Traefik);
        assert_eq!(parse_proxy_type("TRAEFIK"), ProxyType::Traefik);
        assert_eq!(parse_proxy_type("Caddy"), ProxyType::Caddy);
        assert_eq!(parse_proxy_type("auto"), ProxyType::Auto);
        assert_eq!(
            parse_proxy_type("nginx"),
            ProxyType::Auto,
            "an unrecognized value must degrade to auto, not refuse to start"
        );
    }

    /// The window-length override exists purely so tests don't wait a real
    /// minute; at the production default it must agree exactly with the
    /// aggregator's own minute bucketing.
    #[test]
    fn default_window_bucketing_matches_the_aggregator() {
        for ts in [0, 1, 59_999, 60_000, 90_000, 1_786_000_123_456] {
            assert_eq!(
                bucket_of(ts, DEFAULT_WINDOW_MS),
                crate::aggregator::Aggregator::bucket_of(ts)
            );
        }
    }
}
