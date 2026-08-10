#![forbid(unsafe_code)]

//! Main traffic loop: tail, parse, enrich, aggregate, and flush. Polling and
//! flush run on separate timers; shutdown drains and awaits one final flush.
//! Input and storage failures are logged and skipped so traffic analytics
//! cannot take down the agent.

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
mod tests;
