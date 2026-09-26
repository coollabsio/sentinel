#![forbid(unsafe_code)]

//! Main traffic loop: tail, parse, enrich, aggregate, and flush. Polling and
//! flush run on separate timers; shutdown drains and awaits one final flush.
//! Input and storage failures are logged and skipped so traffic analytics
//! cannot take down the agent. If the access log cannot be opened at startup,
//! the service retries the open with a bounded backoff until it succeeds or
//! shutdown arrives.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use store::traffic::AnalyticsStore;

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
/// First delay before the access log open is tried again, when the open at
/// startup failed. The same order as [`DEFAULT_FLUSH_CHECK_INTERVAL`]: a log
/// that shows up a moment late loses about a second of traffic.
const OPEN_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// Cap for the doubling open-retry delay. A log that is missing for a long
/// time costs one `open(2)` every 30s, and its first lines are still read
/// (see [`TrafficService::wait_for_access_log`]).
const OPEN_RETRY_MAX: Duration = Duration::from_secs(30);
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

/// Doubles `current`, capped at `max`: 1s, 2s, 4s, 8s, 16s, 30s, 30s, ...
fn next_open_retry_delay(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
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
    access_log_path: PathBuf,
    /// `None` until the access log opens. Only `None` if the open in
    /// [`Self::build`] failed; [`Self::run`] then retries it before it tails.
    tailer: Option<Tailer>,
    /// Error kind of the last failed open, `None` once the log is open.
    last_open_error: Option<ErrorKind>,
    open_retry_initial: Duration,
    open_retry_max: Duration,
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
    /// Never fails. If the access log at `cfg.traffic.access_log_path` cannot
    /// be opened now, a warning is logged and [`Self::run`] retries the open
    /// with a backoff. Every other kind of failure is handled at runtime too.
    pub async fn build(
        cfg: &config::Config,
        store: AnalyticsStore,
        geo: Arc<dyn CountryLookup>,
    ) -> Self {
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
    ) -> Self {
        let path = &cfg.traffic.access_log_path;
        let (tailer, last_open_error) = match Tailer::open(path) {
            Ok(tailer) => (Some(tailer), None),
            Err(e) => {
                // Logged once here. The retry loop logs again at warn level
                // only if the error kind changes.
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    retry_secs = OPEN_RETRY_INITIAL.as_secs(),
                    "proxy access log cannot be opened; traffic ingest waits and retries \
                     (check that the proxy log directory is mounted and JSON access logging is on)"
                );
                (None, Some(e.kind()))
            }
        };

        let proxy = parse_proxy_type(&cfg.traffic.proxy_type);
        tracing::info!(
            path = %path.display(),
            ?proxy,
            topn = cfg.traffic.topn,
            sample_threshold = cfg.traffic.sample_threshold,
            waiting_for_access_log = tailer.is_none(),
            "traffic service ready"
        );

        Self {
            store,
            access_log_path: path.clone(),
            tailer,
            last_open_error,
            open_retry_initial: OPEN_RETRY_INITIAL,
            open_retry_max: OPEN_RETRY_MAX,
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
        }
    }

    /// Replaces the open-retry backoff, so tests do not wait whole seconds.
    #[cfg(test)]
    fn with_open_retry(mut self, initial: Duration, max: Duration) -> Self {
        self.open_retry_initial = initial;
        self.open_retry_max = max;
        self
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
        if self.tailer.is_none() && !self.wait_for_access_log(&mut shutdown).await {
            // Nothing was tailed, so there is no window to flush.
            tracing::info!("traffic service stopped before the access log opened");
            return;
        }

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

    /// Tries to open the access log again with a doubling backoff
    /// (`open_retry_initial` up to `open_retry_max`) until it opens, and
    /// stores the tailer. Returns `false` if `shutdown` changes (or its
    /// sender is dropped) first; the wait between attempts ends at once then.
    ///
    /// Every error kind is retried, not only `NotFound`: a permission or
    /// mount problem can be fixed on the host while Sentinel runs, and a
    /// stopped ingest task cannot recover without a restart. The real error
    /// is logged at warn level each time its kind changes, and at debug
    /// level on the other attempts, so a long wait does not spam the log.
    ///
    /// If the last failed attempt was `NotFound`, the file did not exist at
    /// most `open_retry_max` ago. All its content is then new, so it is read
    /// from offset 0 and the first lines the proxy wrote are not lost. After
    /// any other error the file may hold old history, so the open seeks to
    /// EOF, the same as an open at startup.
    async fn wait_for_access_log(
        &mut self,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> bool {
        let started = tokio::time::Instant::now();
        let mut delay = self.open_retry_initial;
        // The first attempt was in `build`.
        let mut attempts = 1u32;

        loop {
            tokio::select! {
                _ = shutdown.changed() => return false,
                _ = tokio::time::sleep(delay) => {}
            }

            attempts = attempts.saturating_add(1);
            let from_start = self.last_open_error == Some(ErrorKind::NotFound);
            match open_access_log(&self.access_log_path, from_start) {
                Ok(tailer) => {
                    tracing::info!(
                        path = %self.access_log_path.display(),
                        attempts,
                        waited_secs = started.elapsed().as_secs(),
                        from_start,
                        "proxy access log opened; traffic ingest started"
                    );
                    self.tailer = Some(tailer);
                    self.last_open_error = None;
                    return true;
                }
                Err(e) => {
                    delay = next_open_retry_delay(delay, self.open_retry_max);
                    if self.last_open_error != Some(e.kind()) {
                        tracing::warn!(
                            error = %e,
                            path = %self.access_log_path.display(),
                            attempts,
                            next_retry_secs = delay.as_secs(),
                            "proxy access log still cannot be opened; retrying"
                        );
                    } else {
                        tracing::debug!(
                            error = %e,
                            attempts,
                            next_retry_secs = delay.as_secs(),
                            "proxy access log still cannot be opened"
                        );
                    }
                    self.last_open_error = Some(e.kind());
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
        if let Some(tailer) = self.tailer.as_mut()
            && let Err(e) = tailer.poll_lines(lines)
        {
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

/// Opens the access log at offset 0 (`from_start`) or at EOF.
fn open_access_log(path: &Path, from_start: bool) -> std::io::Result<Tailer> {
    if from_start {
        Tailer::open_from_start(path)
    } else {
        Tailer::open(path)
    }
}

#[cfg(test)]
mod tests;
