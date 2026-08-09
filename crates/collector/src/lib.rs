#![forbid(unsafe_code)]

pub mod host;

pub use host::HostSampler;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use config::Config;
use docker::{DockerClient, calc};
use store::{ContainerSample, Store};
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Bound on concurrent Docker stats requests, matching the Go collector's
/// 10-worker pool. Making it explicit replaces an unbounded goroutine fan-out.
const MAX_CONCURRENT_STATS: usize = 10;

/// Round a percentage to two decimals, matching Go's
/// `math.Round(x*100)/100` / `fmt.Sprintf("%.2f", x)` used when storing metrics.
fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct Collector {
    config: Arc<Config>,
    store: Store,
    docker: DockerClient,
}

impl Collector {
    pub fn new(config: Arc<Config>, store: Store, docker: DockerClient) -> Self {
        Self {
            config,
            store,
            docker,
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            refresh_rate_seconds = self.config.refresh_rate_seconds,
            retention_days = self.config.collector_retention_period_days,
            "starting metrics collector"
        );

        let mut sampler = HostSampler::new();
        // tokio::time::interval's first tick fires immediately, unlike Go's
        // time.NewTicker (which waits a full period before the first tick).
        // interval_at with an explicit first-tick deadline restores that
        // behavior, matching the Go collector's actual startup timing.
        let period = std::time::Duration::from_secs(self.config.refresh_rate_seconds);
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("stopping metrics collector");
                    return;
                }
                _ = ticker.tick() => {
                    // A failed cycle must never kill the loop: every fallible
                    // step inside `cycle` logs and continues, so there is no
                    // error to surface here. This replaces the Go
                    // implementation's panic/recover block.
                    self.cycle(&mut sampler).await;
                }
            }
        }
    }

    async fn cycle(&self, sampler: &mut HostSampler) {
        let time = now_millis();

        // Go stored host CPU with fmt.Sprintf("%.2f", ...) (collector.go), so
        // round to 2 decimals here to keep stored values at wire parity — the
        // same treatment sample_memory already applies to memory. The raw value
        // is only used unrounded by /api/cpu/current, which Go also returned raw.
        // sysinfo refreshes are in-memory and cheap, so sample on the async
        // side; only the SQLite writes go to a blocking thread (matching the
        // API's read handlers) so a WAL fsync stall can't block a worker.
        let cpu = round2(sampler.sample_cpu());
        let mut mem = sampler.sample_memory();
        mem.time = time;

        let store = self.store.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = store.insert_cpu(time, cpu) {
                tracing::warn!(error = %e, "failed to record host cpu");
            }
            if let Err(e) = store.insert_memory(&mem) {
                tracing::warn!(error = %e, "failed to record host memory");
            }
        })
        .await;

        self.collect_containers(time).await;
    }

    async fn collect_containers(&self, time: i64) {
        let containers = match self.docker.list_containers().await {
            Ok(c) => c,
            Err(e) => {
                // Docker being unreachable is expected and must not be fatal.
                tracing::warn!(error = %e, "failed to list containers");
                return;
            }
        };
        if containers.is_empty() {
            return;
        }

        let mut samples = Vec::with_capacity(containers.len());
        let mut tasks = JoinSet::new();
        let mut queue = containers.into_iter();

        // Bounded fan-out: keep at most MAX_CONCURRENT_STATS requests in flight.
        for _ in 0..MAX_CONCURRENT_STATS {
            match queue.next() {
                Some(c) => {
                    tasks.spawn(fetch(self.docker.clone(), c));
                }
                None => break,
            }
        }
        while let Some(joined) = tasks.join_next().await {
            if let Some(c) = queue.next() {
                tasks.spawn(fetch(self.docker.clone(), c));
            }
            match joined {
                Ok(Some(sample)) => samples.push(sample),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "stats task panicked"),
            }
        }

        let store = self.store.clone();
        match tokio::task::spawn_blocking(move || store.insert_container_batch(time, &samples)).await
        {
            Ok(Err(e)) => tracing::warn!(error = %e, "failed to record container metrics"),
            Err(e) => tracing::warn!(error = %e, "container insert task panicked"),
            Ok(Ok(())) => {}
        }
    }
}

async fn fetch(
    docker: DockerClient,
    container: docker::ContainerSummary,
) -> Option<ContainerSample> {
    let name = container.display_name();
    let stats = match docker.stats(&container.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(container = %name, error = %e, "failed to get container stats");
            return None;
        }
    };

    let mem_used = calc::memory_used(&stats);
    let mem_limit = stats.mem_limit;
    // Matches the Go collector: `free` is derived, and `available` is set to the
    // same derived value. Preserved deliberately for wire compatibility.
    let free = mem_limit.saturating_sub(mem_used);
    // Go stored both percentages with fmt.Sprintf("%.2f", ...) (collector.go)
    // and re-parsed them on read, effectively rounding to 2 decimals. Round
    // both here so the stored (and downsampled) values stay at wire parity with
    // the Go agent; without it the raw f64 (e.g. 12.345678901234568) persists
    // to storage even though a type-only check would pass.
    let mem_used_percent = round2(calc::memory_percent(&stats));
    let cpu_percent = round2(calc::cpu_percent(&stats));

    Some(ContainerSample {
        // Store the sanitized key so the `/api/container/{id}/...` read path
        // (which strips everything outside [a-zA-Z0-9]) can find it — a raw
        // display name like `postgres-db` was previously unqueryable.
        container_id: store::sanitize_container_id(&name),
        cpu_percent,
        mem_total: mem_limit,
        mem_available: free,
        mem_used,
        mem_used_percent,
        mem_free: free,
    })
}
