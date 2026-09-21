#![forbid(unsafe_code)]

pub mod host;
pub mod storage;

pub use host::HostSampler;
pub use storage::StorageCollector;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use std::collections::HashMap;

use config::Config;
use docker::{DockerClient, calc};
use store::{ContainerNetworkSample, ContainerSample, ContainerStatusSample, Store};
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
        // Previous cumulative network counters per Docker container id, so each
        // cycle can derive a bytes/sec rate from the delta. Keyed on the id, not
        // the display name: a re-created container reuses the name but starts
        // new counters. Kept in the run
        // loop (not the store) because it is transient rate state, not history.
        let mut net_prev: HashMap<String, (u64, u64, i64)> = HashMap::new();
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
                    self.cycle(&mut sampler, &mut net_prev).await;
                }
            }
        }
    }

    async fn cycle(
        &self,
        sampler: &mut HostSampler,
        net_prev: &mut HashMap<String, (u64, u64, i64)>,
    ) {
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
        // Network rates and load averages are rounded to 2 decimals, like the
        // percentages.
        let net = sampler.sample_network();
        let net_rx = round2(net.rx_bytes_per_sec);
        let net_tx = round2(net.tx_bytes_per_sec);
        let (load1, load5, load15) = sampler.sample_load();
        let (load1, load5, load15) = (round2(load1), round2(load5), round2(load15));
        let host_status = sampler.sample_host_status(time);

        let store = self.store.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            if let Err(e) = store.insert_cpu(time, cpu) {
                tracing::warn!(error = %e, "failed to record host cpu");
            }
            if let Err(e) = store.insert_memory(&mem) {
                tracing::warn!(error = %e, "failed to record host memory");
            }
            if let Err(e) = store.insert_network(time, net_rx, net_tx) {
                tracing::warn!(error = %e, "failed to record host network");
            }
            if let Err(e) = store.insert_load(time, load1, load5, load15) {
                tracing::warn!(error = %e, "failed to record host load average");
            }
            if let Err(e) = store.upsert_host_status(&host_status) {
                tracing::warn!(error = %e, "failed to record host status");
            }
        })
        .await
        {
            tracing::warn!(error = %e, "host metrics insert task panicked");
        }

        self.collect_containers(time, net_prev).await;
    }

    async fn collect_containers(&self, time: i64, net_prev: &mut HashMap<String, (u64, u64, i64)>) {
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

        let mut fetched = Vec::with_capacity(containers.len());
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
                Ok(Some(f)) => fetched.push(f),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "stats task panicked"),
            }
        }

        // Split the fetched data into the three series, deriving each container's
        // network rate from the previous cycle's counter for the same Docker id.
        let live_ids: std::collections::HashSet<String> =
            fetched.iter().map(|f| f.docker_id.clone()).collect();
        let mut samples = Vec::with_capacity(fetched.len());
        let mut net_samples = Vec::with_capacity(fetched.len());
        let mut status_samples = Vec::with_capacity(fetched.len());
        for f in fetched {
            let name = f.sample.container_id.clone();
            let (rx_rate, tx_rate) = net_rate(net_prev.get(&f.docker_id), f.net_rx, f.net_tx, time);
            net_prev.insert(f.docker_id, (f.net_rx, f.net_tx, time));
            net_samples.push(ContainerNetworkSample {
                container_id: name.clone(),
                rx_bytes_per_sec: round2(rx_rate),
                tx_bytes_per_sec: round2(tx_rate),
            });
            // No status row on an inspect failure: the previous row stays rather
            // than being overwritten with made-up values.
            if let Some((health_status, restart_count)) = f.inspect {
                status_samples.push(ContainerStatusSample {
                    container_id: name,
                    state: f.state,
                    health_status,
                    restart_count,
                });
            }
            samples.push(f.sample);
        }
        // Drop prev-counter state for containers that are gone, so the map does
        // not grow without bound across the process lifetime.
        net_prev.retain(|k, _| live_ids.contains(k));

        let store = self.store.clone();
        // Each series is written on its own, so one failed insert does not drop
        // the others.
        if let Err(e) = tokio::task::spawn_blocking(move || {
            if let Err(e) = store.insert_container_batch(time, &samples) {
                tracing::warn!(error = %e, "failed to record container metrics");
            }
            if let Err(e) = store.insert_container_network_batch(time, &net_samples) {
                tracing::warn!(error = %e, "failed to record container network");
            }
            if let Err(e) = store.upsert_container_status_batch(time, &status_samples) {
                tracing::warn!(error = %e, "failed to record container status");
            }
        })
        .await
        {
            tracing::warn!(error = %e, "container insert task panicked");
        }
    }
}

/// Everything one cycle needs from a single container: cpu/mem sample, the raw
/// cumulative network counters (rate derived later), and inspect-derived status.
struct FetchedContainer {
    docker_id: String,
    sample: ContainerSample,
    net_rx: u64,
    net_tx: u64,
    state: String,
    /// `(health_status, restart_count)`; `None` when inspect failed.
    inspect: Option<(String, u64)>,
}

/// Bytes/sec from the counter delta since the previous cycle. Returns 0 on the
/// first sample and on a counter reset (a container restart makes `cur < prev`),
/// so a restart never emits a huge spurious spike.
fn net_rate(prev: Option<&(u64, u64, i64)>, cur_rx: u64, cur_tx: u64, now: i64) -> (f64, f64) {
    match prev {
        Some(&(prx, ptx, pt)) if now > pt && cur_rx >= prx && cur_tx >= ptx => {
            let dt = (now - pt) as f64 / 1000.0;
            ((cur_rx - prx) as f64 / dt, (cur_tx - ptx) as f64 / dt)
        }
        _ => (0.0, 0.0),
    }
}

async fn fetch(
    docker: DockerClient,
    container: docker::ContainerSummary,
) -> Option<FetchedContainer> {
    let name = container.display_name();
    let stats = match docker.stats(&container.id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(container = %name, error = %e, "failed to get container stats");
            return None;
        }
    };

    // One inspect per container per cycle for health + restart count. A failure
    // here must not drop the whole container (its cpu/mem/net are still valid);
    // only its status write is skipped.
    let inspect = match docker.inspect_health_and_restart_count(&container.id).await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(container = %name, error = %e, "failed to inspect container");
            None
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

    Some(FetchedContainer {
        sample: ContainerSample {
            // Preserve the exact display name. Sanitizing punctuation is lossy:
            // distinct names such as `app-a` and `appa` otherwise share history.
            container_id: name,
            cpu_percent,
            mem_total: mem_limit,
            mem_available: free,
            mem_used,
            mem_used_percent,
            mem_free: free,
        },
        docker_id: container.id,
        net_rx: stats.net_rx,
        net_tx: stats.net_tx,
        state: container.state,
        inspect,
    })
}

#[cfg(test)]
mod tests {
    use super::net_rate;

    #[test]
    fn first_sample_is_zero() {
        assert_eq!(net_rate(None, 1_000, 2_000, 5_000), (0.0, 0.0));
    }

    #[test]
    fn rate_is_counter_delta_over_seconds() {
        // +5000 rx and +10000 tx over a 5s gap → 1000 and 2000 bytes/sec.
        let prev = (1_000u64, 2_000u64, 0i64);
        assert_eq!(
            net_rate(Some(&prev), 6_000, 12_000, 5_000),
            (1_000.0, 2_000.0)
        );
    }

    #[test]
    fn counter_reset_clamps_to_zero() {
        // A container restart resets the counter, so cur < prev → 0, not a spike.
        let prev = (10_000u64, 20_000u64, 0i64);
        assert_eq!(net_rate(Some(&prev), 5, 5, 5_000), (0.0, 0.0));
    }

    #[test]
    fn non_advancing_clock_is_zero() {
        let prev = (0u64, 0u64, 5_000i64);
        assert_eq!(net_rate(Some(&prev), 100, 100, 5_000), (0.0, 0.0));
    }
}
