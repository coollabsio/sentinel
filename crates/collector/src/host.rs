use std::time::Instant;

use store::{HostStatusRow, MemRow};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, Networks, RefreshKind, System};

/// Host network throughput sample, as a rate in bytes/sec (see [`NetworkRow`]).
///
/// [`NetworkRow`]: store::NetworkRow
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NetworkSample {
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Owns a long-lived `System`. sysinfo derives CPU usage from the delta between
/// two refreshes, so a brand-new instance's first `sample_cpu` is typically
/// ~0.0 — matching Go's gopsutil `cpu.Percent(0, false)` first-call behavior.
///
/// Deliberately does **not** sleep `MINIMUM_CPU_UPDATE_INTERVAL` (200 ms on
/// Linux) in the constructor: that warm-up used to run on the critical path
/// before the HTTP listener bound, adding ~200 ms to cold start. Callers that
/// need a non-zero first reading should call `sample_cpu` twice with their
/// own delay; the collector's 5 s tick already provides that naturally.
pub struct HostSampler {
    system: System,
    /// Per-interface network counters; sysinfo tracks the delta since the last
    /// `refresh`, which is exactly what a rate needs.
    networks: Networks,
    /// Wall clock of the last network refresh, for the rate denominator.
    last_net_refresh: Instant,
}

impl Default for HostSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl HostSampler {
    pub fn new() -> Self {
        let mut system = System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                // RAM + swap: swap feeds the current-only host status.
                .with_memory(MemoryRefreshKind::nothing().with_ram().with_swap()),
        );
        // Seed the differential baseline and load memory counters without
        // blocking. First sample_cpu will refresh again and return the delta
        // since this baseline (usually ~0 if called immediately).
        system.refresh_cpu_usage();
        system.refresh_memory();
        // Seed the network counter baseline so the first sample_network measures
        // a real interval rather than counting all bytes since boot.
        let networks = Networks::new_with_refreshed_list();
        Self {
            system,
            networks,
            last_net_refresh: Instant::now(),
        }
    }

    pub fn sample_cpu(&mut self) -> f64 {
        self.system.refresh_cpu_usage();
        (self.system.global_cpu_usage() as f64).clamp(0.0, 100.0)
    }

    /// Host network throughput since the previous call, in bytes/sec. sysinfo's
    /// `received`/`transmitted` are per-refresh deltas; dividing by the measured
    /// elapsed time yields the rate. Loopback (`lo`) is excluded. The first call
    /// after construction covers only the short seed-to-now interval, so treat a
    /// sub-100 ms window as a warm-up and report 0 rather than a wild rate.
    pub fn sample_network(&mut self) -> NetworkSample {
        self.networks.refresh(false);
        let elapsed = self.last_net_refresh.elapsed().as_secs_f64();
        self.last_net_refresh = Instant::now();
        if elapsed < 0.1 {
            return NetworkSample {
                rx_bytes_per_sec: 0.0,
                tx_bytes_per_sec: 0.0,
            };
        }
        let (rx, tx) = self
            .networks
            .iter()
            .filter(|(name, _)| name.as_str() != "lo")
            .fold((0u64, 0u64), |(rx, tx), (_, data)| {
                (rx + data.received(), tx + data.transmitted())
            });
        NetworkSample {
            rx_bytes_per_sec: rx as f64 / elapsed,
            tx_bytes_per_sec: tx as f64 / elapsed,
        }
    }

    /// Load average (1 / 5 / 15 minute). Reads `/proc/loadavg` on Linux; returns
    /// zeros on platforms sysinfo does not support.
    pub fn sample_load(&self) -> (f64, f64, f64) {
        let la = System::load_average();
        (la.one, la.five, la.fifteen)
    }

    /// Current-only host status: uptime seconds plus swap totals. Swap comes
    /// from the same refreshed `System` as memory.
    pub fn sample_host_status(&mut self, time: i64) -> HostStatusRow {
        self.system.refresh_memory();
        let swap_total = self.system.total_swap();
        let swap_used = self.system.used_swap();
        let swap_free = self.system.free_swap();
        let swap_used_percent = if swap_total > 0 {
            let raw = swap_used as f64 / swap_total as f64 * 100.0;
            (raw * 100.0).round() / 100.0
        } else {
            0.0
        };
        HostStatusRow {
            uptime_seconds: System::uptime(),
            swap_total,
            swap_used,
            swap_free,
            swap_used_percent,
            time,
        }
    }

    /// `time` is left at 0; the caller stamps it so every metric in a cycle
    /// shares one timestamp, matching the Go collector.
    ///
    /// `used`/`usedPercent` come from sysinfo's `used_memory()`, which is
    /// `MemTotal - MemAvailable`. This is a **deliberate, more-accurate
    /// divergence** from the Go agent, which used gopsutil's classic
    /// `Total - Free - Buffers - Cached`. gopsutil treats *all* page cache as
    /// reclaimable — including tmpfs/shmem and other non-reclaimable pages — so
    /// it under-reports real memory pressure. `MemTotal - MemAvailable` uses the
    /// kernel's own estimate of memory obtainable without swapping, and is what
    /// modern `free`/`htop`/node_exporter report as used.
    ///
    /// NOTE: on cache-heavy hosts this reads HIGHER than the Go agent did — that
    /// is intentional and correct. Do NOT "restore Go parity" by switching back
    /// to the gopsutil formula; the higher number is the honest one. If this
    /// value ever needs to change, treat it as a versioned metric change and
    /// re-check any Coolify memory alert thresholds calibrated on the old agent.
    pub fn sample_memory(&mut self) -> MemRow {
        self.system.refresh_memory();
        let total = self.system.total_memory();
        let available = self.system.available_memory();
        let used = self.system.used_memory();
        let free = self.system.free_memory();
        let used_percent = if total > 0 {
            let raw = used as f64 / total as f64 * 100.0;
            (raw * 100.0).round() / 100.0
        } else {
            0.0
        };
        MemRow {
            time: 0,
            total,
            available,
            used,
            used_percent,
            free,
        }
    }
}
