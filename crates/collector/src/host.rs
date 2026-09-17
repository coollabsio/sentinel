use std::collections::HashMap;
use std::time::Instant;

use store::{HostStatusRow, MemRow};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// Host network counters. Coolify runs Sentinel with `--pid host` but in its own
/// network namespace, so `/proc/net/dev` (and sysinfo, which reads
/// `/sys/class/net`) only sees Sentinel's own container interface. `/proc/1` is
/// the host init process under `--pid host`, so its `net/dev` is the host's.
/// The self view is the fallback when `/proc/1/net` is not readable. The path is
/// picked once, so two samples never compare counters from different namespaces.
const NET_DEV_PATHS: [&str; 2] = ["/proc/1/net/dev", "/proc/net/dev"];

/// Interface name prefixes left out of the host total: loopback, plus interfaces
/// whose traffic is also counted on the physical NIC it leaves through, so summing
/// them would count it twice or more. That covers bridges (their member NIC is
/// counted instead), bonds and teams (their member NICs are), veths, overlays, tunnels and VPNs.
/// VLAN sub-interfaces (`enp7s0.4000`) are skipped by the `.` check in
/// [`parse_net_dev`].
const VIRTUAL_IFACE_PREFIXES: [&str; 22] = [
    "lo",
    "veth",
    "docker",
    "br",
    "virbr",
    "vmbr",
    "lxdbr",
    "incusbr",
    "podman",
    "bond",
    "team",
    "vlan",
    "cni",
    "flannel",
    "cali",
    "vxlan",
    "vnet",
    "tap",
    "tun",
    "tailscale",
    "wg",
    "zt",
];

/// Cumulative `(rx_bytes, tx_bytes)` per interface.
type NetCounters = HashMap<String, (u64, u64)>;

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
    /// `net/dev` file chosen at construction (see [`NET_DEV_PATHS`]); `None`
    /// when neither is readable, which reports a zero rate.
    net_dev_path: Option<&'static str>,
    /// Counters from the previous network sample; the rate is the delta.
    net_counters: NetCounters,
    /// Wall clock of the last network read, for the rate denominator.
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
        let net_dev_path = NET_DEV_PATHS
            .into_iter()
            .find(|p| std::fs::File::open(p).is_ok());
        Self {
            system,
            net_dev_path,
            net_counters: read_net_counters(net_dev_path),
            last_net_refresh: Instant::now(),
        }
    }

    pub fn sample_cpu(&mut self) -> f64 {
        self.system.refresh_cpu_usage();
        (self.system.global_cpu_usage() as f64).clamp(0.0, 100.0)
    }

    /// Host network throughput since the previous call, in bytes/sec, summed
    /// over physical interfaces (see [`VIRTUAL_IFACE_PREFIXES`]). The first call
    /// after construction covers only the short seed-to-now interval, so treat a
    /// sub-100 ms window as a warm-up and report 0 rather than a wild rate.
    pub fn sample_network(&mut self) -> NetworkSample {
        let cur = read_net_counters(self.net_dev_path);
        let prev = std::mem::replace(&mut self.net_counters, cur);
        let elapsed = self.last_net_refresh.elapsed().as_secs_f64();
        self.last_net_refresh = Instant::now();
        if elapsed < 0.1 {
            return NetworkSample {
                rx_bytes_per_sec: 0.0,
                tx_bytes_per_sec: 0.0,
            };
        }
        let (rx, tx) = counter_delta(&prev, &self.net_counters);
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

fn read_net_counters(path: Option<&str>) -> NetCounters {
    path.and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| parse_net_dev(&s))
        .unwrap_or_default()
}

/// Parses `/proc/net/dev`: two header lines, then `iface: rx_bytes <7 more rx
/// fields> tx_bytes ...`. Virtual interfaces are dropped here.
fn parse_net_dev(s: &str) -> NetCounters {
    s.lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let name = name.trim();
            if name.contains('.') || VIRTUAL_IFACE_PREFIXES.iter().any(|p| name.starts_with(p)) {
                return None;
            }
            let mut fields = rest.split_whitespace();
            let rx = fields.next()?.parse().ok()?;
            let tx = fields.nth(7)?.parse().ok()?;
            Some((name.to_string(), (rx, tx)))
        })
        .collect()
}

/// Bytes moved between two counter reads. Only interfaces present in both count,
/// and a counter that went backwards (interface re-created) adds nothing, so a
/// removed or reset interface never produces a phantom rate.
fn counter_delta(prev: &NetCounters, cur: &NetCounters) -> (u64, u64) {
    cur.iter()
        .filter_map(|(name, &(rx, tx))| {
            let &(prx, ptx) = prev.get(name)?;
            Some((rx.saturating_sub(prx), tx.saturating_sub(ptx)))
        })
        .fold((0, 0), |(rx, tx), (drx, dtx)| {
            (rx.saturating_add(drx), tx.saturating_add(dtx))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0
  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
docker0: 700 7 0 0 0 0 0 0 800 8 0 0 0 0 0 0
vethab12: 300 3 0 0 0 0 0 0 400 4 0 0 0 0 0 0
br-1a2b3c: 300 3 0 0 0 0 0 0 400 4 0 0 0 0 0 0
enp7s0.4000: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0
 bond0: 900 9 0 0 0 0 0 0 900 9 0 0 0 0 0 0
  eth1: 10 1 0 0 0 0 0 0 20 2 0 0 0 0 0 0
";

    #[test]
    fn parse_keeps_only_physical_interfaces() {
        let c = parse_net_dev(NET_DEV);
        assert_eq!(c.len(), 2);
        assert_eq!(c["eth0"], (1000, 2000));
        assert_eq!(c["eth1"], (10, 20));
    }

    #[test]
    fn delta_ignores_new_removed_and_reset_interfaces() {
        let prev: NetCounters = [
            ("eth0".to_string(), (1000, 2000)),
            ("eth1".to_string(), (5000, 5000)),
            ("gone".to_string(), (9000, 9000)),
        ]
        .into();
        let cur: NetCounters = [
            ("eth0".to_string(), (1500, 2600)),
            // Re-created interface: counters went backwards.
            ("eth1".to_string(), (10, 10)),
            ("new0".to_string(), (7000, 7000)),
        ]
        .into();
        assert_eq!(counter_delta(&prev, &cur), (500, 600));
    }
}
