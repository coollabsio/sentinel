use store::MemRow;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

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
                .with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        // Seed the differential baseline and load memory counters without
        // blocking. First sample_cpu will refresh again and return the delta
        // since this baseline (usually ~0 if called immediately).
        system.refresh_cpu_usage();
        system.refresh_memory();
        Self { system }
    }

    pub fn sample_cpu(&mut self) -> f64 {
        self.system.refresh_cpu_usage();
        (self.system.global_cpu_usage() as f64).clamp(0.0, 100.0)
    }

    /// `time` is left at 0; the caller stamps it so every metric in a cycle
    /// shares one timestamp, matching the Go collector.
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
