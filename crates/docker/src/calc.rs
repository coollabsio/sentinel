use crate::model::ContainerStats;

/// Ported verbatim from calculateCPUPercent in pkg/collector/collector.go,
/// including its two-step CPU-count fallback: OnlineCPUs, then the length of
/// PercpuUsage, then 0. Dropping the middle step would silently report 0%
/// CPU on hosts where online_cpus isn't populated but percpu_usage is
/// (cgroup v1, some Docker Engine builds).
pub fn cpu_percent(s: &ContainerStats) -> f64 {
    let cpu_delta = s.cpu_total as f64 - s.pre_cpu_total as f64;
    let system_delta = s.system_usage as f64 - s.pre_system_usage as f64;
    if cpu_delta <= 0.0 || system_delta <= 0.0 {
        return 0.0;
    }
    let mut cpus = s.online_cpus;
    if cpus == 0 {
        cpus = s.percpu_usage_len;
    }
    if cpus == 0 {
        return 0.0;
    }
    (cpu_delta / system_delta) * cpus as f64 * 100.0
}

/// Ported verbatim from calculateMemoryUsed. `inactive_file` is resolved by the
/// caller with the cgroup v1 -> v2 fallback (total_inactive_file, then
/// inactive_file), matching Docker CLI behavior.
pub fn memory_used(s: &ContainerStats) -> u64 {
    if s.inactive_file >= s.mem_usage {
        return 0;
    }
    s.mem_usage - s.inactive_file
}

/// Ported verbatim from calculateMemoryPercent.
pub fn memory_percent(s: &ContainerStats) -> f64 {
    let used = memory_used(s) as f64;
    let limit = s.mem_limit as f64;
    if limit <= 0.0 {
        return 0.0;
    }
    used / limit * 100.0
}

#[cfg(test)]
mod tests;
