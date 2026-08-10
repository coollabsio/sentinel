use super::*;

fn stats() -> ContainerStats {
    ContainerStats {
        cpu_total: 0,
        pre_cpu_total: 0,
        system_usage: 0,
        pre_system_usage: 0,
        online_cpus: 0,
        percpu_usage_len: 0,
        mem_usage: 0,
        mem_limit: 0,
        inactive_file: 0,
    }
}

#[test]
fn cpu_percent_matches_docker_formula() {
    let s = ContainerStats {
        cpu_total: 200,
        pre_cpu_total: 100,
        system_usage: 2_000,
        pre_system_usage: 1_000,
        online_cpus: 4,
        ..stats()
    };
    // (100/1000) * 4 * 100 = 40
    assert!((cpu_percent(&s) - 40.0).abs() < 1e-9);
}

#[test]
fn cpu_percent_is_zero_when_deltas_are_non_positive() {
    let s = ContainerStats {
        cpu_total: 100,
        pre_cpu_total: 100,
        system_usage: 2_000,
        pre_system_usage: 1_000,
        online_cpus: 4,
        ..stats()
    };
    assert_eq!(cpu_percent(&s), 0.0);

    let s = ContainerStats {
        cpu_total: 200,
        pre_cpu_total: 100,
        system_usage: 1_000,
        pre_system_usage: 1_000,
        online_cpus: 4,
        ..stats()
    };
    assert_eq!(cpu_percent(&s), 0.0);
}

#[test]
fn cpu_percent_is_zero_with_no_online_cpus_and_no_percpu_usage() {
    let s = ContainerStats {
        cpu_total: 200,
        pre_cpu_total: 100,
        system_usage: 2_000,
        pre_system_usage: 1_000,
        online_cpus: 0,
        percpu_usage_len: 0,
        ..stats()
    };
    assert_eq!(cpu_percent(&s), 0.0);
}

#[test]
fn cpu_percent_falls_back_to_percpu_usage_len_when_online_cpus_is_zero() {
    // Go's calculateCPUPercent falls back to len(PercpuUsage) when
    // OnlineCPUs is 0 (cgroup v1 hosts, some Docker Engine builds don't
    // populate it) — dropping this silently reports 0% on those hosts.
    let s = ContainerStats {
        cpu_total: 200,
        pre_cpu_total: 100,
        system_usage: 2_000,
        pre_system_usage: 1_000,
        online_cpus: 0,
        percpu_usage_len: 4,
        ..stats()
    };
    // same formula as cpu_percent_matches_docker_formula: (100/1000)*4*100 = 40
    assert!((cpu_percent(&s) - 40.0).abs() < 1e-9);
}

#[test]
fn memory_used_subtracts_inactive_file() {
    let s = ContainerStats {
        mem_usage: 1_000,
        inactive_file: 400,
        ..stats()
    };
    assert_eq!(memory_used(&s), 600);
}

#[test]
fn memory_used_is_zero_when_cache_exceeds_usage() {
    let s = ContainerStats {
        mem_usage: 100,
        inactive_file: 500,
        ..stats()
    };
    assert_eq!(memory_used(&s), 0);
    let s = ContainerStats {
        mem_usage: 100,
        inactive_file: 100,
        ..stats()
    };
    assert_eq!(memory_used(&s), 0);
}

#[test]
fn memory_percent_uses_limit_as_denominator() {
    let s = ContainerStats {
        mem_usage: 1_000,
        inactive_file: 0,
        mem_limit: 4_000,
        ..stats()
    };
    assert!((memory_percent(&s) - 25.0).abs() < 1e-9);
}

#[test]
fn memory_percent_is_zero_with_no_limit() {
    let s = ContainerStats {
        mem_usage: 1_000,
        mem_limit: 0,
        ..stats()
    };
    assert_eq!(memory_percent(&s), 0.0);
}
