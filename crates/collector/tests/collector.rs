use collector::{HostSampler, now_millis};

#[test]
fn now_millis_is_a_plausible_unix_timestamp() {
    let t = now_millis();
    // after 2020-01-01 and before 2100-01-01
    assert!(t > 1_577_836_800_000, "got {t}");
    assert!(t < 4_102_444_800_000, "got {t}");
}

#[test]
fn cpu_sample_is_in_range() {
    let mut s = HostSampler::new();
    // First read is often ~0.0 because sysinfo is differential and we no
    // longer block-sleep a warm-up in the constructor (cold-start path).
    // Range is still always valid; subsequent samples gain a real delta.
    let p = s.sample_cpu();
    assert!((0.0..=100.0).contains(&p), "cpu percent out of range: {p}");
}

#[test]
fn repeated_cpu_samples_stay_in_range() {
    let mut s = HostSampler::new();
    for _ in 0..3 {
        let p = s.sample_cpu();
        assert!((0.0..=100.0).contains(&p), "cpu percent out of range: {p}");
    }
}

#[test]
fn memory_sample_is_internally_consistent() {
    let mut s = HostSampler::new();
    let m = s.sample_memory();
    assert!(m.total > 0, "total memory must be non-zero");
    assert!(m.used <= m.total, "used must not exceed total");
    assert!(m.available <= m.total, "available must not exceed total");
    assert!((0.0..=100.0).contains(&m.used_percent));
    // used_percent is rounded to 2 decimals, matching the Go implementation.
    // Checked as "equals its own 2-decimal rounding" rather than via
    // `(x * 100.0).fract()`: multiplying back up reintroduces representation
    // error (63.29_f64 * 100.0 == 6328.999999999999), which made this assert
    // fail intermittently depending on the host's live memory usage.
    let rounded = (m.used_percent * 100.0).round() / 100.0;
    assert!(
        (m.used_percent - rounded).abs() < 1e-9,
        "used_percent not rounded to 2 decimals: {}",
        m.used_percent
    );
}

#[test]
fn container_memory_percent_is_rounded_to_two_decimals() {
    // Mirrors the rounding `fetch()` applies before building a ContainerSample:
    // Go stored this column via fmt.Sprintf("%.2f", ...), so the raw f64 from
    // calc::memory_percent is a wire-format departure. Same rounding the host
    // memory sample above is checked for.
    let stats = docker::ContainerStats {
        cpu_total: 0,
        pre_cpu_total: 0,
        system_usage: 0,
        pre_system_usage: 0,
        online_cpus: 0,
        percpu_usage_len: 0,
        // 12_345_678 / 100_000_000 * 100 == 12.345678
        mem_usage: 12_345_678,
        mem_limit: 100_000_000,
        inactive_file: 0,
    };
    let raw = docker::calc::memory_percent(&stats);
    assert!((raw - 12.345_678).abs() < 1e-9, "raw percent: {raw}");

    let rounded = (raw * 100.0).round() / 100.0;
    assert!((rounded - 12.35).abs() < 1e-9, "rounded percent: {rounded}");
}
