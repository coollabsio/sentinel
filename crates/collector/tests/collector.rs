use collector::{HostSampler, now_millis};

#[test]
fn now_millis_is_a_plausible_unix_timestamp() {
    let t = now_millis();
    // after 2020-01-01 and before 2100-01-01
    assert!(t > 1_577_836_800_000, "got {t}");
    assert!(t < 4_102_444_800_000, "got {t}");
}

#[test]
fn cpu_sample_is_in_range_after_warmup() {
    let mut s = HostSampler::new();
    // First read is meaningless because sysinfo is differential; the sampler
    // must warm up internally so callers never see a bogus first value.
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
    // used_percent is rounded to 2 decimals, matching the Go implementation
    assert!((m.used_percent * 100.0).fract().abs() < 1e-6);
}
