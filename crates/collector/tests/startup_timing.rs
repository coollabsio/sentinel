use std::time::Instant;

#[test]
fn host_sampler_new_is_fast() {
    let t0 = Instant::now();
    let _s = collector::HostSampler::new();
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    eprintln!("HostSampler::new took {ms:.1} ms");
    assert!(ms < 50.0, "HostSampler::new must not sleep a full CPU interval: {ms} ms");
}
