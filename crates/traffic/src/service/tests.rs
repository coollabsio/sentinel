use super::*;
use crate::enrich::NoGeo;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use store::traffic::{AnalyticsStore, Tier};

const APP: &str = "jc4wsgs";

fn traefik_line(path: &str, status: u16, secs: u32) -> String {
    format!(
        r#"{{"ClientAddr":"10.0.0.5:54321","ClientHost":"10.0.0.5","DownstreamContentSize":512,"DownstreamStatus":{status},"Duration":12500000,"RequestContentSize":0,"RequestHost":"app.example.com","RequestMethod":"GET","RequestPath":"{path}","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"https-0-{APP}@docker","StartUTC":"2026-08-09T12:00:{secs:02}.000000000Z","TLSVersion":"1.3","request_Cf-Connecting-Ip":"203.0.113.7","request_Cf-Ipcountry":"US","request_User-Agent":"curl/8.4.0","time":"2026-08-09T12:00:00Z"}}"#
    )
}

fn test_config(access_log_path: PathBuf, sample_threshold: u32) -> config::Config {
    config::Config {
        version: "0.0.0-test".into(),
        debug: false,
        refresh_rate_seconds: 5,
        push_enabled: false,
        push_interval_seconds: 60,
        push_path: "/api/v1/sentinel/push".into(),
        push_url: "http://localhost:8000".into(),
        token: "test-token".into(),
        endpoint: "http://localhost:8000".into(),
        metrics_file: PathBuf::from("./db/metrics.sqlite"),
        collector_enabled: false,
        collector_retention_period_days: 7,
        bind_addr: "127.0.0.1:0".parse::<SocketAddr>().expect("bind addr"),
        storage_enabled: false,
        storage_refresh_rate_seconds: 300,
        storage_volumes_enabled: false,
        storage_volumes_refresh_rate_seconds: 900,
        host_mount_prefix: String::new(),
        traffic: config::TrafficSettings {
            enabled: true,
            access_log_path,
            proxy_type: "auto".into(),
            topn: 50,
            sample_threshold,
            retention_1m_hours: 48,
            retention_1h_days: 30,
            retention_1d_days: 395,
            analytics_file: PathBuf::from("./db/analytics.sqlite"),
            geoip_enabled: false,
            geoip_db_url: None,
            geoip_maxmind_key: None,
            geoip_maxmind_edition: "GeoLite2-Country".into(),
            geoip_refresh_days: 30,
        },
    }
}

fn append(path: &std::path::Path, data: &str) {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open access log for append");
    f.write_all(data.as_bytes()).expect("write access log");
    f.flush().expect("flush access log");
}

fn total_requests(store: &AnalyticsStore) -> i64 {
    store
        .stats_range(Tier::M1, APP, 0, i64::MAX)
        .expect("stats_range")
        .iter()
        .map(|r| r.requests)
        .sum()
}

/// Polls `stats_range` until the requests total reaches `want` or the
/// deadline passes, so the assertion never depends on a single fixed
/// sleep being long enough under CI load.
async fn wait_for_requests(store: &AnalyticsStore, want: i64, timeout: Duration) -> i64 {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let total = total_requests(store);
        if total >= want || tokio::time::Instant::now() >= deadline {
            return total;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Polls an atomic counter until it reaches `want` or the deadline passes.
async fn wait_for_counter(
    counter: &std::sync::atomic::AtomicU64,
    want: u64,
    timeout: Duration,
) -> u64 {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let seen = counter.load(std::sync::atomic::Ordering::Relaxed);
        if seen >= want || tokio::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The whole pipeline, end to end: a real file on disk -> `Tailer` ->
/// `parse_line` (via auto-detect) -> `Enricher` -> `Aggregator` ->
/// `AnalyticsStore::flush_window`, driven by `run`'s own tickers.
#[tokio::test]
async fn full_pipeline_flushes_tailed_lines_to_the_store() {
    const N: i64 = 5;

    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("access.log");
    std::fs::File::create(&log).expect("create access log");

    let store = AnalyticsStore::open_in_memory().expect("open store");
    let cfg = test_config(log.clone(), 0);

    let svc = TrafficService::build_with_intervals(
        &cfg,
        store.clone(),
        Arc::new(NoGeo),
        100,
        Duration::from_millis(10),
        Duration::from_millis(10),
    )
    .await
    .expect("build service");

    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(svc.run(rx));

    for i in 0..N {
        append(
            &log,
            &format!("{}\n", traefik_line("/api/users", 200, i as u32)),
        );
    }

    let total = wait_for_requests(&store, N, Duration::from_secs(5)).await;
    assert_eq!(
        total, N,
        "every tailed line must reach the store's 1m stats tier"
    );

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run() must return promptly after shutdown")
        .expect("run() task must not panic");
}

/// Data recorded into a window that has not closed yet must still be
/// persisted when shutdown arrives -- and `run` must not return until
/// that final flush has actually completed.
#[tokio::test]
async fn shutdown_flushes_the_partial_window_before_returning() {
    const N: i64 = 3;

    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("access.log");
    std::fs::File::create(&log).expect("create access log");

    let store = AnalyticsStore::open_in_memory().expect("open store");
    let cfg = test_config(log.clone(), 0);

    // A 10-minute window: no boundary can be crossed during this test,
    // so the only thing that can persist these rows is the shutdown path.
    let svc = TrafficService::build_with_intervals(
        &cfg,
        store.clone(),
        Arc::new(NoGeo),
        600_000,
        Duration::from_millis(5),
        Duration::from_millis(5),
    )
    .await
    .expect("build service");
    let processed = svc.processed_counter();

    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(svc.run(rx));

    for i in 0..N {
        append(&log, &format!("{}\n", traefik_line("/", 200, i as u32)));
    }

    // Deterministic: wait until the loop has actually folded all N events
    // into the (still open) window, rather than sleeping and hoping.
    let seen = wait_for_counter(&processed, N as u64, Duration::from_secs(5)).await;
    assert_eq!(seen, N as u64, "all lines must be recorded before shutdown");
    assert_eq!(
        total_requests(&store),
        0,
        "the window is still open, nothing should have been flushed yet"
    );

    tx.send(true).expect("send shutdown");
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("run() must return promptly after shutdown")
        .expect("run() task must not panic");

    assert_eq!(
        total_requests(&store),
        N,
        "the partial window must be flushed (and awaited) before run() returns"
    );
}

#[tokio::test]
async fn auto_detect_locks_in_only_on_a_successful_detection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("access.log");
    std::fs::File::create(&log).expect("create access log");

    let store = AnalyticsStore::open_in_memory().expect("open store");
    let cfg = test_config(log, 0);
    let mut svc = TrafficService::build(&cfg, store, Arc::new(NoGeo))
        .await
        .expect("build service");

    assert_eq!(svc.proxy, ProxyType::Auto, "config said auto");

    svc.process_line(b"this is not json at all");
    assert_eq!(
        svc.proxy,
        ProxyType::Auto,
        "a failed detection must not lock the proxy type in"
    );
    assert_eq!(svc.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);

    let line = traefik_line("/", 200, 0);
    svc.process_line(line.as_bytes());
    assert_eq!(
        svc.proxy,
        ProxyType::Traefik,
        "a successful detection locks the proxy type in"
    );
    assert_eq!(svc.processed.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn sampling_hard_caps_events_per_second() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("access.log");
    std::fs::File::create(&log).expect("create access log");

    let store = AnalyticsStore::open_in_memory().expect("open store");
    let cfg = test_config(log, 2);
    let mut svc = TrafficService::build(&cfg, store, Arc::new(NoGeo))
        .await
        .expect("build service");

    let line = traefik_line("/", 200, 0);
    for _ in 0..5 {
        svc.process_line(line.as_bytes());
    }

    let rollup = svc.aggregator.take_rollup(0);
    let recorded: i64 = rollup.stats.iter().map(|r| r.requests).sum();
    assert_eq!(recorded, 2, "at most sample_threshold events per second");
    assert_eq!(
        svc.dropped.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "sampled-away events count as dropped"
    );
}

/// A backward wall-clock step must not wedge the flush gate shut. Under
/// the previous `bucket_now > current_bucket` test, one NTP correction
/// pushing the clock back a minute meant no window ever closed again —
/// nothing was ever written, and the aggregator grew unbounded.
#[tokio::test]
async fn a_backward_clock_step_still_closes_the_window() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("access.log");
    std::fs::File::create(&log).expect("create access log");
    let store = AnalyticsStore::open_in_memory().expect("open store");
    let mut svc = TrafficService::build(&test_config(log, 0), store, Arc::new(NoGeo))
        .await
        .expect("build service");

    svc.current_bucket = 600_000;

    // Same window: nothing closes.
    assert_eq!(svc.take_closed_bucket(600_000), None);
    assert_eq!(svc.current_bucket, 600_000);

    // Forward, the ordinary case: the old window closes and is adopted.
    assert_eq!(svc.take_closed_bucket(660_000), Some(600_000));
    assert_eq!(svc.current_bucket, 660_000);

    // Backward: the open window must still close, and the service must
    // resynchronize onto the clock's new window rather than stalling.
    assert_eq!(
        svc.take_closed_bucket(540_000),
        Some(660_000),
        "a backward step must still close the open window"
    );
    assert_eq!(svc.current_bucket, 540_000);

    // …and it keeps working afterwards, rather than being wedged.
    assert_eq!(svc.take_closed_bucket(600_000), Some(540_000));
    assert_eq!(svc.current_bucket, 600_000);
}

#[test]
fn proxy_type_parsing_is_case_insensitive_and_defaults_to_auto() {
    assert_eq!(parse_proxy_type("traefik"), ProxyType::Traefik);
    assert_eq!(parse_proxy_type("TRAEFIK"), ProxyType::Traefik);
    assert_eq!(parse_proxy_type("Caddy"), ProxyType::Caddy);
    assert_eq!(parse_proxy_type("auto"), ProxyType::Auto);
    assert_eq!(
        parse_proxy_type("nginx"),
        ProxyType::Auto,
        "an unrecognized value must degrade to auto, not refuse to start"
    );
}

/// The window-length override exists purely so tests don't wait a real
/// minute; at the production default it must agree exactly with the
/// aggregator's own minute bucketing.
#[test]
fn default_window_bucketing_matches_the_aggregator() {
    for ts in [0, 1, 59_999, 60_000, 90_000, 1_786_000_123_456] {
        assert_eq!(
            bucket_of(ts, DEFAULT_WINDOW_MS),
            crate::aggregator::Aggregator::bucket_of(ts)
        );
    }
}
