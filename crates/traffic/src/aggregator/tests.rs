use super::*;
use crate::enrich::UaInfo;
use std::net::IpAddr;

fn base_event() -> RequestEvent<'static> {
    RequestEvent {
        ts_ms: 0,
        app: "app-1".into(),
        host: "example.com".into(),
        method: "GET".into(),
        path: "/".into(),
        status: 200,
        bytes_in: 0,
        bytes_out: 100,
        duration_ms: 10.0,
        protocol: "HTTP/1.1".into(),
        scheme: "https".into(),
        tls_version: None,
        client_ip: None,
        xff: None,
        user_agent: None,
        referer: None,
        cf_connecting_ip: None,
        cf_country: None,
        cf_cache_status: None,
        cf_verified_bot: None,
    }
}

fn base_enriched() -> Enriched {
    Enriched {
        country: None,
        ua: UaInfo::default(),
        client_ip: None,
        cache: None,
        bot: false,
    }
}

#[test]
fn folds_requests_and_status() {
    let mut a = Aggregator::new(50);
    let en = base_enriched();

    let mut ev1 = base_event();
    ev1.status = 200;
    let mut ev2 = base_event();
    ev2.status = 200;
    let mut ev3 = base_event();
    ev3.status = 404;

    a.record(&ev1, &en);
    a.record(&ev2, &en);
    a.record(&ev3, &en);

    let rollup = a.take_rollup(60_000);
    assert_eq!(rollup.stats.len(), 1);
    let row = &rollup.stats[0];
    assert_eq!(row.requests, 3);
    assert_eq!(row.s2xx, 2);
    assert_eq!(row.s4xx, 1);
    assert_eq!(row.app, "app-1");
    assert_eq!(row.host, "example.com");
}

#[test]
fn bucket_floors_to_minute() {
    assert_eq!(Aggregator::bucket_of(90_000), 60_000);
}

#[test]
fn breakdown_caps_topn_into_other() {
    let mut a = Aggregator::new(2);

    for _ in 0..3 {
        let mut ev = base_event();
        ev.status = 200;
        let mut en = base_enriched();
        en.country = Some("AA".to_string());
        a.record(&ev, &en);
    }
    for _ in 0..2 {
        let ev = base_event();
        let mut en = base_enriched();
        en.country = Some("BB".to_string());
        a.record(&ev, &en);
    }
    {
        let ev = base_event();
        let mut en = base_enriched();
        en.country = Some("CC".to_string());
        a.record(&ev, &en);
    }

    let rollup = a.take_rollup(60_000);
    let country_rows: Vec<_> = rollup
        .breakdown
        .iter()
        .filter(|r| r.dimension == "country")
        .collect();

    assert_eq!(country_rows.len(), 3, "2 kept + 1 __other__ row");

    let other = country_rows
        .iter()
        .find(|r| r.value == "__other__")
        .expect("expected an __other__ row");
    assert_eq!(other.requests, 1, "the single CC request folded into other");

    let aa = country_rows.iter().find(|r| r.value == "AA").unwrap();
    assert_eq!(aa.requests, 3);
    let bb = country_rows.iter().find(|r| r.value == "BB").unwrap();
    assert_eq!(bb.requests, 2);
}

#[test]
fn paths_get_per_path_latency() {
    let mut a = Aggregator::new(50);
    let en = base_enriched();

    let mut fast = base_event();
    fast.path = "/fast".into();
    fast.duration_ms = 5.0;

    let mut slow = base_event();
    slow.path = "/slow".into();
    slow.duration_ms = 500.0;

    for _ in 0..5 {
        a.record(&fast, &en);
    }
    for _ in 0..5 {
        a.record(&slow, &en);
    }

    let rollup = a.take_rollup(60_000);
    assert_eq!(rollup.paths.len(), 2);

    let fast_row = rollup.paths.iter().find(|p| p.path == "/fast").unwrap();
    let slow_row = rollup.paths.iter().find(|p| p.path == "/slow").unwrap();

    let fast_digest = LatencyDigest::from_bytes(&fast_row.latency_tdigest).unwrap();
    let slow_digest = LatencyDigest::from_bytes(&slow_row.latency_tdigest).unwrap();

    assert!(
        fast_digest.quantile(0.5) < slow_digest.quantile(0.5),
        "per-path digest must reflect that path's own latencies, not a pooled one"
    );
    assert_eq!(fast_row.requests, 5);
    assert_eq!(slow_row.requests, 5);
}

#[test]
fn uniques_skip_when_client_ip_absent() {
    let mut a = Aggregator::new(50);
    let ev = base_event();
    let mut en = base_enriched();
    en.client_ip = None;
    a.record(&ev, &en);

    let mut en2 = base_enriched();
    en2.client_ip = Some("1.2.3.4".parse::<IpAddr>().unwrap());
    a.record(&ev, &en2);

    let rollup = a.take_rollup(60_000);
    assert_eq!(rollup.stats.len(), 1);
    // 1 of the 2 events had a resolvable client_ip; uniques counts ~1.
    let hll_bytes = &rollup.stats[0].uniques_hll;
    let mut u = Uniques::from_bytes(hll_bytes).unwrap();
    assert_eq!(u.count(), 1);
}

#[test]
fn take_rollup_clears_state_for_next_window() {
    let mut a = Aggregator::new(50);
    let en = base_enriched();
    let ev = base_event();

    a.record(&ev, &en);
    let first = a.take_rollup(60_000);
    assert_eq!(first.stats[0].requests, 1);
    assert_eq!(first.paths.len(), 1);
    assert!(!first.breakdown.is_empty());

    // Nothing recorded in the second window: everything must come
    // back empty, not carry over stale counts from the first window.
    let second = a.take_rollup(120_000);
    assert!(second.stats.is_empty());
    assert!(second.paths.is_empty());
    assert!(second.breakdown.is_empty());

    // A fresh record in the third window must not be polluted by
    // anything left behind from the first.
    a.record(&ev, &en);
    let third = a.take_rollup(180_000);
    assert_eq!(third.stats.len(), 1);
    assert_eq!(third.stats[0].requests, 1);
}

#[test]
fn always_recorded_dimensions_bypass_empty_skip() {
    // method is an "always recorded" dimension (status, method,
    // protocol, scheme, bot): it must be recorded even for an
    // edge-case empty value, unlike the skippable dimensions (e.g.
    // country) which drop empty values silently. A real Traefik/Caddy
    // parse would never produce an empty method, but the contract is
    // "always recorded", not "recorded unless empty".
    let mut a = Aggregator::new(50);
    let en = base_enriched();
    let mut ev = base_event();
    ev.method = "".into();

    a.record(&ev, &en);

    let rollup = a.take_rollup(60_000);
    let method_row = rollup
        .breakdown
        .iter()
        .find(|r| r.dimension == "method")
        .expect("method dimension must always produce a row, even for an empty value");
    assert_eq!(method_row.value, "");
    assert_eq!(method_row.requests, 1);
}
