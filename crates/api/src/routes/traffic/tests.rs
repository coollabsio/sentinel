use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use std::net::{IpAddr, Ipv4Addr};
use store::traffic::AnalyticsStore;
use tower::ServiceExt;
use traffic::sketches::{LatencyDigest, Uniques};

/// 2023-11-14T22:13:20Z. Both seeded buckets sit inside RANGE below.
const BUCKET: i64 = 1_700_000_000_000;
const NEXT_BUCKET: i64 = BUCKET + 60_000;
/// A 1h window around `BUCKET` (2023-11-14T22:13:20Z). Narrower than
/// [`M1_TRUSTED_SPAN_MS`] so tier selection lands on the `1m` tier, which
/// is the only one `flush_window` writes.
const RANGE: &str = "from=2023-11-14T22:00:00Z&to=2023-11-14T23:00:00Z";

fn digest_bytes(values: &[f64]) -> Vec<u8> {
    let mut d = LatencyDigest::new();
    d.add(values);
    d.to_bytes()
}

fn uniques_bytes(range: std::ops::Range<u32>) -> Vec<u8> {
    let mut u = Uniques::new();
    for i in range {
        u.add_ip(IpAddr::V4(Ipv4Addr::from(i)));
    }
    u.to_bytes()
}

fn ramp(lo: u32, hi: u32) -> Vec<f64> {
    (lo..=hi).map(f64::from).collect()
}

fn stats(
    bucket: i64,
    app: &str,
    host: &str,
    requests: i64,
    latency: Vec<u8>,
    uniques: Vec<u8>,
) -> StatsRow {
    StatsRow {
        bucket,
        app: app.into(),
        host: host.into(),
        requests,
        bytes_in: requests * 10,
        bytes_out: requests * 100,
        s2xx: requests - 2,
        s3xx: 1,
        s4xx: 1,
        s5xx: 0,
        latency_tdigest: latency,
        uniques_hll: uniques,
    }
}

fn path_row(bucket: i64, app: &str, path: &str, requests: i64, latency: Vec<u8>) -> PathRow {
    PathRow {
        bucket,
        app: app.into(),
        path: path.into(),
        requests,
        bytes_out: requests * 100,
        latency_tdigest: latency,
    }
}

fn bd(bucket: i64, app: &str, value: &str, requests: i64) -> BreakdownRow {
    BreakdownRow {
        bucket,
        app: app.into(),
        dimension: "country".into(),
        value: value.into(),
        requests,
        bytes_out: requests * 100,
    }
}

/// Two hosts of `app-a` in one bucket plus a second bucket's paths and
/// breakdown, so grouping across buckets is exercised for real.
fn seeded() -> AnalyticsStore {
    let a = AnalyticsStore::open_in_memory().unwrap();
    a.flush_window(
        &[
            stats(
                BUCKET,
                "app-a",
                "h1",
                10,
                digest_bytes(&ramp(1, 100)),
                uniques_bytes(0..500),
            ),
            stats(
                BUCKET,
                "app-a",
                "h2",
                30,
                digest_bytes(&ramp(101, 200)),
                uniques_bytes(250..750),
            ),
            stats(
                BUCKET,
                "app-b",
                "h1",
                7,
                digest_bytes(&ramp(1, 10)),
                uniques_bytes(0..10),
            ),
        ],
        &[
            path_row(BUCKET, "app-a", "/a", 5, digest_bytes(&ramp(1, 10))),
            path_row(BUCKET, "app-a", "/b", 2, digest_bytes(&ramp(1, 10))),
            path_row(NEXT_BUCKET, "app-a", "/a", 3, digest_bytes(&ramp(1, 10))),
            path_row(NEXT_BUCKET, "app-a", "/b", 20, digest_bytes(&ramp(1, 10))),
        ],
        &[
            bd(BUCKET, "app-a", "US", 5),
            bd(BUCKET, "app-a", "DE", 3),
            bd(NEXT_BUCKET, "app-a", "US", 4),
            bd(NEXT_BUCKET, "app-a", "FR", 10),
        ],
    )
    .unwrap();
    a
}

fn state(analytics: Option<AnalyticsStore>) -> Arc<AppState> {
    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store: store::Store::open_in_memory().unwrap(),
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: Arc::new(crate::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: Arc::new(tokio::sync::Semaphore::new(
            crate::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics_queries: Arc::new(tokio::sync::Semaphore::new(
            crate::MAX_CONCURRENT_ANALYTICS_QUERIES,
        )),
        analytics,
        geoip_attribution: Arc::new(std::sync::RwLock::new(None)),
    })
}

async fn get_with(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
    let res = crate::router(state)
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("Authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get(uri: &str) -> (StatusCode, serde_json::Value) {
    get_with(state(Some(seeded())), uri).await
}

#[test]
fn tier_is_selected_by_span() {
    // Boundaries are exclusive at the low end: exactly 2h is already too
    // wide for the 1m tier, exactly 30d too wide for 1h.
    assert_eq!(tier_for_span(0, M1_TRUSTED_SPAN_MS - 1), Tier::M1);
    assert_eq!(tier_for_span(0, M1_TRUSTED_SPAN_MS), Tier::H1);
    assert_eq!(tier_for_span(0, 30 * DAY_MS - 1), Tier::H1);
    assert_eq!(tier_for_span(0, 30 * DAY_MS), Tier::D1);
    assert_eq!(tier_for_span(0, 400 * DAY_MS), Tier::D1);
    // Offset windows are judged on width, not absolute position.
    assert_eq!(tier_for_span(BUCKET, BUCKET + HOUR_MS), Tier::M1);
    // Compaction empties the `1m` tier hourly, so anything wider than a
    // couple of hours must read `1h`, where that data actually lives —
    // routing a day-wide query at `1m` reported ~1/24th of real traffic.
    assert_eq!(tier_for_span(0, 24 * HOUR_MS), Tier::H1);
    assert_eq!(tier_for_span(0, 47 * HOUR_MS), Tier::H1);
}

#[tokio::test]
async fn apps_lists_recorded_apps() {
    let (s, j) = get("/api/traffic/apps").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j, serde_json::json!(["app-a", "app-b"]));
}

#[tokio::test]
async fn attribution_is_null_when_geoip_has_not_resolved_yet() {
    // Mirrors real startup: the cell is created empty and only ever
    // filled in once GeoIp::bootstrap succeeds, which can take a while
    // (or never happen, e.g. GEOIP_ENABLED=false).
    let (s, j) = get("/api/traffic/attribution").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["attribution"], serde_json::Value::Null);
}

#[tokio::test]
async fn attribution_reports_the_resolved_string() {
    let st = state(Some(seeded()));
    *st.geoip_attribution.write().unwrap() =
        Some("IP Geolocation by DB-IP (https://db-ip.com)".to_string());
    let (s, j) = get_with(st, "/api/traffic/attribution").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j["attribution"],
        "IP Geolocation by DB-IP (https://db-ip.com)"
    );
}

#[tokio::test]
async fn attribution_reflects_a_later_source_swap_not_the_boot_value() {
    // Regression test for the write-once `OnceLock` design: a GeoIP
    // refresh can swap which source is active (mirror <-> DB-IP
    // fallback) well after boot, and `AppState::geoip_attribution` must
    // be re-writable so the endpoint tracks the *current* source rather
    // than freezing whatever was true at startup. Writing twice with
    // different values, as a real bootstrap-then-refresh-swap sequence
    // would, proves the cell picks up the second write.
    let st = state(Some(seeded()));
    *st.geoip_attribution.write().unwrap() =
        Some("This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com".to_string());
    *st.geoip_attribution.write().unwrap() =
        Some("IP Geolocation by DB-IP (https://db-ip.com)".to_string());
    let (s, j) = get_with(st, "/api/traffic/attribution").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j["attribution"], "IP Geolocation by DB-IP (https://db-ip.com)",
        "the endpoint must report the latest write, not the first"
    );
}

#[tokio::test]
async fn overview_merges_every_host_of_the_app() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/overview?{RANGE}")).await;
    assert_eq!(s, StatusCode::OK);

    assert_eq!(j["requests"], 40, "10 (h1) + 30 (h2)");
    assert_eq!(j["bytes_in"], 400);
    assert_eq!(j["bytes_out"], 4000);
    assert_eq!(j["status"]["s2xx"], 36, "8 + 28");
    assert_eq!(j["status"]["s3xx"], 2);
    assert_eq!(j["status"]["s4xx"], 2);
    assert_eq!(j["status"]["s5xx"], 0);

    // h1 saw latencies 1..=100, h2 saw 101..=200: the merged digest must
    // describe 1..=200, not either half alone.
    let p50 = j["latency"]["p50"].as_f64().unwrap();
    let p95 = j["latency"]["p95"].as_f64().unwrap();
    let p99 = j["latency"]["p99"].as_f64().unwrap();
    assert!((90.0..=112.0).contains(&p50), "p50 was {p50}");
    assert!((180.0..=200.0).contains(&p95), "p95 was {p95}");
    assert!(p99 >= p95 && p99 <= 201.0, "p99 was {p99}");

    // 0..500 unioned with 250..750 is 750 distinct IPs; HLL++ at
    // precision 14 is well inside 5% of that.
    let uniq = j["unique_visitors"].as_u64().unwrap();
    assert!((712..=788).contains(&uniq), "unique_visitors was {uniq}");
}

#[tokio::test]
async fn overview_of_an_app_without_data_is_zeroed_not_404() {
    let (s, j) = get(&format!("/api/app/nosuch/traffic/overview?{RANGE}")).await;
    assert_eq!(s, StatusCode::OK, "no data in range is not 'not enabled'");
    assert_eq!(j["requests"], 0);
    assert_eq!(j["latency"]["p50"], 0.0);
    assert_eq!(j["unique_visitors"], 0);
}

#[tokio::test]
async fn overview_skips_undecodable_sketches_without_failing() {
    let a = AnalyticsStore::open_in_memory().unwrap();
    a.flush_window(
        &[
            stats(BUCKET, "app-a", "good", 4, digest_bytes(&[50.0; 20]), {
                let mut u = Uniques::new();
                u.add_ip(IpAddr::V4(Ipv4Addr::from(1u32)));
                u.to_bytes()
            }),
            // Truncated postcard varints: neither blob can decode.
            stats(
                BUCKET,
                "app-a",
                "corrupt",
                6,
                vec![0xff, 0xff],
                vec![0xff, 0xff],
            ),
        ],
        &[],
        &[],
    )
    .unwrap();

    let (s, j) = get_with(
        state(Some(a)),
        &format!("/api/app/app-a/traffic/overview?{RANGE}"),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "one corrupt blob must not fail the query"
    );
    assert_eq!(j["requests"], 10, "counters from both rows still count");
    let p50 = j["latency"]["p50"].as_f64().unwrap();
    assert!(
        (49.0..=51.0).contains(&p50),
        "the decodable digest must still drive the quantiles, got {p50}"
    );
    assert_eq!(j["unique_visitors"], 1);
}

#[tokio::test]
async fn paths_sum_across_buckets_and_sort_by_requests() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}")).await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["path"], "/b", "22 requests must outrank /a's 8");
    assert_eq!(rows[0]["requests"], 22);
    assert_eq!(rows[0]["bytes_out"], 2200);
    assert_eq!(rows[1]["path"], "/a");
    assert_eq!(rows[1]["requests"], 8);
    assert!(rows[0]["p50"].as_f64().unwrap() > 0.0);
    assert!(rows[0]["p95"].as_f64().unwrap() > 0.0);
    assert!(rows[0].get("p99").is_none(), "p99 is deliberately omitted");
}

#[tokio::test]
async fn paths_limit_applies_after_grouping() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}&limit=1")).await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["requests"], 22,
        "the limit must cut the grouped top-N, not the raw bucket rows"
    );
}

#[tokio::test]
async fn breakdown_sums_across_buckets_sorts_and_limits() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/breakdown/country?{RANGE}")).await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    // US is 5 + 4 = 9 across two buckets; FR is 10 in one. Summing first
    // is what puts FR ahead of US and DE last.
    assert_eq!(rows[0]["value"], "FR");
    assert_eq!(rows[0]["requests"], 10);
    assert_eq!(rows[1]["value"], "US");
    assert_eq!(rows[1]["requests"], 9);
    assert_eq!(rows[1]["bytes_out"], 900);
    assert_eq!(rows[2]["value"], "DE");

    let (s, j) = get(&format!(
        "/api/app/app-a/traffic/breakdown/country?{RANGE}&limit=2"
    ))
    .await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["value"], "FR");
    assert_eq!(rows[1]["value"], "US");
}

#[tokio::test]
async fn unknown_dimension_returns_an_empty_array() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/breakdown/nosuch?{RANGE}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j, serde_json::json!([]));
}

#[tokio::test]
async fn every_endpoint_404s_when_analytics_is_disabled() {
    for uri in [
        "/api/traffic/apps",
        "/api/app/app-a/traffic/overview",
        "/api/app/app-a/traffic/paths",
        "/api/app/app-a/traffic/breakdown/country",
        "/api/traffic/attribution",
    ] {
        let (s, j) = get_with(state(None), uri).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(j["error"], "traffic analytics not enabled", "{uri}");
    }
}

#[tokio::test]
async fn malformed_bounds_and_limits_are_rejected() {
    for uri in [
        "/api/app/app-a/traffic/overview?from=bogus",
        "/api/app/app-a/traffic/paths?to=bogus",
        "/api/app/app-a/traffic/paths?limit=abc",
        "/api/app/app-a/traffic/breakdown/country?limit=0",
    ] {
        let (s, _) = get(uri).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}");
    }
}

/// `?from=&to=&limit=` (a caller interpolating empty optionals) must be
/// treated as absent, exactly as `resolve_range` already does for the
/// host endpoints — never rejected as malformed.
#[tokio::test]
async fn empty_query_values_fall_back_to_defaults() {
    let (s, j) = get(&format!("/api/app/app-a/traffic/paths?{RANGE}&limit=")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j.as_array().unwrap().len(),
        2,
        "an empty limit must fall back to the default, not cap at 0"
    );

    let (s, _) = get("/api/app/app-a/traffic/paths?from=&to=&limit=").await;
    assert_eq!(s, StatusCode::OK, "empty bounds must default, not 400");
}

/// A day of minute-resolution traffic, put through the *real* hourly
/// compaction sweep, must still be fully visible to a day-wide query.
///
/// This is the regression test for the tier-selection bug. `compact_1m_to_1h`
/// deletes the `1m` rows for every window it folds into `1h` — that delete is
/// the watermark that keeps a re-compaction from double-counting, so it is
/// deliberate and load-bearing. The old `tier_for_span` nonetheless routed
/// any span under 48h to `Tier::M1`, reading a table compaction had already
/// emptied: this fixture would have come back as `requests: 0` while
/// reporting HTTP 200, i.e. "no traffic" for a day that had 240 requests.
#[tokio::test]
async fn a_day_wide_query_sees_data_the_hourly_compaction_has_already_swept() {
    const HOURS: i64 = 24;
    const PER_HOUR: i64 = 10;
    // 2023-11-14T00:00:00Z, hour-aligned so each hour is a whole bucket.
    const START: i64 = 1_699_920_000_000;

    let a = AnalyticsStore::open_in_memory().unwrap();
    let rows: Vec<StatsRow> = (0..HOURS)
        .map(|h| {
            stats(
                START + h * HOUR_MS,
                "app-a",
                "h1",
                PER_HOUR,
                digest_bytes(&ramp(1, 10)),
                uniques_bytes(0..10),
            )
        })
        .collect();
    a.flush_window(&rows, &[], &[]).unwrap();

    // The real sweep, not a stand-in: every one of these hours is closed
    // as of `now`, so all of them roll into `1h` and their `1m` rows go.
    let now = START + HOURS * HOUR_MS + HOUR_MS;
    traffic::compaction::compact_1m_to_1h(&a, now, 50).unwrap();
    assert!(
        a.stats_range(Tier::M1, "app-a", START, now)
            .unwrap()
            .is_empty(),
        "compaction must have emptied the 1m tier — that premise is the whole bug"
    );

    let (s, j) = get_with(
        state(Some(a)),
        "/api/app/app-a/traffic/overview?from=2023-11-14T00:00:00Z&to=2023-11-15T00:00:00Z",
    )
    .await;

    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j["requests"],
        HOURS * PER_HOUR,
        "a 24h span must read the 1h tier, where compaction actually put this data"
    );
}

/// 2023-11-14T00:00:00Z, the start of WIDE_RANGE below.
const WIDE_FROM: i64 = 1_699_920_000_000;
/// 119 minutes — just inside [`M1_TRUSTED_SPAN_MS`], so the widest window
/// the finest tier can be asked for: 119 one-minute buckets.
const WIDE_BUCKETS: i64 = 119;
const WIDE_RANGE: &str = "from=2023-11-14T00:00:00Z&to=2023-11-14T01:59:00Z";
/// Distinct paths per bucket, just under the configured `topn` (50) —
/// the aggregator caps a `1m` bucket at `topn` (+ `__other__`), so this is
/// a genuinely full-depth window rather than an impossible one.
const WIDE_PATHS: i64 = 40;

/// A full-depth worst case for the `1m` tier: every bucket of the widest
/// window that tier can now be asked for carrying a full set of per-path
/// rows. `paths_range` orders by bucket ascending, so anything the SQL
/// LIMIT discards is the *most recent* data — truncation here would be
/// both silent and biased towards losing the newest buckets.
#[tokio::test]
async fn a_full_width_1m_window_is_not_truncated_by_the_scan_limit() {
    let a = AnalyticsStore::open_in_memory().unwrap();
    let latency = digest_bytes(&[5.0]);
    let mut rows = Vec::with_capacity((WIDE_BUCKETS * WIDE_PATHS) as usize);
    for b in 0..WIDE_BUCKETS {
        for p in 0..WIDE_PATHS {
            rows.push(path_row(
                WIDE_FROM + b * 60_000,
                "app-a",
                &format!("/p{p}"),
                1,
                latency.clone(),
            ));
        }
    }
    a.flush_window(&[], &rows, &[]).unwrap();

    let (s, j) = get_with(
        state(Some(a)),
        &format!("/api/app/app-a/traffic/paths?{WIDE_RANGE}&limit=1000"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let out = j.as_array().unwrap();
    assert_eq!(out.len(), WIDE_PATHS as usize, "every path must survive");
    for row in out {
        assert_eq!(
            row["requests"], WIDE_BUCKETS,
            "{} lost buckets to truncation",
            row["path"]
        );
    }
}

/// 29 days — over [`M1_TRUSTED_SPAN_MS`] and under the `1h` tier's 30d
/// retention, so this resolves to `Tier::H1`: 696 one-hour buckets.
const COARSE_BUCKETS: i64 = 29 * 24;
const COARSE_RANGE: &str = "from=2023-11-14T00:00:00Z&to=2023-12-13T00:00:00Z";
/// Distinct paths per *coarse* bucket. Above the configured `topn` (50)
/// and below the compaction floor (200), i.e. squarely in the band a
/// `buckets × (topn + 1)` budget wrongly rules out. 150 × 696 = 104,400
/// rows: over the 100_000 fixed budget the scan was once capped at, and
/// under the tier-aware budget of 696 × 201 = 139,896.
const COARSE_PATHS: i64 = 150;

/// Compaction re-caps each coarse `(bucket, app)` group at
/// `effective_topn(topn)`, not at `topn` — a 1h bucket unions up to 60
/// minute buckets, so it legitimately holds more distinct paths than any
/// one of them. A budget of `buckets × (topn + 1)` therefore undersizes
/// the `1h`/`1d` tiers, and since `paths_range` orders by bucket ascending
/// the rows the SQL LIMIT drops are the *newest* ones.
#[tokio::test]
async fn a_compacted_1h_window_is_not_truncated_by_the_scan_limit() {
    let a = AnalyticsStore::open_in_memory().unwrap();
    let latency = digest_bytes(&[5.0]);
    let mut rows = Vec::with_capacity((COARSE_BUCKETS * COARSE_PATHS) as usize);
    for b in 0..COARSE_BUCKETS {
        for p in 0..COARSE_PATHS {
            rows.push(path_row(
                WIDE_FROM + b * HOUR_MS,
                "app-a",
                &format!("/p{p}"),
                1,
                latency.clone(),
            ));
        }
    }
    // These are compaction's output, so they go straight into the `1h`
    // tier — `flush_window` only ever writes `1m`.
    a.write_rows(Tier::H1, &[], &rows, &[]).unwrap();
    assert!(
        rows.len() as i64 > COARSE_BUCKETS * 51,
        "the fixture must exceed a topn-sized budget to be a regression test"
    );
    assert!(
        rows.len() > 100_000,
        "…and the old fixed 100_000-row budget too"
    );

    let (s, j) = get_with(
        state(Some(a)),
        &format!("/api/app/app-a/traffic/paths?{COARSE_RANGE}&limit=1000"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let out = j.as_array().unwrap();
    assert_eq!(out.len(), COARSE_PATHS as usize, "every path must survive");
    for row in out {
        assert_eq!(
            row["requests"], COARSE_BUCKETS,
            "{} lost buckets to truncation",
            row["path"]
        );
    }
}

/// Proves the incremental fold in [`top_paths`] is behaviourally identical
/// to the all-at-once merge it replaced: every bucket's latencies have to
/// reach the final digest, not just the last one folded in.
#[test]
fn top_paths_merges_the_latencies_of_every_bucket() {
    let rows = vec![
        path_row(BUCKET, "app-a", "/a", 1, digest_bytes(&ramp(1, 50))),
        path_row(
            BUCKET + 60_000,
            "app-a",
            "/a",
            1,
            digest_bytes(&ramp(51, 100)),
        ),
        path_row(
            BUCKET + 120_000,
            "app-a",
            "/a",
            1,
            digest_bytes(&ramp(101, 150)),
        ),
        path_row(
            BUCKET + 180_000,
            "app-a",
            "/a",
            1,
            digest_bytes(&ramp(151, 200)),
        ),
    ];
    let out = top_paths(rows, 10);
    assert_eq!(out.len(), 1);
    // 1..=200 across four buckets: a digest holding only the last bucket
    // (151..=200) would put p50 near 175, and one holding only the first
    // would put p95 near 48.
    assert!(
        (90.0..=112.0).contains(&out[0].p50),
        "p50 was {}, which is not the median of 1..=200",
        out[0].p50
    );
    assert!(
        (180.0..=200.0).contains(&out[0].p95),
        "p95 was {}, which is not the p95 of 1..=200",
        out[0].p95
    );
}

/// Pins the documented consequence of `DEFAULT_FROM`: omitting `from`
/// asks for all of history, which is a `1d`-tier question, so freshly
/// flushed `1m` rows are deliberately not visible until compaction has
/// rolled them up. This is behaviour, not a bug — but it is surprising
/// enough to be worth a test that fails loudly if either the default or
/// the tier thresholds are changed without thinking about it.
#[tokio::test]
async fn an_unbounded_range_reads_the_daily_tier() {
    let (s, j) = get("/api/app/app-a/traffic/paths").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j,
        serde_json::json!([]),
        "1m rows must not surface in a 1d-tier query"
    );

    let a = seeded();
    // The same rows written to the 1d tier are visible to that query.
    a.write_rows(
        Tier::D1,
        &[],
        &[path_row(
            BUCKET,
            "app-a",
            "/a",
            5,
            digest_bytes(&ramp(1, 10)),
        )],
        &[],
    )
    .unwrap();
    let (s, j) = get_with(state(Some(a)), "/api/app/app-a/traffic/paths").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j.as_array().unwrap().len(), 1);
    assert_eq!(j.as_array().unwrap()[0]["path"], "/a");
}
