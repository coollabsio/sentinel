use std::sync::Arc;

use api::{AppState, router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn state() -> Arc<AppState> {
    let store = store::Store::open_in_memory().unwrap();
    store
        .insert_container_batch(
            1_700_000_000_000,
            &[store::ContainerSample {
                container_id: "web".into(),
                cpu_percent: 12.5,
                mem_total: 1_000,
                mem_available: 400,
                mem_used: 600,
                mem_used_percent: 60.0,
                mem_free: 400,
            }],
        )
        .unwrap();

    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store,
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: Arc::new(api::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_ANALYTICS_QUERIES,
        )),
        analytics: None,
        geoip_attribution: std::sync::Arc::new(std::sync::RwLock::new(None)),
    })
}

async fn get(uri: &str) -> (StatusCode, serde_json::Value) {
    let res = router(state())
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

#[tokio::test]
async fn container_cpu_history_returns_rows_without_container_id() {
    let (s, j) = get("/api/container/web/cpu/history").await;
    assert_eq!(s, StatusCode::OK);
    let row = &j.as_array().unwrap()[0];
    assert_eq!(row["time"], "1700000000000");
    assert_eq!(row["percent"], "12.50");
    assert!(
        row.get("container_id").is_none(),
        "container_id is not part of the response"
    );
}

#[tokio::test]
async fn container_memory_history_returns_numeric_fields() {
    let (s, j) = get("/api/container/web/memory/history").await;
    assert_eq!(s, StatusCode::OK);
    let row = &j.as_array().unwrap()[0];
    assert_eq!(row["used"], 600);
    assert_eq!(row["usedPercent"], 60.0);
}

#[tokio::test]
async fn distinct_punctuated_container_names_keep_separate_histories() {
    let store = store::Store::open_in_memory().unwrap();
    store
        .insert_container_batch(
            1_700_000_000_000,
            &[
                store::ContainerSample {
                    container_id: "postgres-db".into(),
                    cpu_percent: 7.0,
                    mem_total: 1,
                    mem_available: 1,
                    mem_used: 1,
                    mem_used_percent: 1.0,
                    mem_free: 1,
                },
                store::ContainerSample {
                    container_id: "postgres_db".into(),
                    cpu_percent: 9.0,
                    mem_total: 1,
                    mem_available: 1,
                    mem_used: 1,
                    mem_used_percent: 1.0,
                    mem_free: 1,
                },
            ],
        )
        .unwrap();
    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    let st = Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store,
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: Arc::new(api::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_ANALYTICS_QUERIES,
        )),
        analytics: None,
        geoip_attribution: std::sync::Arc::new(std::sync::RwLock::new(None)),
    });
    for (name, expected) in [("postgres-db", "7.00"), ("postgres_db", "9.00")] {
        let res = router(st.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/api/container/{name}/cpu/history"))
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(j.as_array().unwrap().len(), 1, "{name}");
        assert_eq!(j.as_array().unwrap()[0]["percent"], expected, "{name}");
    }
}

#[tokio::test]
async fn unknown_container_returns_empty_array() {
    let (s, j) = get("/api/container/nosuch/cpu/history").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j, serde_json::json!([]));
}

#[tokio::test]
async fn container_history_rejects_bad_dates() {
    let (s, _) = get("/api/container/web/cpu/history?from=bogus").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn container_history_default_from_is_one_second_not_zero() {
    // "1970-01-01T00:00:00Z" (the HOST endpoints' default, Task 8) = 0ms.
    // "1970-01-01T00:00:01Z" (this endpoint's default) = 1000ms. A row at
    // 500ms falls strictly between the two: excluded under this endpoint's
    // real default, but would be wrongly included if DEFAULT_FROM ever
    // regressed to ":00Z". A row at exactly 1000ms must survive (inclusive
    // bound). This pins the asymmetry down; every other test in this file
    // uses timestamps far past both defaults and would not catch a regression.
    let store = store::Store::open_in_memory().unwrap();
    for (time, id) in [(500i64, "before"), (1_000i64, "atboundary")] {
        store
            .insert_container_batch(
                time,
                &[store::ContainerSample {
                    container_id: id.into(),
                    cpu_percent: 1.0,
                    mem_total: 1,
                    mem_available: 1,
                    mem_used: 1,
                    mem_used_percent: 1.0,
                    mem_free: 1,
                }],
            )
            .unwrap();
    }
    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    let st = Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store,
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: Arc::new(api::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_ANALYTICS_QUERIES,
        )),
        analytics: None,
        geoip_attribution: std::sync::Arc::new(std::sync::RwLock::new(None)),
    });

    let get_st = |uri: &'static str, st: Arc<AppState>| async move {
        let res = router(st)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("Authorization", "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };

    let before = get_st("/api/container/before/cpu/history", st.clone()).await;
    assert_eq!(
        before.as_array().unwrap().len(),
        0,
        "a row at 500ms must be excluded by the :01Z default (1000ms)"
    );

    let at_boundary = get_st("/api/container/atboundary/cpu/history", st).await;
    assert_eq!(
        at_boundary.as_array().unwrap().len(),
        1,
        "a row at exactly 1000ms must be included (inclusive lower bound)"
    );
}

#[tokio::test]
async fn stats_route_is_absent_unless_debug() {
    // state() builds a non-debug config
    let (s, _) = get("/api/stats").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stats_route_reports_row_counts_and_live_memory_when_debug() {
    // state()'s Config::load_for_test() hardcodes debug: false, so this
    // builds its own debug-enabled state directly rather than going through
    // the shared get()/state() helpers.
    let store = store::Store::open_in_memory().unwrap();
    store.insert_cpu(1_000, 1.0).unwrap();
    store.insert_cpu(2_000, 2.0).unwrap();

    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    config.debug = true;
    let st = Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store,
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: Arc::new(api::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics_queries: Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_ANALYTICS_QUERIES,
        )),
        analytics: None,
        geoip_attribution: std::sync::Arc::new(std::sync::RwLock::new(None)),
    });

    let res = router(st)
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .header("Authorization", "Bearer secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        j["row_count"], 2,
        "the two inserted cpu_usage rows must be counted"
    );
    assert!(j["storage_usage_kb"].is_string());
    assert!(j["storage_usage_mb"].is_string());
    // memory_usage must come from the live sampler, not a hardcoded stub --
    // total is always > 0 on any real machine.
    assert!(j["memory_usage"]["total"].as_u64().unwrap() > 0);
    assert!(j["memory_usage"]["usedPercent"].is_number());
    let cpu_table = j["table_sizes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["table_name"] == "cpu_usage")
        .expect("cpu_usage must appear in table_sizes");
    assert_eq!(cpu_table["row_count"], 2);
}
