//! Asserts the JSON *types* the API emits, independently of the handlers.
//! This is the last line of defence for the frozen wire format: if a future
//! change makes `percent` numeric in /history, this fails.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn fetch(uri: &str) -> serde_json::Value {
    let store = store::Store::open_in_memory().unwrap();
    store.insert_cpu(1_700_000_000_000, 42.5).unwrap();
    store
        .insert_memory(&store::MemRow {
            time: 1_700_000_000_000,
            total: 100,
            available: 40,
            used: 60,
            used_percent: 60.0,
            free: 40,
        })
        .unwrap();
    store
        .insert_container_batch(
            1_700_000_000_000,
            &[store::ContainerSample {
                container_id: "web".into(),
                cpu_percent: 1.0,
                mem_total: 10,
                mem_available: 4,
                mem_used: 6,
                mem_used_percent: 60.0,
                mem_free: 4,
            }],
        )
        .unwrap();

    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    let state = Arc::new(api::AppState {
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
        analytics: None,
        geoip_attribution: Arc::new(std::sync::RwLock::new(None)),
    });

    let res = api::router(state)
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
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn frozen_wire_types() {
    let cpu = fetch("/api/cpu/history").await;
    let row = &cpu.as_array().unwrap()[0];
    assert!(row["time"].is_string(), "cpu history time must be a string");
    assert!(
        row["percent"].is_string(),
        "cpu history percent must be a STRING"
    );

    let cur = fetch("/api/cpu/current").await;
    assert!(cur["time"].is_string());
    assert!(
        cur["percent"].is_number(),
        "cpu current percent must be a NUMBER"
    );

    for uri in ["/api/memory/history", "/api/container/web/memory/history"] {
        let mem = fetch(uri).await;
        let row = &mem.as_array().unwrap()[0];
        assert!(row["time"].is_string(), "{uri}: time");
        assert!(row["total"].is_number(), "{uri}: total");
        assert!(row["used"].is_number(), "{uri}: used");
        assert!(row["free"].is_number(), "{uri}: free");
        assert!(row["available"].is_number(), "{uri}: available");
        assert!(
            row["usedPercent"].is_number(),
            "{uri}: usedPercent camelCase"
        );
        assert!(
            row.get("used_percent").is_none(),
            "{uri}: no snake_case key"
        );
    }

    let ccpu = fetch("/api/container/web/cpu/history").await;
    let row = &ccpu.as_array().unwrap()[0];
    assert!(row["percent"].is_string());
    assert!(row.get("container_id").is_none());
}
