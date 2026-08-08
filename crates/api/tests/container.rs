use std::sync::Arc;

use api::{router, AppState};
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
        config: Arc::new(config),
        store,
        sampler: Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
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
    (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
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
async fn container_id_is_sanitised_to_alphanumerics() {
    // "we/b-!" sanitises to "web", matching the stored id
    let (s, j) = get("/api/container/we%2Fb-!/cpu/history").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j.as_array().unwrap().len(), 1);
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
async fn stats_route_is_absent_unless_debug() {
    // state() builds a non-debug config
    let (s, _) = get("/api/stats").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
