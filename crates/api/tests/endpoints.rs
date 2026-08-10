use std::sync::Arc;

use api::{AppState, router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn state(debug: bool) -> Arc<AppState> {
    let store = store::Store::open_in_memory().unwrap();
    store.insert_cpu(1_700_000_000_000, 42.5).unwrap();
    store.insert_cpu(1_700_000_005_000, 43.25).unwrap();
    store
        .insert_memory(&store::MemRow {
            time: 1_700_000_000_000,
            total: 16_000_000_000,
            available: 8_000_000_000,
            used: 7_000_000_000,
            used_percent: 43.75,
            free: 1_000_000_000,
        })
        .unwrap();

    let mut config = config::Config::load_for_test();
    config.debug = debug;
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

async fn get(app: axum::Router, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().uri(uri);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn get_text(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn internal_errors_do_not_expose_the_underlying_message() {
    let response = api::routes::cpu::internal_error("/app/db/metrics.sqlite is corrupt");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "Internal server error");
    assert!(!body.to_string().contains("metrics.sqlite"));
}

#[tokio::test]
async fn health_and_version_are_public_plain_text() {
    let (s, body) = get_text(router(state(false)), "/api/health").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, "ok");

    let (s, body) = get_text(router(state(false)), "/api/version").await;
    assert_eq!(s, StatusCode::OK);
    assert!(!body.is_empty());
}

#[tokio::test]
async fn protected_routes_require_the_bearer_token() {
    let (s, _) = get(router(state(false)), "/api/cpu/history", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _) = get(router(state(false)), "/api/cpu/history", Some("wrong")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _) = get(router(state(false)), "/api/cpu/history", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn cpu_history_returns_strings_ordered_ascending() {
    let (s, j) = get(router(state(false)), "/api/cpu/history", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    let arr = j.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["time"], "1700000000000");
    assert_eq!(arr[0]["percent"], "42.50", "percent is a 2dp string");
    assert_eq!(arr[1]["time"], "1700000005000");
    assert!(arr[0].get("human_friendly_time").is_none());
}

#[tokio::test]
async fn cpu_history_honours_from_and_to() {
    let app = router(state(false));
    let (s, j) = get(
        app,
        "/api/cpu/history?from=2023-11-14T22:13:21Z&to=2030-01-01T00:00:00Z",
        Some("secret"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        j.as_array().unwrap().len(),
        1,
        "only the later sample matches"
    );
}

#[tokio::test]
async fn empty_from_and_to_fall_back_to_the_defaults() {
    // `?from=&to=` deserializes to Some("") through axum's Query extractor,
    // not None. Go's ctx.Query returned "" for both absent and empty and
    // applied the defaults either way, so an empty value must return full
    // history, not 400.
    for (uri, expected) in [
        ("/api/cpu/history?from=&to=", 2),
        ("/api/cpu/history?from=", 2),
        ("/api/cpu/history?to=", 2),
        ("/api/memory/history?from=&to=", 1),
    ] {
        let (s, j) = get(router(state(false)), uri, Some("secret")).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        assert_eq!(
            j.as_array().unwrap().len(),
            expected,
            "{uri} must return full history"
        );
    }
}

#[tokio::test]
async fn cpu_history_rejects_bad_dates() {
    for uri in [
        "/api/cpu/history?from=nonsense",
        "/api/cpu/history?to=2023-13-45T99:99:99Z",
    ] {
        let (s, j) = get(router(state(false)), uri, Some("secret")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{uri}");
        assert!(j["error"].as_str().unwrap().contains("Invalid"));
    }
}

#[tokio::test]
async fn cpu_history_returns_empty_array_not_null() {
    let store = store::Store::open_in_memory().unwrap();
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
    let (s, j) = get(router(st), "/api/cpu/history", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j, serde_json::json!([]), "must be [] never null");
}

#[tokio::test]
async fn cpu_current_returns_percent_as_a_number() {
    let (s, j) = get(router(state(false)), "/api/cpu/current", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(j["time"].is_string());
    assert!(
        j["percent"].is_number(),
        "/api/cpu/current returns a NUMBER, unlike /api/cpu/history"
    );
}

#[tokio::test]
async fn memory_history_uses_numeric_fields_and_camel_case() {
    let (s, j) = get(router(state(false)), "/api/memory/history", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    let row = &j.as_array().unwrap()[0];
    assert_eq!(row["time"], "1700000000000");
    assert_eq!(row["total"], 16_000_000_000u64);
    assert_eq!(row["usedPercent"], 43.75);
    assert!(row.get("used_percent").is_none());
}

#[tokio::test]
async fn memory_current_is_internally_consistent() {
    let (s, j) = get(router(state(false)), "/api/memory/current", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(j["time"].is_string());
    assert!(j["total"].as_u64().unwrap() > 0);
    assert!(j["usedPercent"].is_number());
}

#[tokio::test]
async fn debug_mode_adds_human_friendly_time() {
    let (s, j) = get(router(state(true)), "/api/cpu/history", Some("secret")).await;
    assert_eq!(s, StatusCode::OK);
    let row = &j.as_array().unwrap()[0];
    assert_eq!(row["human_friendly_time"], "2023-11-14T22:13:20Z");
}
