use api::time::parse_bound;

#[test]
fn parses_the_go_layout() {
    // layout "2006-01-02T15:04:05Z"
    assert_eq!(parse_bound("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(
        parse_bound("2023-11-14T22:13:20Z").unwrap(),
        1_700_000_000_000
    );
}

#[test]
fn rejects_malformed_bounds() {
    for bad in [
        "2023-11-14",
        "2023-11-14T22:13:20",       // missing Z
        "2023-11-14T22:13:20+01:00", // offset not accepted by the Go layout
        "not-a-date",
        "",
    ] {
        assert!(parse_bound(bad).is_err(), "expected {bad:?} to be rejected");
    }
}

#[test]
fn cpu_usage_serializes_percent_as_string() {
    let v = api::types::CpuUsage {
        time: "1700000000000".into(),
        percent: "42.50".into(),
        human_friendly_time: None,
    };
    let j: serde_json::Value = serde_json::to_value(&v).unwrap();
    assert!(j["time"].is_string());
    assert!(
        j["percent"].is_string(),
        "percent MUST be a string in /history"
    );
    assert!(
        j.get("human_friendly_time").is_none(),
        "human_friendly_time must be omitted when absent"
    );
}

#[test]
fn mem_usage_serializes_numbers_and_camel_case_percent() {
    let v = api::types::MemUsage {
        time: "1700000000000".into(),
        total: 16_000_000_000,
        available: 8_000_000_000,
        used: 7_000_000_000,
        used_percent: 43.75,
        free: 1_000_000_000,
        human_friendly_time: None,
    };
    let j: serde_json::Value = serde_json::to_value(&v).unwrap();
    assert!(j["time"].is_string());
    assert!(j["total"].is_number());
    assert!(j["used"].is_number());
    assert!(j["free"].is_number());
    assert!(
        j["usedPercent"].is_number(),
        "usedPercent must be camelCase and numeric"
    );
    assert!(
        j.get("used_percent").is_none(),
        "snake_case key must not appear"
    );
}

#[test]
fn human_friendly_time_is_included_when_present() {
    let v = api::types::CpuUsage {
        time: "0".into(),
        percent: "1.00".into(),
        human_friendly_time: Some("1970-01-01T00:00:00Z".into()),
    };
    let j: serde_json::Value = serde_json::to_value(&v).unwrap();
    assert_eq!(j["human_friendly_time"], "1970-01-01T00:00:00Z");
}

fn test_state() -> std::sync::Arc<api::AppState> {
    let mut config = config::Config::load_for_test();
    // Override minimal fields for this test
    config.token = "secret".to_string();
    config.endpoint = "http://localhost".to_string();
    config.push_url = "http://localhost/api/v1/sentinel/push".to_string();
    config.bind_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    std::sync::Arc::new(api::AppState {
        auth_header: format!("Bearer {}", config.token),
        config: std::sync::Arc::new(config),
        store: store::Store::open_in_memory().unwrap(),
        sampler: std::sync::Arc::new(tokio::sync::Mutex::new(collector::HostSampler::new())),
        memory: std::sync::Arc::new(api::CachedMemory::new(
            collector::HostSampler::new().sample_memory(),
        )),
        history_queries: std::sync::Arc::new(tokio::sync::Semaphore::new(
            api::MAX_CONCURRENT_HISTORY_QUERIES,
        )),
        analytics: None,
    })
}

async fn status_for(app: axum::Router, uri: &str, token: Option<&str>) -> axum::http::StatusCode {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    let mut req = Request::builder().uri(uri);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    res.status()
}

#[tokio::test]
async fn health_and_version_need_no_token() {
    use axum::http::StatusCode;
    let state = test_state();
    assert_eq!(
        status_for(api::router(state.clone()), "/api/health", None).await,
        StatusCode::OK
    );
    assert_eq!(
        status_for(api::router(state), "/api/version", None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn require_token_middleware_runs_before_routing() {
    // The auth layer must reject an unauthenticated request even for a path
    // whose route isn't registered yet (this task's route modules are still
    // empty stubs) -- confirmed empirically that axum's .layer() runs before
    // route matching, so a missing/wrong token never falls through to a 404.
    use axum::http::StatusCode;
    let state = test_state();

    assert_eq!(
        status_for(api::router(state.clone()), "/api/cpu/history", None).await,
        StatusCode::UNAUTHORIZED,
        "missing token must be rejected before routing"
    );
    assert_eq!(
        status_for(api::router(state), "/api/cpu/history", Some("wrong-token")).await,
        StatusCode::UNAUTHORIZED,
        "incorrect token must be rejected"
    );
}
