use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use store::{ContainerDiskSample, ContainerSample, DiskSample, MemRow, Store};
use tower::ServiceExt;

use crate::AppState;

fn mem_row(time: i64, used: u64) -> MemRow {
    MemRow {
        time,
        total: 100,
        available: 100 - used,
        used,
        used_percent: used as f64,
        free: 100 - used,
    }
}

fn disk(mount: &str, used: u64) -> DiskSample {
    DiskSample {
        mount: mount.into(),
        total: 100,
        used,
        available: 100 - used,
        used_percent: used as f64,
    }
}

fn container(id: &str, cpu: f64, mem_used: u64) -> ContainerSample {
    ContainerSample {
        container_id: id.into(),
        cpu_percent: cpu,
        mem_total: 100,
        mem_available: 100 - mem_used,
        mem_used,
        mem_used_percent: mem_used as f64,
        mem_free: 100 - mem_used,
    }
}

fn container_disk(id: &str, writable: u64) -> ContainerDiskSample {
    ContainerDiskSample {
        container_id: id.into(),
        writable_layer: writable,
        volumes_total: writable * 2,
    }
}

fn state(store: Store) -> Arc<AppState> {
    let mut config = config::Config::load_for_test();
    config.token = "secret".into();
    Arc::new(AppState {
        auth_header: format!("Bearer {}", config.token),
        config: Arc::new(config),
        store,
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
        analytics: None,
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

/// `/api/summary` returns the latest row of each host series in the shapes the
/// standalone `current` endpoints use, nested under cpu / memory / disk.
#[tokio::test]
async fn summary_returns_the_latest_of_each_series() {
    let store = Store::open_in_memory().unwrap();
    store.insert_cpu(1000, 10.0).unwrap();
    store.insert_cpu(2000, 42.5).unwrap(); // newer wins
    store.insert_memory(&mem_row(1000, 20)).unwrap();
    store.insert_memory(&mem_row(3000, 55)).unwrap(); // newer wins
    // Two mounts share the newest cycle timestamp; an older cycle must not leak.
    store.insert_disk_batch(500, &[disk("/", 5)]).unwrap();
    store
        .insert_disk_batch(4000, &[disk("/", 30), disk("/data", 70)])
        .unwrap();

    let (s, j) = get_with(state(store), "/api/summary").await;
    assert_eq!(s, StatusCode::OK);

    // cpu matches /api/cpu/current: string time, numeric percent.
    assert_eq!(j["cpu"]["time"], "2000");
    assert_eq!(j["cpu"]["percent"], 42.5);

    assert_eq!(j["memory"]["time"], "3000");
    assert_eq!(j["memory"]["used"], 55);
    assert_eq!(j["memory"]["usedPercent"], 55.0);

    let disks = j["disk"].as_array().unwrap();
    assert_eq!(disks.len(), 2, "only the newest cycle's mounts");
    assert_eq!(disks[0]["mount"], "/");
    assert_eq!(disks[0]["time"], "4000");
    assert_eq!(disks[1]["mount"], "/data");
    assert_eq!(disks[1]["used"], 70);
}

/// Every key is `null` when its table is empty.
#[tokio::test]
async fn summary_nulls_empty_series() {
    let (s, j) = get_with(state(Store::open_in_memory().unwrap()), "/api/summary").await;
    assert_eq!(s, StatusCode::OK);
    assert!(j["cpu"].is_null());
    assert!(j["memory"].is_null());
    assert!(j["disk"].is_null());
}

/// `/api/containers/current` returns one row per container carrying the latest
/// sample of each metric, keyed and joined by id.
#[tokio::test]
async fn containers_current_returns_latest_per_container() {
    let store = Store::open_in_memory().unwrap();
    // Two cycles: the second must win for both containers.
    store
        .insert_container_batch(1000, &[container("alpha", 5.0, 10), container("beta", 1.0, 2)])
        .unwrap();
    store
        .insert_container_batch(2000, &[container("alpha", 88.0, 40), container("beta", 3.0, 6)])
        .unwrap();
    // alpha also has a disk sample at a later time than its cpu/memory.
    store
        .insert_container_disk_batch(3000, &[container_disk("alpha", 12)])
        .unwrap();

    let (s, j) = get_with(state(store), "/api/containers/current").await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 2, "one row per container, sorted by id");

    let alpha = &rows[0];
    assert_eq!(alpha["id"], "alpha");
    // Container cpu reuses the history shape: percent is a string.
    assert_eq!(alpha["cpu"]["time"], "2000");
    assert_eq!(alpha["cpu"]["percent"], "88.00");
    assert_eq!(alpha["memory"]["time"], "2000");
    assert_eq!(alpha["memory"]["used"], 40);
    assert_eq!(alpha["disk"]["time"], "3000");
    assert_eq!(alpha["disk"]["writableLayer"], 12);
    assert_eq!(alpha["disk"]["volumesTotal"], 24);
    // Top-level time is the newest across the three (disk at 3000).
    assert_eq!(alpha["time"], 3000);

    let beta = &rows[1];
    assert_eq!(beta["id"], "beta");
    assert_eq!(beta["cpu"]["percent"], "3.00");
    // beta has no disk sample recorded.
    assert!(beta["disk"].is_null());
    assert_eq!(beta["time"], 2000);
}

/// A container with only a disk sample still appears, with cpu/memory `null`.
#[tokio::test]
async fn containers_current_includes_disk_only_container() {
    let store = Store::open_in_memory().unwrap();
    store
        .insert_container_disk_batch(1500, &[container_disk("lonely", 7)])
        .unwrap();

    let (s, j) = get_with(state(store), "/api/containers/current").await;
    assert_eq!(s, StatusCode::OK);
    let rows = j.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], "lonely");
    assert!(rows[0]["cpu"].is_null());
    assert!(rows[0]["memory"].is_null());
    assert_eq!(rows[0]["disk"]["writableLayer"], 7);
    assert_eq!(rows[0]["time"], 1500);
}

/// An empty database yields an empty array, not an error.
#[tokio::test]
async fn containers_current_empty_db_is_empty_array() {
    let (s, j) = get_with(
        state(Store::open_in_memory().unwrap()),
        "/api/containers/current",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j, serde_json::json!([]));
}

/// Both endpoints sit under the global auth middleware: no bearer token → 401.
#[tokio::test]
async fn bulk_endpoints_require_auth() {
    for uri in ["/api/summary", "/api/containers/current"] {
        let res = crate::router(state(Store::open_in_memory().unwrap()))
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}
