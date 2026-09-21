use super::CachedMemory;
use store::MemRow;

fn memory(used: u64) -> MemRow {
    MemRow {
        time: 0,
        total: 100,
        available: 100 - used,
        used,
        used_percent: used as f64,
        free: 100 - used,
    }
}

#[test]
fn cached_memory_returns_the_latest_snapshot() {
    let cache = CachedMemory::new(memory(10));
    assert_eq!(cache.get().used, 10);

    cache.set(memory(25));

    assert_eq!(cache.get().used, 25);
}

/// The generated spec must document every route the binary can serve.
/// Guards against a route being registered without a `#[utoipa::path]`
/// annotation (which would silently drop it from the docs).
#[test]
fn openapi_documents_every_route() {
    let api = super::openapi_document();
    let paths: Vec<&str> = api.paths.paths.keys().map(String::as_str).collect();

    // `mut` is only exercised when the traffic feature extends the list.
    #[allow(unused_mut)]
    let mut expected = vec![
        "/api/health",
        "/api/version",
        "/api/cpu/current",
        "/api/cpu/history",
        "/api/memory/current",
        "/api/memory/history",
        "/api/disk/current",
        "/api/disk/history",
        "/api/container/{containerId}/cpu/history",
        "/api/container/{containerId}/memory/history",
        "/api/container/{containerId}/disk/current",
        "/api/container/{containerId}/disk/history",
        // DEBUG-gated at runtime, always documented.
        "/api/stats",
    ];
    #[cfg(feature = "traffic")]
    expected.extend([
        "/api/traffic/apps",
        "/api/traffic/overview",
        "/api/traffic/paths",
        "/api/traffic/breakdown/{dimension}",
        "/api/traffic/series",
        "/api/traffic/dashboard",
        "/api/traffic/attribution",
        "/api/app/{uuid}/traffic/overview",
        "/api/app/{uuid}/traffic/paths",
        "/api/app/{uuid}/traffic/breakdown/{dimension}",
        "/api/app/{uuid}/traffic/series",
        "/api/app/{uuid}/traffic/dashboard",
    ]);

    for p in &expected {
        assert!(paths.contains(p), "spec is missing {p}");
    }
    assert_eq!(paths.len(), expected.len(), "unexpected extra paths: {paths:?}");

    // Bearer auth is the global default, with the docs-visible exceptions
    // explicitly opted out.
    let components = api.components.as_ref().expect("components present");
    assert!(
        components.security_schemes.contains_key("bearerAuth"),
        "bearerAuth security scheme missing"
    );
    for public in ["/api/health", "/api/version"] {
        let item = &api.paths.paths[public];
        let op = item.get.as_ref().expect("GET operation");
        let security = op.security.as_ref().expect("explicit security override");
        assert!(
            security
                .iter()
                .all(|req| serde_json::to_value(req).unwrap() == serde_json::json!({})),
            "{public} must be publicly accessible (empty security requirement)"
        );
    }
}
