use super::{
    container_disk_from_summary, has_volume_usage, only_volume_disk_usage, volume_sizes_from_items,
};
use bollard::models::{ContainerSummary, ContainerSummaryStateEnum, HealthStatusEnum, MountPoint};

// A `size: true` list yields the raw Docker id, but the disk series must be
// keyed on the same display name as cpu/memory (coolify.name label, else the
// Docker name, else id[:12]) — otherwise GET /api/container/{name}/disk/*
// and push correlation miss. Pin that here.
#[test]
fn container_disk_keys_on_display_name_not_raw_id() {
    let mut labels = std::collections::HashMap::new();
    labels.insert("coolify.name".to_string(), "postgres-db".to_string());
    let c = ContainerSummary {
        id: Some("a".repeat(64)),
        names: Some(vec!["/some-generated-name".to_string()]),
        labels: Some(labels),
        size_rw: Some(2048),
        mounts: Some(vec![MountPoint {
            source: Some("/var/lib/docker/volumes/x/_data".to_string()),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let disk = container_disk_from_summary(c);
    assert_eq!(disk.id, "postgres-db");
    assert_eq!(disk.writable_layer, 2048);
    assert_eq!(
        disk.mount_sources,
        vec!["/var/lib/docker/volumes/x/_data".to_string()]
    );
}

#[test]
fn container_disk_falls_back_to_truncated_id_not_full_hash() {
    let c = ContainerSummary {
        id: Some("abcdef0123456789deadbeef".to_string()),
        ..Default::default()
    };
    let disk = container_disk_from_summary(c);
    assert_eq!(disk.id, "abcdef012345");
}

#[test]
fn container_disk_empty_source_mounts_are_dropped() {
    let c = ContainerSummary {
        id: Some("id".to_string()),
        mounts: Some(vec![
            MountPoint {
                source: Some(String::new()),
                ..Default::default()
            },
            MountPoint {
                source: None,
                ..Default::default()
            },
            MountPoint {
                source: Some("/data".to_string()),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };
    let disk = container_disk_from_summary(c);
    assert_eq!(disk.mount_sources, vec!["/data".to_string()]);
}

// Coolify's PushServerUpdateJob keys container status on these exact
// lowercase strings (running / restarting / exited / paused / dead ...),
// and the push/list wire values come from these enums' Display impl. Pin
// the mapping so a bollard upgrade that renames a variant or changes its
// Display can't silently break status reporting to Coolify.
#[test]
fn container_state_wire_strings_match_docker() {
    use ContainerSummaryStateEnum::*;
    assert_eq!(CREATED.to_string(), "created");
    assert_eq!(RUNNING.to_string(), "running");
    assert_eq!(PAUSED.to_string(), "paused");
    assert_eq!(RESTARTING.to_string(), "restarting");
    assert_eq!(EXITED.to_string(), "exited");
    assert_eq!(REMOVING.to_string(), "removing");
    assert_eq!(DEAD.to_string(), "dead");
    // The empty state must serialize to "" (Go's empty string), NOT "empty".
    assert_eq!(EMPTY.to_string(), "");
}

#[test]
fn health_status_wire_strings_match_docker() {
    use HealthStatusEnum::*;
    assert_eq!(NONE.to_string(), "none");
    assert_eq!(STARTING.to_string(), "starting");
    assert_eq!(HEALTHY.to_string(), "healthy");
    assert_eq!(UNHEALTHY.to_string(), "unhealthy");
    assert_eq!(EMPTY.to_string(), "");
}

#[test]
fn volume_sizes_skip_unavailable_and_malformed_items() {
    let items = vec![
        serde_json::json!({
            "Name": "db",
            "Mountpoint": "/var/lib/docker/volumes/db/_data",
            "UsageData": { "RefCount": 1, "Size": 4096 }
        }),
        serde_json::json!({
            "Name": "remote",
            "Mountpoint": "/mnt/remote",
            "UsageData": { "RefCount": 1, "Size": -1 }
        }),
        serde_json::json!({ "Name": "no-usage", "Mountpoint": "/var/lib/docker/volumes/x/_data" }),
    ];
    let sizes = volume_sizes_from_items(&items);
    assert_eq!(sizes.len(), 1);
    assert_eq!(sizes["/var/lib/docker/volumes/db/_data"], 4096);
}

fn request_to(uri: &str) -> String {
    let mut request =
        bollard::BollardRequest::new(bollard::body_stream(futures_util::stream::empty()));
    *request.uri_mut() = uri.parse().unwrap();
    only_volume_disk_usage(request).uri().to_string()
}

// Without `type=volume`, every `/system/df` call also makes dockerd size all
// images, layers, containers, and the build cache (coollabsio/coolify#12518).
#[test]
fn system_df_requests_only_volume_usage() {
    assert_eq!(
        request_to("http://localhost/v1.53/system/df?verbose=true"),
        "http://localhost/v1.53/system/df?verbose=true&type=volume"
    );
    assert_eq!(
        request_to("http://localhost/v1.53/system/df"),
        "http://localhost/v1.53/system/df?type=volume"
    );
    assert_eq!(
        request_to("http://localhost/v1.53/containers/json?all=true&size=true"),
        "http://localhost/v1.53/containers/json?all=true&size=true"
    );
}

// Docker 27 (API 1.46) answers `/system/df` in the old shape, which bollard
// cannot parse, so Sentinel must not ask it to walk the volumes.
#[test]
fn volume_usage_needs_api_1_52() {
    assert!(has_volume_usage(Some("1.52")));
    assert!(has_volume_usage(Some("1.56")));
    assert!(has_volume_usage(Some("2.0")));
    assert!(!has_volume_usage(Some("1.46")));
    assert!(!has_volume_usage(Some("1.9")));
    assert!(!has_volume_usage(Some("garbage")));
    assert!(!has_volume_usage(None));
}
