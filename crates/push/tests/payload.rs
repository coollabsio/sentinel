#[test]
fn root_filesystem_usage_is_a_percentage() {
    let pct = push::fs_usage::root_used_percentage().unwrap();
    assert!(pct <= 100, "got {pct}");
}

#[test]
fn snapshot_metadata_reports_completeness() {
    let complete = push::snapshot_metadata(0);
    assert_eq!(complete["version"], 1);
    assert_eq!(complete["complete"], true);
    assert_eq!(complete["inspection_failures"], 0);

    let partial = push::snapshot_metadata(3);
    assert_eq!(partial["complete"], false);
    assert_eq!(partial["inspection_failures"], 3);
}

#[test]
fn container_entry_serializes_expected_keys() {
    let c = push::Container {
        time: "2023-11-14T22:13:20Z".into(),
        id: "abc".into(),
        image: "nginx".into(),
        name: "web".into(),
        state: "running".into(),
        labels: std::collections::HashMap::from([("k".to_string(), "v".to_string())]),
        health_status: "healthy".into(),
    };
    let j = serde_json::to_value(&c).unwrap();
    for key in [
        "time", "id", "image", "name", "state", "labels", "health_status",
    ] {
        assert!(j.get(key).is_some(), "missing key {key}");
    }
    assert_eq!(j["labels"]["k"], "v");
}
