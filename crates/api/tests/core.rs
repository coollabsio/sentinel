use api::time::parse_bound;

#[test]
fn parses_the_go_layout() {
    // layout "2006-01-02T15:04:05Z"
    assert_eq!(parse_bound("1970-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(parse_bound("2023-11-14T22:13:20Z").unwrap(), 1_700_000_000_000);
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
    assert!(j["percent"].is_string(), "percent MUST be a string in /history");
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
    assert!(j.get("used_percent").is_none(), "snake_case key must not appear");
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
