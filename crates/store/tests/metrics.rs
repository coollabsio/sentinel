use store::{ContainerSample, MemRow, Store};

fn mem(time: i64) -> MemRow {
    MemRow {
        time,
        total: 16_000_000_000,
        available: 8_000_000_000,
        used: 7_000_000_000,
        used_percent: 43.75,
        free: 1_000_000_000,
    }
}

#[test]
fn round_trips_cpu() {
    let s = Store::open_in_memory().unwrap();
    s.insert_cpu(1_000, 12.34).unwrap();
    s.insert_cpu(2_000, 56.78).unwrap();
    let rows = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].time, 1_000);
    assert!((rows[0].percent - 12.34).abs() < f64::EPSILON);
}

#[test]
fn cpu_history_is_ordered_ascending_and_range_filtered() {
    let s = Store::open_in_memory().unwrap();
    for t in [3_000, 1_000, 2_000] {
        s.insert_cpu(t, 1.0).unwrap();
    }
    let rows = s.cpu_history(1_500, 3_000).unwrap();
    assert_eq!(
        rows.iter().map(|r| r.time).collect::<Vec<_>>(),
        vec![2_000, 3_000]
    );
}

#[test]
fn cpu_insert_is_upsert_on_time() {
    let s = Store::open_in_memory().unwrap();
    s.insert_cpu(1_000, 1.0).unwrap();
    s.insert_cpu(1_000, 9.0).unwrap();
    let rows = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(rows.len(), 1);
    assert!((rows[0].percent - 9.0).abs() < f64::EPSILON);
}

#[test]
fn round_trips_memory() {
    let s = Store::open_in_memory().unwrap();
    s.insert_memory(&mem(1_000)).unwrap();
    let rows = s.memory_history(0, i64::MAX).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].total, 16_000_000_000);
    assert!((rows[0].used_percent - 43.75).abs() < f64::EPSILON);
}

#[test]
fn container_batch_writes_cpu_and_memory() {
    let s = Store::open_in_memory().unwrap();
    let samples = vec![
        ContainerSample {
            container_id: "web".into(),
            cpu_percent: 10.0,
            mem_total: 100,
            mem_available: 40,
            mem_used: 60,
            mem_used_percent: 60.0,
            mem_free: 40,
        },
        ContainerSample {
            container_id: "db".into(),
            cpu_percent: 20.0,
            mem_total: 200,
            mem_available: 100,
            mem_used: 100,
            mem_used_percent: 50.0,
            mem_free: 100,
        },
    ];
    s.insert_container_batch(5_000, &samples).unwrap();

    let web = s.container_cpu_history("web", 0, i64::MAX).unwrap();
    assert_eq!(web.len(), 1);
    assert!((web[0].percent - 10.0).abs() < f64::EPSILON);

    let db = s.container_memory_history("db", 0, i64::MAX).unwrap();
    assert_eq!(db.len(), 1);
    assert_eq!(db[0].used, 100);

    // container scoping must not leak across ids
    assert!(s.container_cpu_history("nope", 0, i64::MAX).unwrap().is_empty());
}

#[test]
fn empty_batch_is_a_noop() {
    let s = Store::open_in_memory().unwrap();
    s.insert_container_batch(1_000, &[]).unwrap();
    assert!(s.container_cpu_history("x", 0, i64::MAX).unwrap().is_empty());
}

#[test]
fn opening_twice_is_idempotent() {
    let dir = std::env::temp_dir().join(format!("sentinel-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    {
        let s = Store::open(&path).unwrap();
        s.insert_cpu(1_000, 1.0).unwrap();
    }
    {
        let s = Store::open(&path).unwrap();
        assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 1);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn opens_a_bare_filename_with_no_directory_component() {
    // Path::parent() on a single-component relative path returns Some(""),
    // not None. Store::open must not choke on that when trying to create /
    // chmod the (nonexistent) parent directory. Uses a unique name directly
    // in the test binary's cwd rather than changing it, so this stays safe
    // under parallel test execution.
    let name = format!("sentinel-test-bare-{}.sqlite", std::process::id());
    let path = std::path::PathBuf::from(&name);
    let _ = std::fs::remove_file(&path);

    let result = Store::open(&path);
    let ok = result.is_ok();
    std::fs::remove_file(&path).ok();

    assert!(ok, "Store::open must accept a bare filename: {:?}", result.err());
}
