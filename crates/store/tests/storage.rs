use store::{ContainerDiskSample, DiskSample, Store};

fn disk(mount: &str, used_percent: f64) -> DiskSample {
    DiskSample {
        mount: mount.into(),
        total: 100,
        used: 60,
        available: 40,
        used_percent,
    }
}

#[test]
fn round_trips_disk_and_reports_latest_per_mount() {
    let s = Store::open_in_memory().unwrap();
    s.insert_disk_batch(1_000, &[disk("/", 10.0), disk("/data", 20.0)])
        .unwrap();
    s.insert_disk_batch(2_000, &[disk("/", 30.0), disk("/data", 40.0)])
        .unwrap();

    // History returns every stored row, ordered by (time, mount).
    let hist = s.disk_history(0, i64::MAX).unwrap();
    assert_eq!(hist.len(), 4);
    assert_eq!(hist[0].time, 1_000);
    assert_eq!(hist[0].mount, "/");

    // Latest returns only the most recent cycle (time == 2000), one per mount.
    let latest = s.disk_latest().unwrap();
    assert_eq!(latest.len(), 2);
    assert!(latest.iter().all(|r| r.time == 2_000));
    let root = latest.iter().find(|r| r.mount == "/").unwrap();
    assert!((root.used_percent - 30.0).abs() < f64::EPSILON);
    assert_eq!(root.total, 100);
    assert_eq!(root.used, 60);
    assert_eq!(root.available, 40);
}

#[test]
fn disk_insert_is_upsert_on_time_and_mount() {
    let s = Store::open_in_memory().unwrap();
    s.insert_disk_batch(1_000, &[disk("/", 10.0)]).unwrap();
    s.insert_disk_batch(1_000, &[disk("/", 99.0)]).unwrap();
    let rows = s.disk_history(0, i64::MAX).unwrap();
    assert_eq!(rows.len(), 1);
    assert!((rows[0].used_percent - 99.0).abs() < f64::EPSILON);
}

#[test]
fn round_trips_container_disk_and_scopes_by_id() {
    let s = Store::open_in_memory().unwrap();
    let samples = vec![
        ContainerDiskSample {
            container_id: "web".into(),
            writable_layer: 1_000,
            volumes_total: 5_000,
        },
        ContainerDiskSample {
            container_id: "db".into(),
            writable_layer: 2_000,
            volumes_total: 9_000,
        },
    ];
    s.insert_container_disk_batch(1_000, &samples).unwrap();
    s.insert_container_disk_batch(
        2_000,
        &[ContainerDiskSample {
            container_id: "web".into(),
            writable_layer: 1_500,
            volumes_total: 6_000,
        }],
    )
    .unwrap();

    let web = s.container_disk_history("web", 0, i64::MAX).unwrap();
    assert_eq!(web.len(), 2);
    assert_eq!(web[0].writable_layer, 1_000);
    assert_eq!(web[1].volumes_total, 6_000);

    // latest_one returns the most recent row for that container
    let latest_web = s.container_disk_latest_one("web").unwrap().unwrap();
    assert_eq!(latest_web.time, 2_000);
    assert_eq!(latest_web.writable_layer, 1_500);

    // latest (all containers) selects only the newest cycle's rows
    let latest = s.container_disk_latest().unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].container_id, "web");

    // scoping must not leak across ids
    assert!(s.container_disk_latest_one("nope").unwrap().is_none());
    assert!(
        s.container_disk_history("nope", 0, i64::MAX)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn empty_disk_batches_are_noops() {
    let s = Store::open_in_memory().unwrap();
    s.insert_disk_batch(1_000, &[]).unwrap();
    s.insert_container_disk_batch(1_000, &[]).unwrap();
    assert!(s.disk_latest().unwrap().is_empty());
    assert!(s.container_disk_latest().unwrap().is_empty());
}

#[test]
fn downsampling_collapses_aged_storage_rows_per_entity() {
    let s = Store::open_in_memory().unwrap();
    // Two aged rows for the same mount inside one 1-minute bucket must collapse
    // into a single averaged row; a fresh row (< 24h old) is left untouched.
    let now = 100 * 24 * 60 * 60 * 1_000; // 100 days, well past the 24h window
    let aged_a = now - 40 * 24 * 60 * 60 * 1_000;
    let aged_b = aged_a + 1_000; // same minute bucket as aged_a

    s.insert_disk_batch(aged_a, &[disk("/", 10.0)]).unwrap();
    s.insert_disk_batch(aged_b, &[disk("/", 20.0)]).unwrap();
    s.insert_container_disk_batch(
        aged_a,
        &[ContainerDiskSample {
            container_id: "web".into(),
            writable_layer: 100,
            volumes_total: 1_000,
        }],
    )
    .unwrap();
    s.insert_container_disk_batch(
        aged_b,
        &[ContainerDiskSample {
            container_id: "web".into(),
            writable_layer: 300,
            volumes_total: 3_000,
        }],
    )
    .unwrap();

    s.downsample(now).unwrap();

    let disks = s.disk_history(0, i64::MAX).unwrap();
    assert_eq!(disks.len(), 1, "two aged disk rows collapse to one bucket");
    assert!((disks[0].used_percent - 15.0).abs() < 0.01, "averaged");

    let cds = s.container_disk_history("web", 0, i64::MAX).unwrap();
    assert_eq!(
        cds.len(),
        1,
        "two aged container rows collapse to one bucket"
    );
    assert_eq!(cds[0].writable_layer, 200, "integer average of 100 and 300");
    assert_eq!(cds[0].volumes_total, 2_000);
}
