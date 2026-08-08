use store::{Store, retention};

const DAY: i64 = 86_400_000;

#[test]
fn deletes_rows_older_than_retention() {
    // Test that rows older than retention AND not in the top 10 are deleted,
    // while the top 10 are always preserved (matching the Go implementation).
    let s = Store::open_in_memory().unwrap();
    let now = 100 * DAY;
    for d in 0..20 {
        s.insert_cpu(now - d * DAY, d as f64).unwrap();
    }
    let before = s.cpu_history(0, i64::MAX).unwrap().len();
    s.cleanup(7, now).unwrap();
    let after = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(before, 20, "should have 20 rows before cleanup");
    assert_eq!(
        after.len(),
        10,
        "should have 10 rows after cleanup (top 10 preserved)"
    );
    // Rows 11-20 (times now - 10*DAY through now - 19*DAY) are deleted
    assert!(
        after.iter().all(|r| r.time >= now - 10 * DAY),
        "oldest remaining row should be within top 10"
    );
}

#[test]
fn always_preserves_the_ten_most_recent_rows() {
    // Matches the Go cleanup, which protects the newest 10 rows per table
    // regardless of age, so a stalled agent never empties its own history.
    let s = Store::open_in_memory().unwrap();
    let now = 100 * DAY;
    for i in 0..10 {
        s.insert_cpu(1_000 + i, i as f64).unwrap(); // all far older than cutoff
    }
    s.cleanup(7, now).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 10);
}

#[test]
fn cleanup_covers_every_table() {
    let s = Store::open_in_memory().unwrap();
    let now = 100 * DAY;
    let old = now - 30 * DAY;
    for i in 0..15i64 {
        s.insert_cpu(old + i, 1.0).unwrap();
        s.insert_memory(&store::MemRow {
            time: old + i,
            total: 1,
            available: 1,
            used: 1,
            used_percent: 1.0,
            free: 1,
        })
        .unwrap();
        s.insert_container_batch(
            old + i,
            &[store::ContainerSample {
                container_id: "web".into(),
                cpu_percent: 1.0,
                mem_total: 1,
                mem_available: 1,
                mem_used: 1,
                mem_used_percent: 1.0,
                mem_free: 1,
            }],
        )
        .unwrap();
    }
    s.cleanup(7, now).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 10);
    assert_eq!(s.memory_history(0, i64::MAX).unwrap().len(), 10);
    assert_eq!(
        s.container_cpu_history("web", 0, i64::MAX).unwrap().len(),
        10
    );
    assert_eq!(
        s.container_memory_history("web", 0, i64::MAX)
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn downsample_collapses_old_samples_into_one_minute_averages() {
    let s = Store::open_in_memory().unwrap();
    let now = 10 * DAY;
    let old = now - 2 * DAY; // older than the 24h threshold
    let bucket = old - (old % retention::BUCKET_MS);
    // 12 samples at 5s spacing, all inside one minute bucket
    for i in 0..12 {
        s.insert_cpu(bucket + i * 5_000, 10.0 + i as f64).unwrap();
    }
    let collapsed = s.downsample(now).unwrap();
    // must report the 12 raw rows rolled up, not the 1 bucket row written —
    // Connection::changes() after a multi-statement batch would wrongly
    // report the latter.
    assert_eq!(collapsed, 12);

    let rows = s
        .cpu_history(bucket, bucket + retention::BUCKET_MS - 1)
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "one minute of old samples collapses to one row"
    );
    assert_eq!(rows[0].time, bucket);
    let expected = (10..22).map(|v| v as f64).sum::<f64>() / 12.0;
    assert!(
        (rows[0].percent - expected).abs() < 1e-9,
        "value is the bucket mean"
    );
}

#[test]
fn downsample_leaves_recent_samples_at_full_resolution() {
    let s = Store::open_in_memory().unwrap();
    let now = 10 * DAY;
    let recent = now - 3_600_000; // 1 hour old, inside the 24h window
    for i in 0..12 {
        s.insert_cpu(recent + i * 5_000, 1.0).unwrap();
    }
    s.downsample(now).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 12);
}

#[test]
fn downsample_is_idempotent() {
    let s = Store::open_in_memory().unwrap();
    let now = 10 * DAY;
    let old = now - 2 * DAY;
    let bucket = old - (old % retention::BUCKET_MS);
    for i in 0..12 {
        s.insert_cpu(bucket + i * 5_000, 5.0).unwrap();
    }
    s.downsample(now).unwrap();
    let first = s.cpu_history(0, i64::MAX).unwrap();
    s.downsample(now).unwrap();
    assert_eq!(first, s.cpu_history(0, i64::MAX).unwrap());
}

#[test]
fn downsample_keeps_container_series_separate() {
    let s = Store::open_in_memory().unwrap();
    let now = 10 * DAY;
    let old = now - 2 * DAY;
    let bucket = old - (old % retention::BUCKET_MS);
    for i in 0..6 {
        s.insert_container_batch(
            bucket + i * 5_000,
            &[
                store::ContainerSample {
                    container_id: "web".into(),
                    cpu_percent: 10.0,
                    mem_total: 1,
                    mem_available: 1,
                    mem_used: 1,
                    mem_used_percent: 1.0,
                    mem_free: 1,
                },
                store::ContainerSample {
                    container_id: "db".into(),
                    cpu_percent: 20.0,
                    mem_total: 1,
                    mem_available: 1,
                    mem_used: 1,
                    mem_used_percent: 1.0,
                    mem_free: 1,
                },
            ],
        )
        .unwrap();
    }
    s.downsample(now).unwrap();
    let web = s.container_cpu_history("web", 0, i64::MAX).unwrap();
    let db = s.container_cpu_history("db", 0, i64::MAX).unwrap();
    assert_eq!(web.len(), 1);
    assert_eq!(db.len(), 1);
    assert!((web[0].percent - 10.0).abs() < 1e-9);
    assert!((db[0].percent - 20.0).abs() < 1e-9);
}
