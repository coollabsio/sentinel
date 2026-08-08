use store::Store;

/// Recreates the exact legacy schema from pkg/db/database.go.
fn legacy_db(path: &std::path::Path) {
    let c = rusqlite::Connection::open(path).unwrap();
    c.execute_batch(
        r#"
        CREATE TABLE cpu_usage (time VARCHAR, percent VARCHAR, PRIMARY KEY (time));
        CREATE TABLE memory_usage (
            time VARCHAR, total VARCHAR, available VARCHAR,
            used VARCHAR, usedPercent VARCHAR, free VARCHAR, PRIMARY KEY (time));
        CREATE TABLE container_cpu_usage (
            time VARCHAR, container_id VARCHAR, percent VARCHAR,
            PRIMARY KEY (time, container_id));
        CREATE TABLE container_memory_usage (
            time VARCHAR, container_id VARCHAR, total VARCHAR, available VARCHAR,
            used VARCHAR, usedPercent VARCHAR, free VARCHAR,
            PRIMARY KEY (time, container_id));
        CREATE TABLE container_logs (time VARCHAR, container_id VARCHAR, log VARCHAR);

        INSERT INTO cpu_usage VALUES ('1700000000000', '42.50');
        INSERT INTO cpu_usage VALUES ('1700000005000', '43.25');
        INSERT INTO memory_usage VALUES
            ('1700000000000','16000000000','8000000000','7000000000','43.75','1000000000');
        INSERT INTO container_cpu_usage VALUES ('1700000000000', 'web', '10.00');
        INSERT INTO container_memory_usage VALUES
            ('1700000000000','web','100','40','60','60.00','40');
        "#,
    )
    .unwrap();
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sentinel-mig-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn migrates_legacy_text_schema_preserving_data() {
    let dir = tmpdir("basic");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);

    let s = Store::open(&path).unwrap();

    let cpu = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(cpu.len(), 2);
    assert_eq!(cpu[0].time, 1_700_000_000_000);
    assert!((cpu[0].percent - 42.50).abs() < 1e-9);

    let mem = s.memory_history(0, i64::MAX).unwrap();
    assert_eq!(mem.len(), 1);
    assert_eq!(mem[0].total, 16_000_000_000);
    assert!((mem[0].used_percent - 43.75).abs() < 1e-9);

    let ccpu = s.container_cpu_history("web", 0, i64::MAX).unwrap();
    assert_eq!(ccpu.len(), 1);
    assert!((ccpu[0].percent - 10.0).abs() < 1e-9);

    let cmem = s.container_memory_history("web", 0, i64::MAX).unwrap();
    assert_eq!(cmem.len(), 1);
    assert_eq!(cmem[0].used, 60);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn migration_is_idempotent() {
    let dir = tmpdir("idem");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);

    { Store::open(&path).unwrap(); }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn skips_unparseable_rows_instead_of_failing() {
    let dir = tmpdir("bad");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("INSERT INTO cpu_usage VALUES ('not-a-number', 'garbage')", [])
            .unwrap();
    }

    let s = Store::open(&path).unwrap();
    // the two good rows survive; the malformed one is dropped
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fresh_database_needs_no_migration() {
    let dir = tmpdir("fresh");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);

    let s = Store::open(&path).unwrap();
    s.insert_cpu(1_000, 1.0).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn drops_unused_container_logs_table() {
    let dir = tmpdir("logs");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);

    Store::open(&path).unwrap();

    let c = rusqlite::Connection::open(&path).unwrap();
    let n: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='container_logs'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0, "container_logs should be dropped: never read or written");

    std::fs::remove_dir_all(&dir).ok();
}
