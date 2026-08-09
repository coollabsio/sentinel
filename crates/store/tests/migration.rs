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

    {
        Store::open(&path).unwrap();
    }
    let s = Store::open(&path).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 2);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn migrates_available_legacy_tables_when_one_is_missing() {
    let dir = tmpdir("partial");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("DROP TABLE memory_usage", [])
        .unwrap();

    let s = Store::open(&path).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 2);
    assert!(s.memory_history(0, i64::MAX).unwrap().is_empty());
    assert_eq!(
        s.container_cpu_history("web", 0, i64::MAX).unwrap().len(),
        1
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn detects_legacy_schema_when_cpu_table_is_missing() {
    let dir = tmpdir("partial-no-cpu");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("DROP TABLE cpu_usage", [])
        .unwrap();

    let s = Store::open(&path).unwrap();
    assert!(s.cpu_history(0, i64::MAX).unwrap().is_empty());
    assert_eq!(s.memory_history(0, i64::MAX).unwrap().len(), 1);
    assert_eq!(
        s.container_cpu_history("web", 0, i64::MAX).unwrap().len(),
        1
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn recovery_moves_sqlite_sidecars_using_appended_suffixes() {
    let dir = tmpdir("sidecars");
    let path = dir.join("metrics.db");
    let backup = path.with_extension("legacy-backup.sqlite");
    std::fs::write(&path, b"not sqlite").unwrap();
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    let shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
    std::fs::write(&wal, b"wal").unwrap();
    std::fs::write(&shm, b"shm").unwrap();

    Store::open(&path).unwrap();

    assert!(backup.exists());
    assert_ne!(
        std::fs::read(&wal).unwrap_or_default(),
        b"wal",
        "the stale WAL must be removed before SQLite creates a fresh sidecar"
    );
    assert_ne!(
        std::fs::read(&shm).unwrap_or_default(),
        b"shm",
        "the stale SHM must be removed before SQLite creates a fresh sidecar"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn skips_unparseable_rows_instead_of_failing() {
    // Three distinct corruption shapes. SQL `CAST` would silently coerce all
    // of these to 0/0.0 rather than skip them — this test only passes if
    // migration actually parses in Rust (str::parse failure), not CAST.
    let dir = tmpdir("bad");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        // time is fully non-numeric
        c.execute(
            "INSERT INTO cpu_usage VALUES ('not-a-number', 'garbage')",
            [],
        )
        .unwrap();
        // time has a digit prefix but trailing garbage — CAST(... AS INTEGER)
        // would truncate this to 123, not skip it
        c.execute("INSERT INTO cpu_usage VALUES ('123abc', '10.00')", [])
            .unwrap();
        // time is valid, but percent is garbage
        c.execute(
            "INSERT INTO cpu_usage VALUES ('1700000099999', 'garbage')",
            [],
        )
        .unwrap();
    }

    let s = Store::open(&path).unwrap();
    // only the two originally-seeded good rows survive; all three malformed
    // rows above are dropped, none silently coerced to a fabricated 0/0.0
    let rows = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(rows.len(), 2, "got {rows:?}");
    assert!(
        rows.iter()
            .all(|r| r.time == 1_700_000_000_000 || r.time == 1_700_000_005_000)
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn skips_rows_with_a_genuine_sql_null_not_just_unparseable_text() {
    // The legacy schema declares every column VARCHAR with no NOT NULL, and
    // SQLite does not imply NOT NULL from a non-INTEGER PRIMARY KEY, so a
    // real SQL NULL is a legal legacy value distinct from garbage text.
    // Reading straight into `String` would error (and abort the whole
    // migration) instead of skipping; reading into `Option<String>` must
    // treat NULL the same as a parse failure.
    let dir = tmpdir("null");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("INSERT INTO cpu_usage VALUES (NULL, '10.00')", [])
            .unwrap();
        c.execute("INSERT INTO cpu_usage VALUES ('1700000099999', NULL)", [])
            .unwrap();
        c.execute(
            "INSERT INTO container_cpu_usage VALUES ('1700000099999', NULL, '5.00')",
            [],
        )
        .unwrap();
    }

    let s = Store::open(&path).unwrap();
    let rows = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "NULL rows must be skipped, not error the migration: got {rows:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn migrates_a_large_legacy_database_row_for_row() {
    // The migration streams rows instead of collecting the whole legacy table
    // into a Vec first (which would materialize millions of rows in RAM on a
    // busy host). This is the correctness guard on that rewrite: every row
    // must still land, with its exact values, when there are far more rows
    // than a single `Rows::next()` step.
    const N: i64 = 2_000;
    let dir = tmpdir("bulk");
    let path = dir.join("m.sqlite");
    let _ = std::fs::remove_file(&path);
    legacy_db(&path);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        let tx = c.unchecked_transaction().unwrap();
        for i in 0..N {
            // offset past the rows legacy_db() already seeded
            let t = 1_700_000_100_000 + i * 1_000;
            tx.execute(
                "INSERT INTO cpu_usage VALUES (?1, ?2)",
                (t.to_string(), format!("{:.2}", i as f64 / 100.0)),
            )
            .unwrap();
            tx.execute(
                "INSERT INTO memory_usage VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    t.to_string(),
                    "16000000000",
                    (8_000_000_000i64 + i).to_string(),
                    (7_000_000_000i64 + i).to_string(),
                    format!("{:.2}", i as f64 / 100.0),
                    "1000000000",
                ),
            )
            .unwrap();
            for name in ["web", "db"] {
                tx.execute(
                    "INSERT INTO container_cpu_usage VALUES (?1, ?2, ?3)",
                    (t.to_string(), name, format!("{:.2}", i as f64 / 100.0)),
                )
                .unwrap();
                tx.execute(
                    "INSERT INTO container_memory_usage VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    (
                        t.to_string(),
                        name,
                        "100",
                        (40 + i).to_string(),
                        (60 + i).to_string(),
                        format!("{:.2}", i as f64 / 100.0),
                        (40 + i).to_string(),
                    ),
                )
                .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    let s = Store::open(&path).unwrap();

    let cpu = s.cpu_history(0, i64::MAX).unwrap();
    assert_eq!(cpu.len() as i64, N + 2, "2 seeded + {N} bulk cpu rows");
    let mem = s.memory_history(0, i64::MAX).unwrap();
    assert_eq!(mem.len() as i64, N + 1);
    for name in ["web", "db"] {
        let ccpu = s.container_cpu_history(name, 0, i64::MAX).unwrap();
        let cmem = s.container_memory_history(name, 0, i64::MAX).unwrap();
        // "web" also has the single row legacy_db() seeded
        let seeded = i64::from(name == "web");
        assert_eq!(ccpu.len() as i64, N + seeded, "{name} cpu");
        assert_eq!(cmem.len() as i64, N + seeded, "{name} mem");
    }

    // spot-check exact values at the start, middle and end of the stream
    for i in [0i64, N / 2, N - 1] {
        let t = 1_700_000_100_000 + i * 1_000;
        let expected = i as f64 / 100.0;
        let cpu = s.cpu_history(t, t).unwrap();
        assert_eq!(cpu.len(), 1, "cpu row at {t}");
        assert!((cpu[0].percent - expected).abs() < 1e-9, "cpu at {t}");

        let mem = s.memory_history(t, t).unwrap();
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].used, 7_000_000_000 + i as u64);
        assert!((mem[0].used_percent - expected).abs() < 1e-9);

        let ccpu = s.container_cpu_history("db", t, t).unwrap();
        assert_eq!(ccpu.len(), 1);
        assert!((ccpu[0].percent - expected).abs() < 1e-9);

        let cmem = s.container_memory_history("db", t, t).unwrap();
        assert_eq!(cmem.len(), 1);
        assert_eq!(cmem[0].used, 60 + i as u64);
        assert_eq!(cmem[0].free, 40 + i as u64);
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unreadable_database_is_moved_aside_instead_of_failing_startup() {
    // A corrupt/unmigratable file must not be fatal: history is regenerable
    // and retention-bounded, but a hard error here crash-loops the whole
    // agent (API, push, collection) forever on the same file.
    let dir = tmpdir("garbage");
    let path = dir.join("m.sqlite");
    let backup = path.with_extension("legacy-backup.sqlite");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&backup);

    let garbage = b"this is definitely not a sqlite database\n";
    std::fs::write(&path, garbage).unwrap();

    let s = Store::open(&path).expect("open must recover, not error");

    // fresh, empty, typed database usable immediately
    assert!(s.cpu_history(0, i64::MAX).unwrap().is_empty());
    s.insert_cpu(1_000, 1.0).unwrap();
    assert_eq!(s.cpu_history(0, i64::MAX).unwrap().len(), 1);

    assert!(
        backup.exists(),
        "original file must be preserved at {backup:?}"
    );
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        garbage,
        "backup must hold the original bytes verbatim"
    );

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
    assert_eq!(
        n, 0,
        "container_logs should be dropped: never read or written"
    );

    std::fs::remove_dir_all(&dir).ok();
}
