use rusqlite::Connection;

/// Typed, STRICT schema. Replaces the Go implementation's all-VARCHAR tables,
/// which forced `CAST(time AS INTEGER)` on every query and every index.
/// `container_logs` is intentionally absent: the Go code created and indexed it
/// but never read or wrote it.
pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS cpu_usage (
    time    INTEGER PRIMARY KEY,
    percent REAL NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS memory_usage (
    time         INTEGER PRIMARY KEY,
    total        INTEGER NOT NULL,
    available    INTEGER NOT NULL,
    used         INTEGER NOT NULL,
    used_percent REAL    NOT NULL,
    free         INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS disk_usage (
    time         INTEGER NOT NULL,
    mount        TEXT    NOT NULL,
    total        INTEGER NOT NULL,
    used         INTEGER NOT NULL,
    available    INTEGER NOT NULL,
    used_percent REAL    NOT NULL,
    PRIMARY KEY (time, mount)
) STRICT;

CREATE TABLE IF NOT EXISTS network_usage (
    time             INTEGER PRIMARY KEY,
    rx_bytes_per_sec REAL NOT NULL,
    tx_bytes_per_sec REAL NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS load_average (
    time   INTEGER PRIMARY KEY,
    load1  REAL NOT NULL,
    load5  REAL NOT NULL,
    load15 REAL NOT NULL
) STRICT;

-- Current status only (latest snapshot per container), keyed on the display
-- name like every other container series; not a time-series, so no history.
CREATE TABLE IF NOT EXISTS container_status (
    container_id  TEXT PRIMARY KEY,
    state         TEXT    NOT NULL,
    health_status TEXT    NOT NULL,
    restart_count INTEGER NOT NULL,
    time          INTEGER NOT NULL
) STRICT;

-- Singleton host status (id fixed at 0): current-only uptime + swap.
CREATE TABLE IF NOT EXISTS host_status (
    id                INTEGER PRIMARY KEY CHECK (id = 0),
    uptime_seconds    INTEGER NOT NULL,
    swap_total        INTEGER NOT NULL,
    swap_used         INTEGER NOT NULL,
    swap_free         INTEGER NOT NULL,
    swap_used_percent REAL    NOT NULL,
    time              INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_du_mount_time
    ON disk_usage (mount, time);

CREATE TABLE IF NOT EXISTS sentinel_meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) STRICT;
"#;

/// One per-container time series. Clustered on `(container_id, time)` (WITHOUT
/// ROWID), so one container's history is a single range scan; a rowid table
/// with a `(container_id, time)` index costs a random table lookup per row.
/// Only the disk table gets a `time` index, for its "latest cycle" read. The
/// others do retention and downsampling as a sequential scan, which is faster
/// than keeping each row in a second B-tree.
struct ContainerTable {
    name: &'static str,
    columns: &'static str,
    ddl: &'static str,
    index: Option<&'static str>,
}

const CONTAINER_TABLES: [ContainerTable; 4] = [
    ContainerTable {
        name: "container_cpu_usage",
        columns: "time, container_id, percent",
        ddl: r#"
CREATE TABLE IF NOT EXISTS container_cpu_usage (
    time         INTEGER NOT NULL,
    container_id TEXT    NOT NULL,
    percent      REAL    NOT NULL,
    PRIMARY KEY (container_id, time)
) STRICT, WITHOUT ROWID;
"#,
        index: None,
    },
    ContainerTable {
        name: "container_memory_usage",
        columns: "time, container_id, total, available, used, used_percent, free",
        ddl: r#"
CREATE TABLE IF NOT EXISTS container_memory_usage (
    time         INTEGER NOT NULL,
    container_id TEXT    NOT NULL,
    total        INTEGER NOT NULL,
    available    INTEGER NOT NULL,
    used         INTEGER NOT NULL,
    used_percent REAL    NOT NULL,
    free         INTEGER NOT NULL,
    PRIMARY KEY (container_id, time)
) STRICT, WITHOUT ROWID;
"#,
        index: None,
    },
    ContainerTable {
        name: "container_disk_usage",
        columns: "time, container_id, writable_layer, volumes_total",
        ddl: r#"
CREATE TABLE IF NOT EXISTS container_disk_usage (
    time           INTEGER NOT NULL,
    container_id   TEXT    NOT NULL,
    writable_layer INTEGER NOT NULL,
    volumes_total  INTEGER NOT NULL,
    PRIMARY KEY (container_id, time)
) STRICT, WITHOUT ROWID;
"#,
        index: Some("CREATE INDEX IF NOT EXISTS idx_cdu_time ON container_disk_usage (time)"),
    },
    ContainerTable {
        name: "container_network_usage",
        columns: "time, container_id, rx_bytes_per_sec, tx_bytes_per_sec",
        ddl: r#"
CREATE TABLE IF NOT EXISTS container_network_usage (
    time             INTEGER NOT NULL,
    container_id     TEXT    NOT NULL,
    rx_bytes_per_sec REAL    NOT NULL,
    tx_bytes_per_sec REAL    NOT NULL,
    PRIMARY KEY (container_id, time)
) STRICT, WITHOUT ROWID;
"#,
        index: None,
    },
];

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)?;
    for table in &CONTAINER_TABLES {
        conn.execute_batch(table.ddl)?;
        // A table left in the old layout by a failed rebuild already has a
        // `(time, container_id)` key, so a `time` index would only cost disk.
        if let Some(index) = table.index
            && is_without_rowid(conn, table.name)?
        {
            conn.execute_batch(index)?;
        }
    }
    Ok(())
}

/// Rebuilds container tables still in the old layout (rowid tables keyed on
/// `(time, container_id)`) in the clustered one. One transaction and one
/// WAL checkpoint per table, so the extra disk is about one table, not all
/// four. An interrupted rebuild rolls back and runs again on the next start.
/// Returns true if any table was rebuilt.
pub fn cluster_container_tables(conn: &Connection) -> rusqlite::Result<bool> {
    let mut rebuilt = false;
    for table in &CONTAINER_TABLES {
        let name = table.name;
        if !table_exists(conn, name)? || is_without_rowid(conn, name)? {
            continue;
        }
        let started_at = std::time::Instant::now();
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(&format!("ALTER TABLE {name} RENAME TO {name}_old"))?;
        tx.execute_batch(table.ddl)?;
        // No ORDER BY: rowid (insert) order is a sequential read, while
        // (container_id, time) order would be a random lookup per row. A
        // `time` index is built after the copy, which is faster than keeping
        // it up to date row by row.
        let cols = table.columns;
        tx.execute_batch(&format!(
            "INSERT INTO {name} ({cols}) SELECT {cols} FROM {name}_old;
             DROP TABLE {name}_old;"
        ))?;
        if let Some(index) = table.index {
            tx.execute_batch(index)?;
        }
        tx.commit()?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        tracing::info!(
            table = name,
            elapsed_ms = started_at.elapsed().as_millis(),
            "container table clustered on (container_id, time)"
        );
        rebuilt = true;
    }
    Ok(rebuilt)
}

/// Switches a database created without `auto_vacuum=INCREMENTAL` with one
/// full VACUUM. That also gives back the pages freed by the legacy migration
/// and the container table rebuild. The VACUUM needs free disk for about two
/// copies of the live data. Returns true if it ran.
pub fn enable_incremental_vacuum(conn: &Connection) -> rusqlite::Result<bool> {
    let mode: i64 = conn.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
    if mode == 2 {
        return Ok(false);
    }
    let started_at = std::time::Instant::now();
    conn.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
    tracing::info!(
        elapsed_ms = started_at.elapsed().as_millis(),
        "metrics database compacted, auto_vacuum is now incremental"
    );
    Ok(true)
}

fn is_without_rowid(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT wr FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
        (table,),
        |row| row.get(0),
    )
}

fn table_exists(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        (table,),
        |row| row.get(0),
    )
}

/// Returns true if a legacy (all-VARCHAR) schema was detected and migrated.
///
/// Row values are parsed in Rust, not filtered via SQL CAST: SQLite's
/// `CAST(text AS INTEGER/REAL)` never yields NULL for non-NULL text — it
/// extracts a leading numeric prefix and otherwise falls back to 0. A
/// `WHERE CAST(...) IS NOT NULL` guard therefore does not skip garbage, it
/// silently coerces it to a fabricated 0/0.0 value indistinguishable from a
/// real reading. Real `str::parse` failure is what "skip, don't corrupt"
/// requires.
pub fn migrate_legacy(conn: &Connection) -> rusqlite::Result<bool> {
    if !is_legacy(conn)? {
        return Ok(false);
    }
    tracing::info!("legacy metrics schema detected, migrating to typed schema");
    let started_at = std::time::Instant::now();

    let tx = conn.unchecked_transaction()?;

    let tables = [
        "cpu_usage",
        "memory_usage",
        "container_cpu_usage",
        "container_memory_usage",
    ];
    let mut present = Vec::new();
    for table in tables {
        if table_exists(&tx, table)? {
            tx.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_old"))?;
            present.push(table);
        }
    }
    apply(&tx)?;

    if present.contains(&"cpu_usage") {
        migrate_cpu_usage(&tx)?;
    }
    if present.contains(&"memory_usage") {
        migrate_memory_usage(&tx)?;
    }
    if present.contains(&"container_cpu_usage") {
        migrate_container_cpu_usage(&tx)?;
    }
    if present.contains(&"container_memory_usage") {
        migrate_container_memory_usage(&tx)?;
    }

    for table in present {
        tx.execute_batch(&format!("DROP TABLE {table}_old"))?;
    }
    // Created and indexed by the Go implementation but never read or written.
    tx.execute_batch("DROP TABLE IF EXISTS container_logs")?;

    tx.commit()?;
    tracing::info!(
        elapsed_ms = started_at.elapsed().as_millis(),
        "legacy schema migration complete"
    );
    Ok(true)
}

/// The legacy schema declares every column VARCHAR with no NOT NULL, and a
/// non-INTEGER PRIMARY KEY does not imply NOT NULL in SQLite — so a legacy
/// row's `time` (or any other column) can be a genuine SQL NULL, not just
/// unparseable text. Reading straight into `String` would error on NULL
/// (`InvalidColumnType`) and abort the whole migration; reading into
/// `Option<String>` and treating None the same as a parse failure is what
/// "skip this row" actually requires.
fn parse_opt<T: std::str::FromStr>(s: Option<String>) -> Option<T> {
    s?.trim().parse().ok()
}

/// Reads every row as raw (possibly-NULL) text first, so a value that is
/// missing or fails to parse skips only that row rather than the whole
/// migration.
///
/// Streams row-by-row (`Statement::query` + `Rows::next`) rather than
/// collecting into a `Vec` first: a `.collect::<Vec<_>>()` materializes the
/// ENTIRE legacy table in memory before inserting anything. At 7 days of
/// retention, 5s sampling, and a few dozen containers, the container tables
/// can hold millions of rows — collecting first can burn well over a
/// gigabyte of RAM on an agent whose whole design goal is a single-digit-MB
/// footprint, on exactly the busiest hosts. A `select`/`insert` pair of
/// independent prepared statements on the same transaction is safe here:
/// they operate on different tables (the `_old` table being read, the typed
/// table being written), so there's no self-referential cursor conflict.
fn migrate_cpu_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let mut select = tx.prepare("SELECT time, percent FROM cpu_usage_old")?;
    let mut insert =
        tx.prepare("INSERT OR REPLACE INTO cpu_usage (time, percent) VALUES (?1, ?2)")?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let time_s: Option<String> = row.get(0)?;
        let percent_s: Option<String> = row.get(1)?;
        let Some(time) = parse_opt::<i64>(time_s) else {
            continue;
        };
        let Some(percent) = parse_opt::<f64>(percent_s) else {
            continue;
        };
        insert.execute((time, percent))?;
    }
    Ok(())
}

fn migrate_memory_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let mut select =
        tx.prepare("SELECT time, total, available, used, usedPercent, free FROM memory_usage_old")?;
    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO memory_usage (time, total, available, used, used_percent, free)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let time_s: Option<String> = row.get(0)?;
        let total_s: Option<String> = row.get(1)?;
        let available_s: Option<String> = row.get(2)?;
        let used_s: Option<String> = row.get(3)?;
        let used_percent_s: Option<String> = row.get(4)?;
        let free_s: Option<String> = row.get(5)?;
        let Some(time) = parse_opt::<i64>(time_s) else {
            continue;
        };
        let Some(total) = parse_opt::<i64>(total_s) else {
            continue;
        };
        let Some(available) = parse_opt::<i64>(available_s) else {
            continue;
        };
        let Some(used) = parse_opt::<i64>(used_s) else {
            continue;
        };
        let Some(used_percent) = parse_opt::<f64>(used_percent_s) else {
            continue;
        };
        let Some(free) = parse_opt::<i64>(free_s) else {
            continue;
        };
        insert.execute((time, total, available, used, used_percent, free))?;
    }
    Ok(())
}

fn migrate_container_cpu_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let mut select =
        tx.prepare("SELECT time, container_id, percent FROM container_cpu_usage_old")?;
    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO container_cpu_usage (time, container_id, percent)
         VALUES (?1, ?2, ?3)",
    )?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let time_s: Option<String> = row.get(0)?;
        let container_id: Option<String> = row.get(1)?;
        let percent_s: Option<String> = row.get(2)?;
        let Some(time) = parse_opt::<i64>(time_s) else {
            continue;
        };
        let Some(container_id) = container_id.filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(percent) = parse_opt::<f64>(percent_s) else {
            continue;
        };
        insert.execute((time, container_id, percent))?;
    }
    Ok(())
}

fn migrate_container_memory_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let mut select = tx.prepare(
        "SELECT time, container_id, total, available, used, usedPercent, free
         FROM container_memory_usage_old",
    )?;
    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO container_memory_usage
            (time, container_id, total, available, used, used_percent, free)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    let mut rows = select.query([])?;
    while let Some(row) = rows.next()? {
        let time_s: Option<String> = row.get(0)?;
        let container_id: Option<String> = row.get(1)?;
        let total_s: Option<String> = row.get(2)?;
        let available_s: Option<String> = row.get(3)?;
        let used_s: Option<String> = row.get(4)?;
        let used_percent_s: Option<String> = row.get(5)?;
        let free_s: Option<String> = row.get(6)?;
        let Some(time) = parse_opt::<i64>(time_s) else {
            continue;
        };
        let Some(container_id) = container_id.filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(total) = parse_opt::<i64>(total_s) else {
            continue;
        };
        let Some(available) = parse_opt::<i64>(available_s) else {
            continue;
        };
        let Some(used) = parse_opt::<i64>(used_s) else {
            continue;
        };
        let Some(used_percent) = parse_opt::<f64>(used_percent_s) else {
            continue;
        };
        let Some(free) = parse_opt::<i64>(free_s) else {
            continue;
        };
        insert.execute((
            time,
            container_id,
            total,
            available,
            used,
            used_percent,
            free,
        ))?;
    }
    Ok(())
}

fn is_legacy(conn: &Connection) -> rusqlite::Result<bool> {
    for table in [
        "cpu_usage",
        "memory_usage",
        "container_cpu_usage",
        "container_memory_usage",
    ] {
        if !table_exists(conn, table)? {
            continue;
        }
        // table_info reports the declared type; the legacy schema declares VARCHAR.
        let sql = format!("SELECT name, type FROM pragma_table_info('{table}')");
        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let ty: String = row.get(1)?;
            if name == "time" && !ty.eq_ignore_ascii_case("INTEGER") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
