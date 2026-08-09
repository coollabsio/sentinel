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

CREATE TABLE IF NOT EXISTS container_cpu_usage (
    time         INTEGER NOT NULL,
    container_id TEXT    NOT NULL,
    percent      REAL    NOT NULL,
    PRIMARY KEY (time, container_id)
) STRICT;

CREATE TABLE IF NOT EXISTS container_memory_usage (
    time         INTEGER NOT NULL,
    container_id TEXT    NOT NULL,
    total        INTEGER NOT NULL,
    available    INTEGER NOT NULL,
    used         INTEGER NOT NULL,
    used_percent REAL    NOT NULL,
    free         INTEGER NOT NULL,
    PRIMARY KEY (time, container_id)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ccu_container_time
    ON container_cpu_usage (container_id, time);
CREATE INDEX IF NOT EXISTS idx_cmu_container_time
    ON container_memory_usage (container_id, time);

CREATE TABLE IF NOT EXISTS sentinel_meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) STRICT;
"#;

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)
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
    // VACUUM cannot run inside a transaction. It only reclaims disk space left
    // by the dropped legacy tables — the migration is already durably committed
    // above. A VACUUM failure (e.g. transient disk-full) must NOT propagate:
    // the caller (Store::open) treats a migration error as an unopenable DB and
    // renames the file aside, which would hide the freshly-migrated history.
    // Log and continue with the successfully migrated data instead.
    if let Err(e) = conn.execute_batch("VACUUM") {
        tracing::warn!(error = %e, "post-migration VACUUM failed; continuing with migrated data");
    }
    tracing::info!("legacy schema migration complete");
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
