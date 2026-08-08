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
"#;

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)
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

    tx.execute_batch(
        r#"
        ALTER TABLE cpu_usage              RENAME TO cpu_usage_old;
        ALTER TABLE memory_usage           RENAME TO memory_usage_old;
        ALTER TABLE container_cpu_usage    RENAME TO container_cpu_usage_old;
        ALTER TABLE container_memory_usage RENAME TO container_memory_usage_old;
        "#,
    )?;
    apply(&tx)?;

    migrate_cpu_usage(&tx)?;
    migrate_memory_usage(&tx)?;
    migrate_container_cpu_usage(&tx)?;
    migrate_container_memory_usage(&tx)?;

    tx.execute_batch(
        r#"
        DROP TABLE cpu_usage_old;
        DROP TABLE memory_usage_old;
        DROP TABLE container_cpu_usage_old;
        DROP TABLE container_memory_usage_old;
        -- created and indexed by the Go implementation but never read or written
        DROP TABLE IF EXISTS container_logs;
        "#,
    )?;

    tx.commit()?;
    // VACUUM cannot run inside a transaction.
    conn.execute_batch("VACUUM")?;
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
fn migrate_cpu_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let rows: Vec<(Option<String>, Option<String>)> = tx
        .prepare("SELECT time, percent FROM cpu_usage_old")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut insert =
        tx.prepare("INSERT OR REPLACE INTO cpu_usage (time, percent) VALUES (?1, ?2)")?;
    for (time_s, percent_s) in rows {
        let Some(time) = parse_opt::<i64>(time_s) else { continue };
        let Some(percent) = parse_opt::<f64>(percent_s) else { continue };
        insert.execute((time, percent))?;
    }
    Ok(())
}

fn migrate_memory_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = tx
        .prepare("SELECT time, total, available, used, usedPercent, free FROM memory_usage_old")?
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO memory_usage (time, total, available, used, used_percent, free)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for (time_s, total_s, available_s, used_s, used_percent_s, free_s) in rows {
        let Some(time) = parse_opt::<i64>(time_s) else { continue };
        let Some(total) = parse_opt::<i64>(total_s) else { continue };
        let Some(available) = parse_opt::<i64>(available_s) else { continue };
        let Some(used) = parse_opt::<i64>(used_s) else { continue };
        let Some(used_percent) = parse_opt::<f64>(used_percent_s) else { continue };
        let Some(free) = parse_opt::<i64>(free_s) else { continue };
        insert.execute((time, total, available, used, used_percent, free))?;
    }
    Ok(())
}

fn migrate_container_cpu_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let rows: Vec<(Option<String>, Option<String>, Option<String>)> = tx
        .prepare("SELECT time, container_id, percent FROM container_cpu_usage_old")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO container_cpu_usage (time, container_id, percent)
         VALUES (?1, ?2, ?3)",
    )?;
    for (time_s, container_id, percent_s) in rows {
        let Some(time) = parse_opt::<i64>(time_s) else { continue };
        let Some(container_id) = container_id.filter(|s| !s.is_empty()) else { continue };
        let Some(percent) = parse_opt::<f64>(percent_s) else { continue };
        insert.execute((time, container_id, percent))?;
    }
    Ok(())
}

fn migrate_container_memory_usage(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = tx
        .prepare(
            "SELECT time, container_id, total, available, used, usedPercent, free
             FROM container_memory_usage_old",
        )?
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
        })?
        .collect::<rusqlite::Result<_>>()?;

    let mut insert = tx.prepare(
        "INSERT OR REPLACE INTO container_memory_usage
            (time, container_id, total, available, used, used_percent, free)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (time_s, container_id, total_s, available_s, used_s, used_percent_s, free_s) in rows {
        let Some(time) = parse_opt::<i64>(time_s) else { continue };
        let Some(container_id) = container_id.filter(|s| !s.is_empty()) else { continue };
        let Some(total) = parse_opt::<i64>(total_s) else { continue };
        let Some(available) = parse_opt::<i64>(available_s) else { continue };
        let Some(used) = parse_opt::<i64>(used_s) else { continue };
        let Some(used_percent) = parse_opt::<f64>(used_percent_s) else { continue };
        let Some(free) = parse_opt::<i64>(free_s) else { continue };
        insert.execute((time, container_id, total, available, used, used_percent, free))?;
    }
    Ok(())
}

fn is_legacy(conn: &Connection) -> rusqlite::Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cpu_usage'",
        [],
        |r| r.get(0),
    )?;
    if exists == 0 {
        return Ok(false);
    }
    // table_info reports the declared type; the legacy schema declares VARCHAR.
    let mut stmt = conn.prepare("SELECT name, type FROM pragma_table_info('cpu_usage')")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let ty: String = row.get(1)?;
        if name == "time" {
            return Ok(!ty.eq_ignore_ascii_case("INTEGER"));
        }
    }
    Ok(false)
}
