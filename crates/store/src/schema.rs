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
pub fn migrate_legacy(conn: &Connection) -> rusqlite::Result<bool> {
    if !is_legacy(conn)? {
        return Ok(false);
    }
    tracing::info!("legacy metrics schema detected, migrating to typed schema");

    conn.execute_batch(
        r#"
        BEGIN;

        ALTER TABLE cpu_usage              RENAME TO cpu_usage_old;
        ALTER TABLE memory_usage           RENAME TO memory_usage_old;
        ALTER TABLE container_cpu_usage    RENAME TO container_cpu_usage_old;
        ALTER TABLE container_memory_usage RENAME TO container_memory_usage_old;
        "#,
    )?;
    apply(conn)?;

    // CAST yields NULL for unparseable text; WHERE ... IS NOT NULL drops those
    // rows rather than aborting. Metrics are regenerable and retention-bounded.
    conn.execute_batch(
        r#"
        INSERT OR REPLACE INTO cpu_usage (time, percent)
        SELECT CAST(time AS INTEGER), CAST(percent AS REAL)
        FROM cpu_usage_old
        WHERE CAST(time AS INTEGER) IS NOT NULL
          AND CAST(percent AS REAL) IS NOT NULL
          AND time GLOB '[0-9]*';

        INSERT OR REPLACE INTO memory_usage
            (time, total, available, used, used_percent, free)
        SELECT CAST(time AS INTEGER), CAST(total AS INTEGER),
               CAST(available AS INTEGER), CAST(used AS INTEGER),
               CAST(usedPercent AS REAL), CAST(free AS INTEGER)
        FROM memory_usage_old
        WHERE time GLOB '[0-9]*';

        INSERT OR REPLACE INTO container_cpu_usage (time, container_id, percent)
        SELECT CAST(time AS INTEGER), container_id, CAST(percent AS REAL)
        FROM container_cpu_usage_old
        WHERE time GLOB '[0-9]*' AND container_id IS NOT NULL;

        INSERT OR REPLACE INTO container_memory_usage
            (time, container_id, total, available, used, used_percent, free)
        SELECT CAST(time AS INTEGER), container_id, CAST(total AS INTEGER),
               CAST(available AS INTEGER), CAST(used AS INTEGER),
               CAST(usedPercent AS REAL), CAST(free AS INTEGER)
        FROM container_memory_usage_old
        WHERE time GLOB '[0-9]*' AND container_id IS NOT NULL;

        DROP TABLE cpu_usage_old;
        DROP TABLE memory_usage_old;
        DROP TABLE container_cpu_usage_old;
        DROP TABLE container_memory_usage_old;
        -- created and indexed by the Go implementation but never read or written
        DROP TABLE IF EXISTS container_logs;

        COMMIT;
        "#,
    )?;

    // VACUUM cannot run inside a transaction.
    conn.execute_batch("VACUUM")?;
    tracing::info!("legacy schema migration complete");
    Ok(true)
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
