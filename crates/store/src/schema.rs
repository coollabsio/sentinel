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
