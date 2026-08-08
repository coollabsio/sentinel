use crate::{Store, StoreError};

/// Samples older than this are collapsed to one-minute averages.
pub const DOWNSAMPLE_AFTER_MS: i64 = 24 * 60 * 60 * 1_000;
/// Downsampling bucket width.
pub const BUCKET_MS: i64 = 60_000;

const TABLES: [&str; 4] = [
    "cpu_usage",
    "memory_usage",
    "container_cpu_usage",
    "container_memory_usage",
];

impl Store {
    /// Deletes rows older than `retention_days`, always preserving the 10 most
    /// recent rows per table (matching the Go implementation).
    pub fn cleanup(&self, retention_days: u32, now_ms: i64) -> Result<u64, StoreError> {
        let cutoff = now_ms - (retention_days as i64) * 86_400_000;
        self.with_conn(|c| {
            let mut deleted = 0u64;
            for table in TABLES {
                let sql = format!(
                    "DELETE FROM {table} WHERE time < ?1 AND time NOT IN
                     (SELECT DISTINCT time FROM {table} ORDER BY time DESC LIMIT 10)"
                );
                deleted += c.execute(&sql, (cutoff,))? as u64;
            }
            Ok(deleted)
        })
    }

    /// Collapses samples older than 24h into one-minute averages. This is the
    /// durable fix for metrics growth: at the default 5s rate it reduces the
    /// aged portion of each series roughly 12x.
    pub fn downsample(&self, now_ms: i64) -> Result<u64, StoreError> {
        let cutoff = now_ms - DOWNSAMPLE_AFTER_MS;
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let mut collapsed = 0u64;

            // Host series: bucket on time alone.
            collapsed += bucket_host(&tx, "cpu_usage", &["percent"], cutoff)?;
            collapsed += bucket_host(
                &tx,
                "memory_usage",
                &["total", "available", "used", "used_percent", "free"],
                cutoff,
            )?;
            // Container series: bucket on (time, container_id).
            collapsed += bucket_container(&tx, "container_cpu_usage", &["percent"], cutoff)?;
            collapsed += bucket_container(
                &tx,
                "container_memory_usage",
                &["total", "available", "used", "used_percent", "free"],
                cutoff,
            )?;

            tx.commit()?;
            Ok(collapsed)
        })
    }
}

/// Rewrites `table` so every row older than `cutoff` becomes one row per
/// minute bucket, each numeric column replaced by its bucket mean.
/// Integer columns are rounded back to integers to satisfy STRICT typing.
fn bucket_host(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    cols: &[&str],
    cutoff: i64,
) -> rusqlite::Result<u64> {
    // execute_batch runs a multi-statement script and Connection::changes()
    // afterward reflects only the LAST statement that touched row counts —
    // here that's the INSERT OR REPLACE (the DROP TABLE that follows it is
    // DDL and leaves changes() unchanged), not the DELETE. Since many raw
    // rows always collapse into fewer bucket rows, that would systematically
    // under-report "rows collapsed". Count the raw rows directly instead.
    let raw_count: i64 = tx.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE time < ?1"),
        (cutoff,),
        |r| r.get(0),
    )?;

    let avg_list = cols
        .iter()
        .map(|c| {
            if *c == "percent" || *c == "used_percent" {
                format!("AVG({c}) AS {c}")
            } else {
                format!("CAST(ROUND(AVG({c})) AS INTEGER) AS {c}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let col_list = cols.join(", ");

    let sql = format!(
        r#"
        CREATE TEMP TABLE _ds AS
        SELECT (time / {BUCKET_MS}) * {BUCKET_MS} AS time, {avg_list}
        FROM {table} WHERE time < ?1
        GROUP BY time / {BUCKET_MS};

        DELETE FROM {table} WHERE time < ?1;

        INSERT OR REPLACE INTO {table} (time, {col_list})
        SELECT time, {col_list} FROM _ds;

        DROP TABLE _ds;
        "#
    );
    // execute_batch does not bind parameters, so inline the validated integer.
    let sql = sql.replace("?1", &cutoff.to_string());
    tx.execute_batch(&sql)?;
    Ok(raw_count as u64)
}

fn bucket_container(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    cols: &[&str],
    cutoff: i64,
) -> rusqlite::Result<u64> {
    // See bucket_host: count raw rows directly rather than trusting
    // Connection::changes() after a multi-statement execute_batch.
    let raw_count: i64 = tx.query_row(
        &format!("SELECT COUNT(*) FROM {table} WHERE time < ?1"),
        (cutoff,),
        |r| r.get(0),
    )?;

    let avg_list = cols
        .iter()
        .map(|c| {
            if *c == "percent" || *c == "used_percent" {
                format!("AVG({c}) AS {c}")
            } else {
                format!("CAST(ROUND(AVG({c})) AS INTEGER) AS {c}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let col_list = cols.join(", ");

    let sql = format!(
        r#"
        CREATE TEMP TABLE _ds AS
        SELECT (time / {BUCKET_MS}) * {BUCKET_MS} AS time, container_id, {avg_list}
        FROM {table} WHERE time < ?1
        GROUP BY time / {BUCKET_MS}, container_id;

        DELETE FROM {table} WHERE time < ?1;

        INSERT OR REPLACE INTO {table} (time, container_id, {col_list})
        SELECT time, container_id, {col_list} FROM _ds;

        DROP TABLE _ds;
        "#
    );
    let sql = sql.replace("?1", &cutoff.to_string());
    tx.execute_batch(&sql)?;
    Ok(raw_count as u64)
}
