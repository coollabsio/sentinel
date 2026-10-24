use crate::{Store, StoreError};
use rusqlite::OptionalExtension;

/// Samples older than this are collapsed to one-minute averages.
pub const DOWNSAMPLE_AFTER_MS: i64 = 24 * 60 * 60 * 1_000;
/// Downsampling bucket width.
pub const BUCKET_MS: i64 = 60_000;

/// Tables with an index that starts with `time`.
const TIME_INDEXED_TABLES: [&str; 6] = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "container_disk_usage",
    "network_usage",
    "load_average",
];

/// Tables clustered on `(container_id, time)` with no `time` index.
const PER_CONTAINER_TABLES: [&str; 3] = [
    "container_cpu_usage",
    "container_memory_usage",
    "container_network_usage",
];

impl Store {
    /// Deletes rows older than `retention_days`, always preserving the 10 most
    /// recent rows per table (matching the Go implementation).
    pub fn cleanup(&self, retention_days: u32, now_ms: i64) -> Result<u64, StoreError> {
        let cutoff = now_ms - (retention_days as i64) * 86_400_000;
        self.with_conn(|c| {
            let mut deleted = 0u64;
            for table in TIME_INDEXED_TABLES {
                let sql = format!(
                    "DELETE FROM {table} WHERE time < ?1 AND time NOT IN
                     (SELECT DISTINCT time FROM {table} ORDER BY time DESC LIMIT 10)"
                );
                deleted += c.execute(&sql, (cutoff,))? as u64;
            }
            for table in PER_CONTAINER_TABLES {
                // Fewer than 10 distinct times: every row is protected.
                if let Some(tenth) = tenth_newest_time(c, table)? {
                    let sql = format!("DELETE FROM {table} WHERE time < ?1");
                    deleted += c.execute(&sql, (cutoff.min(tenth),))? as u64;
                }
            }
            // container_status is a current-only snapshot keyed on the display
            // name; its `time` is a last-seen stamp. A container not seen since
            // the cutoff is gone, so drop its stale status row (no per-row "keep
            // last 10" — each container already has at most one row).
            deleted += c.execute("DELETE FROM container_status WHERE time < ?1", (cutoff,))? as u64;
            Ok(deleted)
        })
    }

    /// Gives the pages freed by `cleanup` and `downsample` back to the file
    /// system. Without this, the file stays at its largest size. Returns the
    /// number of pages released.
    pub fn release_free_pages(&self) -> Result<u64, StoreError> {
        self.with_conn(|c| {
            let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
            // Each step frees one page, so step until done (`execute_batch`
            // steps once). The file shrinks at the checkpoint.
            let mut stmt = c.prepare("PRAGMA incremental_vacuum")?;
            let mut rows = stmt.query([])?;
            while rows.next()?.is_some() {}
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
            Ok(free as u64)
        })
    }

    /// Collapses samples older than 24h into one-minute averages. This is the
    /// durable fix for metrics growth: at the default 5s rate it reduces the
    /// aged portion of each series roughly 12x.
    pub fn downsample(&self, now_ms: i64) -> Result<u64, StoreError> {
        // Snap the cutoff down to a bucket boundary so no one-minute bucket ever
        // straddles it. Buckets are keyed on `(time / BUCKET_MS) * BUCKET_MS`;
        // if the cutoff fell mid-bucket, a first pass would collapse the rows
        // below it into a bucket row, and the next pass — resuming from the
        // stored cutoff as its lower bound — would collapse the remaining rows
        // in that same bucket to the identical key and `INSERT OR REPLACE` over
        // the earlier average, silently dropping the first half. A bucket-aligned
        // cutoff keeps each bucket entirely on one side of the boundary.
        let cutoff = now_ms - DOWNSAMPLE_AFTER_MS;
        let cutoff = cutoff - cutoff.rem_euclid(BUCKET_MS);
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            let lower_bound = tx
                .query_row(
                    "SELECT value FROM sentinel_meta WHERE key = 'downsample_cutoff'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?;
            let mut collapsed = 0u64;

            // Host series: bucket on time alone.
            collapsed += bucket_host(&tx, "cpu_usage", &["percent"], lower_bound, cutoff)?;
            collapsed += bucket_host(
                &tx,
                "memory_usage",
                &["total", "available", "used", "used_percent", "free"],
                lower_bound,
                cutoff,
            )?;
            // Per-entity series: bucket on (time, <entity>).
            collapsed += bucket_entity(
                &tx,
                "container_cpu_usage",
                "container_id",
                &["percent"],
                lower_bound,
                cutoff,
            )?;
            collapsed += bucket_entity(
                &tx,
                "container_memory_usage",
                "container_id",
                &["total", "available", "used", "used_percent", "free"],
                lower_bound,
                cutoff,
            )?;
            collapsed += bucket_entity(
                &tx,
                "disk_usage",
                "mount",
                &["total", "used", "available", "used_percent"],
                lower_bound,
                cutoff,
            )?;
            collapsed += bucket_entity(
                &tx,
                "container_disk_usage",
                "container_id",
                &["writable_layer", "volumes_total"],
                lower_bound,
                cutoff,
            )?;
            // Network is stored as a rate (bytes/sec), so a per-minute mean is
            // the correct aged value — the same reason it is not a raw counter.
            collapsed += bucket_host(
                &tx,
                "network_usage",
                &["rx_bytes_per_sec", "tx_bytes_per_sec"],
                lower_bound,
                cutoff,
            )?;
            collapsed += bucket_host(
                &tx,
                "load_average",
                &["load1", "load5", "load15"],
                lower_bound,
                cutoff,
            )?;
            collapsed += bucket_entity(
                &tx,
                "container_network_usage",
                "container_id",
                &["rx_bytes_per_sec", "tx_bytes_per_sec"],
                lower_bound,
                cutoff,
            )?;

            tx.execute(
                "INSERT INTO sentinel_meta (key, value) VALUES ('downsample_cutoff', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (cutoff,),
            )?;

            tx.commit()?;
            Ok(collapsed)
        })
    }
}

/// The 10th-newest distinct `time` in a per-container table. Without a `time`
/// index, `SELECT DISTINCT time ... LIMIT 10` sorts every row. Each of the 10
/// newest times is in some container's 10 newest rows, and the primary key
/// reads those directly.
fn tenth_newest_time(c: &rusqlite::Connection, table: &str) -> rusqlite::Result<Option<i64>> {
    let sql = format!(
        "WITH RECURSIVE ids(id) AS (
             SELECT MIN(container_id) FROM {table}
             UNION ALL
             SELECT (SELECT MIN(container_id) FROM {table} WHERE container_id > ids.id)
             FROM ids WHERE ids.id IS NOT NULL
         ),
         recent(id, since) AS MATERIALIZED (
             SELECT id, (SELECT MIN(time) FROM (SELECT time FROM {table}
                         WHERE container_id = ids.id ORDER BY time DESC LIMIT 10))
             FROM ids WHERE id IS NOT NULL
         )
         SELECT DISTINCT time FROM recent JOIN {table}
             ON container_id = recent.id AND time >= recent.since
         ORDER BY time DESC LIMIT 1 OFFSET 9"
    );
    c.query_row(&sql, [], |r| r.get(0)).optional()
}

/// Rewrites `table` so every row older than `cutoff` becomes one row per
/// minute bucket, each numeric column replaced by its bucket mean.
/// Integer columns are rounded back to integers to satisfy STRICT typing.
fn bucket_host(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    cols: &[&str],
    lower_bound: Option<i64>,
    cutoff: i64,
) -> rusqlite::Result<u64> {
    let avg_list = avg_list(cols);
    let col_list = cols.join(", ");
    let lower_predicate = lower_bound
        .map(|value| format!("time >= {value}"))
        .unwrap_or_else(|| "1 = 1".to_string());

    tx.execute_batch(&format!(
        "CREATE TEMP TABLE _ds AS
         SELECT (time / {BUCKET_MS}) * {BUCKET_MS} AS time, {avg_list}
         FROM {table} WHERE {lower_predicate} AND time < {cutoff}
         GROUP BY time / {BUCKET_MS}"
    ))?;
    let raw_count = tx.execute(
        &format!("DELETE FROM {table} WHERE {lower_predicate} AND time < {cutoff}"),
        [],
    )?;
    tx.execute_batch(&format!(
        "INSERT OR REPLACE INTO {table} (time, {col_list}) SELECT time, {col_list} FROM _ds;
         DROP TABLE _ds;"
    ))?;
    Ok(raw_count as u64)
}

/// Like `bucket_host`, but keyed on `(time_bucket, entity)` so each distinct
/// entity (container_id, mount, …) keeps its own one-minute averages.
fn bucket_entity(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    entity: &str,
    cols: &[&str],
    lower_bound: Option<i64>,
    cutoff: i64,
) -> rusqlite::Result<u64> {
    let avg_list = avg_list(cols);
    let col_list = cols.join(", ");
    let lower_predicate = lower_bound
        .map(|value| format!("time >= {value}"))
        .unwrap_or_else(|| "1 = 1".to_string());

    // Entity first: the rows come out in the container tables' primary key
    // order, so the insert appends instead of seeking.
    tx.execute_batch(&format!(
        "CREATE TEMP TABLE _ds AS
         SELECT (time / {BUCKET_MS}) * {BUCKET_MS} AS time, {entity}, {avg_list}
         FROM {table} WHERE {lower_predicate} AND time < {cutoff}
         GROUP BY {entity}, time / {BUCKET_MS}"
    ))?;
    let raw_count = tx.execute(
        &format!("DELETE FROM {table} WHERE {lower_predicate} AND time < {cutoff}"),
        [],
    )?;
    tx.execute_batch(&format!(
        "INSERT OR REPLACE INTO {table} (time, {entity}, {col_list})
         SELECT time, {entity}, {col_list} FROM _ds;
         DROP TABLE _ds;"
    ))?;
    Ok(raw_count as u64)
}

/// Metric columns stored as REAL. Every other averaged column is a byte/count
/// value rounded back to an integer to satisfy STRICT typing. Integer-casting a
/// REAL column (e.g. a `load1` of 0.75) would silently truncate it.
pub(crate) const REAL_COLS: [&str; 7] = [
    "percent",
    "used_percent",
    "rx_bytes_per_sec",
    "tx_bytes_per_sec",
    "load1",
    "load5",
    "load15",
];

fn avg_list(cols: &[&str]) -> String {
    // REAL columns keep two decimals.
    cols.iter()
        .map(|c| {
            if REAL_COLS.contains(c) {
                format!("ROUND(AVG({c}), 2) AS {c}")
            } else {
                format!("CAST(ROUND(AVG({c})) AS INTEGER) AS {c}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}
