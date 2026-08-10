//! `analytics.sqlite`: traffic time series, kept separate from `metrics.sqlite`
//! so the minute flush's WAL churn never contends with the 5s metrics collector.
//! Three roll-up tiers (`_1m`/`_1h`/`_1d`) share one shape per table family
//! (stats, paths, breakdown). `flush_window` writes only `1m`; rolling up lives
//! in `traffic::compaction` (merging sketch BLOBs needs its types — `store →
//! traffic` would be a cycle), driven via `compact_window`, which moves one bucket up atomically.

use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::StoreError;

/// Per-family typed, STRICT table+index templates. All three roll-up tiers
/// (`_1m`/`_1h`/`_1d`) are byte-identical bar the suffix, so [`apply`] builds
/// the nine tables and nine indexes by substituting `{sfx}` per tier rather
/// than spelling each out. `1h`/`1d` tables are written by compaction (via
/// `write_rows`); `flush_window` only ever inserts into the `1m` tables.
const STATS_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS traffic_stats_{sfx} (
    bucket          INTEGER NOT NULL,
    app             TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    requests        INTEGER NOT NULL,
    bytes_in        INTEGER NOT NULL,
    bytes_out       INTEGER NOT NULL,
    s2xx            INTEGER NOT NULL,
    s3xx            INTEGER NOT NULL,
    s4xx            INTEGER NOT NULL,
    s5xx            INTEGER NOT NULL,
    latency_tdigest BLOB    NOT NULL,
    uniques_hll     BLOB    NOT NULL,
    PRIMARY KEY (bucket, app, host)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_ts_{sfx}_app_bucket ON traffic_stats_{sfx} (app, bucket);
";

const PATHS_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS traffic_paths_{sfx} (
    bucket          INTEGER NOT NULL,
    app             TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    requests        INTEGER NOT NULL,
    bytes_out       INTEGER NOT NULL,
    latency_tdigest BLOB    NOT NULL,
    PRIMARY KEY (bucket, app, path)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_tp_{sfx}_app_bucket ON traffic_paths_{sfx} (app, bucket);
";

const BREAKDOWN_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS traffic_breakdown_{sfx} (
    bucket    INTEGER NOT NULL,
    app       TEXT    NOT NULL,
    dimension TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    requests  INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    PRIMARY KEY (bucket, app, dimension, value)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_tb_{sfx}_app_bucket ON traffic_breakdown_{sfx} (app, bucket, dimension);
";

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    let mut ddl = String::new();
    for tier in [Tier::M1, Tier::H1, Tier::D1] {
        let sfx = suffix(tier);
        for template in [STATS_SCHEMA, PATHS_SCHEMA, BREAKDOWN_SCHEMA] {
            ddl.push_str(&template.replace("{sfx}", sfx));
        }
    }
    conn.execute_batch(&ddl)
}

/// Roll-up tier; maps to the `_1m`/`_1h`/`_1d` table-name suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    M1,
    H1,
    D1,
}

fn suffix(tier: Tier) -> &'static str {
    match tier {
        Tier::M1 => "1m",
        Tier::H1 => "1h",
        Tier::D1 => "1d",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatsRow {
    pub bucket: i64,
    pub app: String,
    pub host: String,
    pub requests: i64,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub s2xx: i64,
    pub s3xx: i64,
    pub s4xx: i64,
    pub s5xx: i64,
    pub latency_tdigest: Vec<u8>,
    pub uniques_hll: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathRow {
    pub bucket: i64,
    pub app: String,
    pub path: String,
    pub requests: i64,
    pub bytes_out: i64,
    pub latency_tdigest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BreakdownRow {
    pub bucket: i64,
    pub app: String,
    pub dimension: String,
    pub value: String,
    pub requests: i64,
    pub bytes_out: i64,
}

/// One bucket window's rows across all three tables of a single tier.
///
/// Exists so [`AnalyticsStore::compact_window`] can hand a whole window to
/// its merge callback and take the merged result back in one value, without
/// a three-tuple at every call site.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TierRows {
    pub stats: Vec<StatsRow>,
    pub paths: Vec<PathRow>,
    pub breakdown: Vec<BreakdownRow>,
}

impl TierRows {
    /// Total row count across the three tables.
    pub fn len(&self) -> usize {
        self.stats.len() + self.paths.len() + self.breakdown.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stats.is_empty() && self.paths.is_empty() && self.breakdown.is_empty()
    }
}

#[derive(Clone)]
pub struct AnalyticsStore {
    /// Single read-write connection; serializes all writes (minute-flush,
    /// future compaction/retention) through one `Mutex`, matching `Store`.
    writer: Arc<Mutex<Connection>>,
    /// Dedicated read-only connection for range queries. In WAL mode a reader
    /// sees the latest committed snapshot without blocking the writer. For
    /// in-memory stores (tests) a second `:memory:` connection would be a
    /// distinct empty DB, so `reader` aliases `writer` there.
    reader: Arc<Mutex<Connection>>,
}

impl AnalyticsStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // Path::parent() returns Some("") for a bare filename with no
        // directory component, not None — create_dir_all("") silently
        // no-ops, but set_permissions("") fails with NotFound. Skip the
        // whole block when there's no real directory to create.
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
            }
        }
        match Connection::open(path)
            .map_err(StoreError::from)
            .and_then(|conn| Self::from_writer(conn, Some(path)))
        {
            Ok(store) => Ok(store),
            Err(e) => {
                // Open/schema failure must never be fatal to startup:
                // traffic analytics history is regenerable from ongoing
                // access-log tailing, while the agent itself is not
                // optional. Move the unreadable file aside and start fresh
                // rather than crash-looping on the same failure forever.
                tracing::error!(
                    error = %e,
                    path = %path.display(),
                    "failed to open or migrate analytics database, starting fresh"
                );
                if path.exists() {
                    let backup = path.with_extension("legacy-backup.sqlite");
                    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
                    let shm = std::path::PathBuf::from(format!("{}-shm", path.display()));
                    let backup_wal = std::path::PathBuf::from(format!("{}-wal", backup.display()));
                    let _ = std::fs::remove_file(&backup);
                    let _ = std::fs::remove_file(&backup_wal);
                    std::fs::rename(path, &backup)?;
                    if wal.exists() {
                        std::fs::rename(&wal, &backup_wal)?;
                    }
                    let _ = std::fs::remove_file(&shm);
                }
                let conn = Connection::open(path)?;
                Self::from_writer(conn, Some(path))
            }
        }
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_writer(Connection::open_in_memory()?, None)
    }

    /// Initializes the writer connection's schema, then (for file-backed
    /// stores) opens a separate read-only connection on the same path.
    /// `path == None` marks an in-memory store, where the reader must alias
    /// the writer.
    fn from_writer(conn: Connection, path: Option<&Path>) -> Result<Self, StoreError> {
        Self::init_conn(&conn)?;
        apply(&conn)?;
        let writer = Arc::new(Mutex::new(conn));

        let reader = match path {
            Some(path) => {
                use rusqlite::OpenFlags;
                let ro = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
                )?;
                // A brief checkpoint can hold the DB; wait rather than error.
                ro.busy_timeout(std::time::Duration::from_secs(5))?;
                ro.pragma_update(None, "cache_size", -16000)?;
                Arc::new(Mutex::new(ro))
            }
            // In-memory: a second `:memory:` connection is a distinct empty
            // DB, so alias the writer to keep read-after-write visible in
            // tests.
            None => writer.clone(),
        };

        Ok(Self { writer, reader })
    }

    fn init_conn(conn: &Connection) -> Result<(), StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // ~16 MB, double Store's -8000 (~8 MB): deliberate deviation per this
        // feature's spec — minute-cadence flush transactions touch more rows
        // per commit than the metrics collector's per-5s scalar inserts.
        conn.pragma_update(None, "cache_size", -16000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // A brief checkpoint (or, later, the timed wal_checkpoint(TRUNCATE))
        // can hold the writer lock; wait rather than error immediately,
        // matching the reader connection below.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // Disable SQLite's automatic checkpoint: a later task adds an
        // explicit timed `wal_checkpoint(TRUNCATE)` that owns checkpointing
        // instead, so it isn't racing an implicit one here (design spec §9).
        conn.pragma_update(None, "wal_autocheckpoint", 0)?;
        // Must be set before any table exists (below, via `apply`) to take
        // effect without a full VACUUM later (design spec §9).
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
        Ok(())
    }

    /// Read-write connection: minute-flush, future compaction/retention.
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.writer.lock().map_err(|_| StoreError::Poisoned)?;
        f(&guard)
    }

    /// Read-only connection: range queries. Decoupled from the writer so
    /// reads don't serialize behind the once-a-minute flush.
    fn with_reader<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.reader.lock().map_err(|_| StoreError::Poisoned)?;
        f(&guard)
    }

    /// Writes one minute-window's worth of aggregated rows to the `_1m`
    /// tier. Thin wrapper over [`Self::write_rows`], kept as the name the
    /// minute-flush path uses.
    pub fn flush_window(
        &self,
        stats: &[StatsRow],
        paths: &[PathRow],
        breakdown: &[BreakdownRow],
    ) -> Result<(), StoreError> {
        self.write_rows(Tier::M1, stats, paths, breakdown)
    }

    /// Upserts a batch into `tier`'s three tables in one transaction. On
    /// conflict counters sum but sketch blobs replace (callers hand fully-merged
    /// sketches). Compaction clears its window first, so it relies on neither.
    pub fn write_rows(
        &self,
        tier: Tier,
        stats: &[StatsRow],
        paths: &[PathRow],
        breakdown: &[BreakdownRow],
    ) -> Result<(), StoreError> {
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            insert_rows(&tx, tier, stats, paths, breakdown)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Rolls one coarse bucket up a tier atomically. `merge(finer, coarse)` feeds
    /// the destination back in and *recomputes* (never increments), so a late finer
    /// row can't clobber sketches; the single transaction rolls back write+delete together, so a retry can't double-count.
    pub fn compact_window<F>(
        &self,
        from_tier: Tier,
        to_tier: Tier,
        from_bucket: i64,
        to_bucket: i64,
        merge: F,
    ) -> Result<usize, StoreError>
    where
        F: FnOnce(TierRows, TierRows) -> TierRows,
    {
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;

            let finer = TierRows {
                stats: select_stats(&tx, from_tier, from_bucket, to_bucket)?,
                paths: select_paths(&tx, from_tier, from_bucket, to_bucket)?,
                breakdown: select_breakdown(&tx, from_tier, from_bucket, to_bucket)?,
            };
            if finer.is_empty() {
                // Nothing was written, so there is nothing to commit;
                // dropping the transaction rolls back an empty read. The
                // destination is deliberately left unread and untouched.
                return Ok(0);
            }

            // Whatever a previous pass already wrote for this coarse bucket.
            // Empty on the common first-compaction path.
            let coarse = TierRows {
                stats: select_stats(&tx, to_tier, from_bucket, to_bucket)?,
                paths: select_paths(&tx, to_tier, from_bucket, to_bucket)?,
                breakdown: select_breakdown(&tx, to_tier, from_bucket, to_bucket)?,
            };

            let merged = merge(finer, coarse);

            // Clear the destination window before writing: `merged` already
            // subsumes everything that was in it, so an upsert would sum the
            // counters into themselves.
            for table in ["traffic_stats", "traffic_paths", "traffic_breakdown"] {
                delete_range(&tx, table, to_tier, from_bucket, to_bucket)?;
            }
            insert_rows(
                &tx,
                to_tier,
                &merged.stats,
                &merged.paths,
                &merged.breakdown,
            )?;

            for table in ["traffic_stats", "traffic_paths", "traffic_breakdown"] {
                delete_range(&tx, table, from_tier, from_bucket, to_bucket)?;
            }

            tx.commit()?;
            Ok(merged.len())
        })
    }

    /// Every distinct bucket in `tier` (stats ∪ paths ∪ breakdown) before
    /// `cutoff`, ascending. Lets compaction enumerate waiting work and drain a
    /// backlog one bounded transaction at a time rather than in one unbounded read.
    pub fn distinct_buckets_before(&self, tier: Tier, cutoff: i64) -> Result<Vec<i64>, StoreError> {
        self.with_reader(|c| {
            let sfx = suffix(tier);
            let sql = format!(
                "SELECT bucket FROM traffic_stats_{sfx}     WHERE bucket < ?1
                 UNION
                 SELECT bucket FROM traffic_paths_{sfx}     WHERE bucket < ?1
                 UNION
                 SELECT bucket FROM traffic_breakdown_{sfx} WHERE bucket < ?1
                 ORDER BY 1"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((cutoff,), |r| r.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn stats_range(
        &self,
        tier: Tier,
        app: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<StatsRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {STATS_COLS} FROM traffic_stats_{} \
                 WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3 ORDER BY bucket",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to), map_stats_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn paths_range(
        &self,
        tier: Tier,
        app: &str,
        from: i64,
        to: i64,
        limit: usize,
    ) -> Result<Vec<PathRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {PATHS_COLS} FROM traffic_paths_{} \
                 WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3 ORDER BY bucket LIMIT ?4",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to, limit as i64), map_path_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn breakdown_range(
        &self,
        tier: Tier,
        app: &str,
        dim: &str,
        from: i64,
        to: i64,
        limit: usize,
    ) -> Result<Vec<BreakdownRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {BREAKDOWN_COLS} FROM traffic_breakdown_{} \
                 WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3 AND dimension = ?4 \
                 ORDER BY requests DESC LIMIT ?5",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to, dim, limit as i64), map_breakdown_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Every `tier` stats row in the half-open bucket window `[from, to)`,
    /// across *all* apps. Compaction needs the whole window regardless of
    /// app, so unlike [`Self::stats_range`] this takes no app filter and no
    /// limit.
    pub fn stats_rows_between(
        &self,
        tier: Tier,
        from: i64,
        to: i64,
    ) -> Result<Vec<StatsRow>, StoreError> {
        self.with_reader(|c| select_stats(c, tier, from, to))
    }

    /// Every `tier` path row in the half-open bucket window `[from, to)`,
    /// across all apps. See [`Self::stats_rows_between`].
    pub fn paths_rows_between(
        &self,
        tier: Tier,
        from: i64,
        to: i64,
    ) -> Result<Vec<PathRow>, StoreError> {
        self.with_reader(|c| select_paths(c, tier, from, to))
    }

    /// Every `tier` breakdown row in the half-open bucket window
    /// `[from, to)`, across all apps and all dimensions. See
    /// [`Self::stats_rows_between`].
    pub fn breakdown_rows_between(
        &self,
        tier: Tier,
        from: i64,
        to: i64,
    ) -> Result<Vec<BreakdownRow>, StoreError> {
        self.with_reader(|c| select_breakdown(c, tier, from, to))
    }

    /// Deletes every `tier` row (stats + paths + breakdown) strictly older
    /// than `cutoff`; returns the total number of rows removed.
    pub fn delete_before(&self, tier: Tier, cutoff: i64) -> Result<usize, StoreError> {
        let mut total = 0;
        for table in ["traffic_stats", "traffic_paths", "traffic_breakdown"] {
            total += self.delete_table_before(table, tier, cutoff)?;
        }
        Ok(total)
    }

    /// Applies the per-tier retention windows (48h / 30d / 395d), deleting
    /// everything older than `now - window` in each tier; returns rows removed.
    /// Pure SQL deletion — no sketch merging (that lives in `traffic::compaction`).
    pub fn retention(
        &self,
        now: i64,
        m1_hours: u32,
        h1_days: u32,
        d1_days: u32,
    ) -> Result<usize, StoreError> {
        const HOUR_MS: i64 = 3_600_000;
        const DAY_MS: i64 = 86_400_000;
        // Saturating throughout: a pathologically large configured window
        // must clamp the cutoff at i64::MIN (delete nothing), never wrap
        // around into a future timestamp (delete everything).
        let m1_cutoff = now.saturating_sub((m1_hours as i64).saturating_mul(HOUR_MS));
        let h1_cutoff = now.saturating_sub((h1_days as i64).saturating_mul(DAY_MS));
        let d1_cutoff = now.saturating_sub((d1_days as i64).saturating_mul(DAY_MS));

        Ok(self.delete_before(Tier::M1, m1_cutoff)?
            + self.delete_before(Tier::H1, h1_cutoff)?
            + self.delete_before(Tier::D1, d1_cutoff)?)
    }

    fn delete_table_before(
        &self,
        table: &str,
        tier: Tier,
        cutoff: i64,
    ) -> Result<usize, StoreError> {
        self.with_conn(|c| {
            let sql = format!("DELETE FROM {}_{} WHERE bucket < ?1", table, suffix(tier));
            let mut stmt = c.prepare_cached(&sql)?;
            Ok(stmt.execute((cutoff,))?)
        })
    }

    /// Test-only escape hatch: runs `sql` on the writer connection. Used to
    /// inject a failure (a trigger that raises) into the middle of
    /// [`Self::compact_window`]'s transaction so its atomicity can be tested
    /// for real rather than asserted.
    #[cfg(test)]
    fn execute_batch_for_test(&self, sql: &str) -> Result<(), StoreError> {
        self.with_conn(|c| Ok(c.execute_batch(sql)?))
    }

    /// Distinct app UUIDs with traffic, across every tier. The `UNION` is
    /// required: compaction deletes the `1m` rows it consumes, so `1m` alone
    /// would hide any app idle longer than an hour whose history lives in `1h`/`1d`.
    pub fn apps(&self) -> Result<Vec<String>, StoreError> {
        self.with_reader(|c| {
            let mut stmt = c.prepare_cached(
                "SELECT DISTINCT app FROM traffic_stats_1m
                 UNION SELECT DISTINCT app FROM traffic_stats_1h
                 UNION SELECT DISTINCT app FROM traffic_stats_1d
                 ORDER BY app",
            )?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }
}

/// Upserts a batch into `tier`'s three tables on an existing connection. Shared
/// by `write_rows` and `compact_window` so flush/compaction can't drift: on
/// conflict counters *sum*, sketch blobs *replace* (compaction recomputes, so relies on neither).
fn insert_rows(
    conn: &Connection,
    tier: Tier,
    stats: &[StatsRow],
    paths: &[PathRow],
    breakdown: &[BreakdownRow],
) -> Result<(), StoreError> {
    let sfx = suffix(tier);
    {
        let sql = format!(
            "INSERT INTO traffic_stats_{sfx}
                (bucket, app, host, requests, bytes_in, bytes_out, s2xx, s3xx, s4xx, s5xx, latency_tdigest, uniques_hll)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(bucket, app, host) DO UPDATE SET
                requests = requests + excluded.requests,
                bytes_in = bytes_in + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out,
                s2xx = s2xx + excluded.s2xx,
                s3xx = s3xx + excluded.s3xx,
                s4xx = s4xx + excluded.s4xx,
                s5xx = s5xx + excluded.s5xx,
                latency_tdigest = excluded.latency_tdigest,
                uniques_hll = excluded.uniques_hll"
        );
        let mut ins = conn.prepare_cached(&sql)?;
        for r in stats {
            ins.execute((
                r.bucket,
                &r.app,
                &r.host,
                r.requests,
                r.bytes_in,
                r.bytes_out,
                r.s2xx,
                r.s3xx,
                r.s4xx,
                r.s5xx,
                &r.latency_tdigest,
                &r.uniques_hll,
            ))?;
        }
    }
    {
        let sql = format!(
            "INSERT INTO traffic_paths_{sfx}
                (bucket, app, path, requests, bytes_out, latency_tdigest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(bucket, app, path) DO UPDATE SET
                requests = requests + excluded.requests,
                bytes_out = bytes_out + excluded.bytes_out,
                latency_tdigest = excluded.latency_tdigest"
        );
        let mut ins = conn.prepare_cached(&sql)?;
        for r in paths {
            ins.execute((
                r.bucket,
                &r.app,
                &r.path,
                r.requests,
                r.bytes_out,
                &r.latency_tdigest,
            ))?;
        }
    }
    {
        let sql = format!(
            "INSERT INTO traffic_breakdown_{sfx}
                (bucket, app, dimension, value, requests, bytes_out)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(bucket, app, dimension, value) DO UPDATE SET
                requests = requests + excluded.requests,
                bytes_out = bytes_out + excluded.bytes_out"
        );
        let mut ins = conn.prepare_cached(&sql)?;
        for r in breakdown {
            ins.execute((
                r.bucket,
                &r.app,
                &r.dimension,
                &r.value,
                r.requests,
                r.bytes_out,
            ))?;
        }
    }
    Ok(())
}

// Column lists and row-mapping fns are shared between the app-filtered range
// queries ([`AnalyticsStore::stats_range`] et al.) and the unfiltered
// connection-scoped selects below, so a schema column can only be read one
// way. The `?N` order in every SELECT must match the `r.get(N)` order here.
const STATS_COLS: &str = "bucket, app, host, requests, bytes_in, bytes_out, s2xx, s3xx, s4xx, s5xx, latency_tdigest, uniques_hll";
const PATHS_COLS: &str = "bucket, app, path, requests, bytes_out, latency_tdigest";
const BREAKDOWN_COLS: &str = "bucket, app, dimension, value, requests, bytes_out";

fn map_stats_row(r: &rusqlite::Row) -> rusqlite::Result<StatsRow> {
    Ok(StatsRow {
        bucket: r.get(0)?,
        app: r.get(1)?,
        host: r.get(2)?,
        requests: r.get(3)?,
        bytes_in: r.get(4)?,
        bytes_out: r.get(5)?,
        s2xx: r.get(6)?,
        s3xx: r.get(7)?,
        s4xx: r.get(8)?,
        s5xx: r.get(9)?,
        latency_tdigest: r.get(10)?,
        uniques_hll: r.get(11)?,
    })
}

fn map_path_row(r: &rusqlite::Row) -> rusqlite::Result<PathRow> {
    Ok(PathRow {
        bucket: r.get(0)?,
        app: r.get(1)?,
        path: r.get(2)?,
        requests: r.get(3)?,
        bytes_out: r.get(4)?,
        latency_tdigest: r.get(5)?,
    })
}

fn map_breakdown_row(r: &rusqlite::Row) -> rusqlite::Result<BreakdownRow> {
    Ok(BreakdownRow {
        bucket: r.get(0)?,
        app: r.get(1)?,
        dimension: r.get(2)?,
        value: r.get(3)?,
        requests: r.get(4)?,
        bytes_out: r.get(5)?,
    })
}

/// `tier` stats rows in the half-open bucket window `[from, to)`, all apps.
/// Connection-scoped so the same query can run on the read-only connection
/// ([`AnalyticsStore::stats_rows_between`]) or inside a writer transaction
/// ([`AnalyticsStore::compact_window`]).
fn select_stats(
    conn: &Connection,
    tier: Tier,
    from: i64,
    to: i64,
) -> Result<Vec<StatsRow>, StoreError> {
    let sql = format!(
        "SELECT {STATS_COLS} FROM traffic_stats_{} \
         WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), map_stats_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// See [`select_stats`].
fn select_paths(
    conn: &Connection,
    tier: Tier,
    from: i64,
    to: i64,
) -> Result<Vec<PathRow>, StoreError> {
    let sql = format!(
        "SELECT {PATHS_COLS} FROM traffic_paths_{} \
         WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), map_path_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// See [`select_stats`].
fn select_breakdown(
    conn: &Connection,
    tier: Tier,
    from: i64,
    to: i64,
) -> Result<Vec<BreakdownRow>, StoreError> {
    let sql = format!(
        "SELECT {BREAKDOWN_COLS} FROM traffic_breakdown_{} \
         WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), map_breakdown_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Deletes `tier` rows of `table` in the half-open window `[from, to)`.
/// Range-scoped, not `< cutoff`: [`AnalyticsStore::compact_window`] must
/// delete exactly the rows it just consumed and nothing beyond them, or a
/// bucket still queued for a later pass would be dropped un-compacted.
fn delete_range(
    conn: &Connection,
    table: &str,
    tier: Tier,
    from: i64,
    to: i64,
) -> Result<usize, StoreError> {
    let sql = format!(
        "DELETE FROM {}_{} WHERE bucket >= ?1 AND bucket < ?2",
        table,
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    Ok(stmt.execute((from, to))?)
}

#[cfg(test)]
mod tests;
