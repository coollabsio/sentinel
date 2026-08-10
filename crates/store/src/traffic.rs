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
mod tests {
    use super::*;

    fn stats_row(
        bucket: i64,
        app: &str,
        host: &str,
        requests: i64,
        tdigest: Vec<u8>,
        hll: Vec<u8>,
    ) -> StatsRow {
        StatsRow {
            bucket,
            app: app.into(),
            host: host.into(),
            requests,
            bytes_in: 10,
            bytes_out: 20,
            s2xx: requests,
            s3xx: 0,
            s4xx: 0,
            s5xx: 0,
            latency_tdigest: tdigest,
            uniques_hll: hll,
        }
    }

    /// Design spec §9: `wal_autocheckpoint=0` (a later task's timed
    /// `wal_checkpoint(TRUNCATE)` owns checkpointing instead) and
    /// `auto_vacuum=INCREMENTAL` (reported back as `2`) must both actually
    /// take effect on the writer connection, not just be sent and ignored.
    #[test]
    fn writer_pragmas_take_effect() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let (autocheckpoint, auto_vacuum) = s
            .with_conn(|conn| {
                let autocheckpoint: i64 =
                    conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))?;
                let auto_vacuum: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
                Ok((autocheckpoint, auto_vacuum))
            })
            .unwrap();
        assert_eq!(
            autocheckpoint, 0,
            "automatic checkpointing must be disabled; a later task's timed \
             wal_checkpoint(TRUNCATE) owns it instead"
        );
        assert_eq!(
            auto_vacuum, 2,
            "auto_vacuum must be INCREMENTAL (SQLite reports this mode as 2)"
        );
        // busy_timeout has no readback pragma in rusqlite; init_conn sets it
        // via `conn.busy_timeout(Duration::from_secs(5))`, mirroring the
        // reader connection's setting above.
    }

    #[test]
    fn flush_and_read_back() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let stats = vec![stats_row(60_000, "a", "h", 5, vec![1, 2], vec![3, 4])];
        s.flush_window(&stats, &[], &[]).unwrap();
        let got = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].requests, 5);
        assert_eq!(got[0].latency_tdigest, vec![1, 2]);
    }

    /// Two flushes of the same (bucket, app, host): `ON CONFLICT` must sum
    /// the count/byte columns but replace (not merge) the sketch blobs with
    /// whatever the latest flush handed over.
    #[test]
    fn upsert_accumulates_on_conflict() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let first = stats_row(60_000, "a", "h", 5, vec![1, 2], vec![9, 9]);
        s.flush_window(&[first], &[], &[]).unwrap();

        let second = stats_row(60_000, "a", "h", 3, vec![7, 8], vec![10, 10]);
        s.flush_window(&[second], &[], &[]).unwrap();

        let got = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
        assert_eq!(
            got.len(),
            1,
            "same (bucket, app, host) must upsert in place, not duplicate"
        );
        assert_eq!(got[0].requests, 8);
        assert_eq!(got[0].bytes_in, 20);
        assert_eq!(got[0].bytes_out, 40);
        assert_eq!(got[0].s2xx, 8);
        assert_eq!(
            got[0].latency_tdigest,
            vec![7, 8],
            "sketch blobs replace, they don't concatenate/merge byte-wise"
        );
        assert_eq!(got[0].uniques_hll, vec![10, 10]);
    }

    #[test]
    fn apps_lists_distinct() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let rows = vec![
            stats_row(60_000, "a", "h1", 1, vec![], vec![]),
            stats_row(60_000, "a", "h2", 1, vec![], vec![]),
            stats_row(60_000, "b", "h1", 1, vec![], vec![]),
            stats_row(120_000, "a", "h1", 1, vec![], vec![]),
        ];
        s.flush_window(&rows, &[], &[]).unwrap();
        let apps = s.apps().unwrap();
        assert_eq!(apps, vec!["a".to_string(), "b".to_string()]);
    }

    /// An app whose `1m` rows compaction has already consumed and deleted must
    /// still be listed — its history lives in the coarser tiers and is fully
    /// queryable, so omitting it from `apps()` would make it unreachable
    /// through the UI while every other endpoint still answered for it.
    ///
    /// The coarse rows are written directly rather than via `flush_window`
    /// (which only ever writes `1m`), reproducing exactly the state
    /// compaction leaves behind: coarse rows present, finer rows gone.
    #[test]
    fn apps_lists_apps_whose_data_only_survives_in_the_coarse_tiers() {
        let s = AnalyticsStore::open_in_memory().unwrap();

        // Recently active: still un-compacted, so present in `1m`.
        s.flush_window(
            &[stats_row(60_000, "recent", "h1", 1, vec![], vec![])],
            &[],
            &[],
        )
        .unwrap();
        // Idle for hours: compacted up to `1h`, its `1m` rows deleted.
        s.write_rows(
            Tier::H1,
            &[stats_row(3_600_000, "hourly-only", "h1", 1, vec![], vec![])],
            &[],
            &[],
        )
        .unwrap();
        // Idle for days: compacted all the way to `1d`.
        s.write_rows(
            Tier::D1,
            &[stats_row(86_400_000, "daily-only", "h1", 1, vec![], vec![])],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(
            s.apps().unwrap(),
            vec![
                "daily-only".to_string(),
                "hourly-only".to_string(),
                "recent".to_string()
            ],
            "every tier contributes; a 1m-only query would have returned just `recent`"
        );
    }

    fn path_row(bucket: i64, app: &str, path: &str, requests: i64) -> PathRow {
        PathRow {
            bucket,
            app: app.into(),
            path: path.into(),
            requests,
            bytes_out: 20,
            latency_tdigest: vec![1],
        }
    }

    fn breakdown_row(
        bucket: i64,
        app: &str,
        dim: &str,
        value: &str,
        requests: i64,
    ) -> BreakdownRow {
        BreakdownRow {
            bucket,
            app: app.into(),
            dimension: dim.into(),
            value: value.into(),
            requests,
            bytes_out: 20,
        }
    }

    const HOUR_MS: i64 = 3_600_000;
    const DAY_MS: i64 = 86_400_000;

    /// The `flush_window` -> `write_rows(Tier::M1, ..)` refactor must not
    /// change `_1m` behavior: both entry points write the same rows to the
    /// same tier, and both still upsert-accumulate on conflict.
    #[test]
    fn write_rows_m1_matches_flush_window() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[stats_row(60_000, "a", "h", 5, vec![1, 2], vec![3, 4])],
            &[path_row(60_000, "a", "/x", 5)],
            &[breakdown_row(60_000, "a", "country", "US", 5)],
        )
        .unwrap();
        s.write_rows(
            Tier::M1,
            &[stats_row(60_000, "a", "h", 3, vec![7, 8], vec![9, 9])],
            &[path_row(60_000, "a", "/x", 3)],
            &[breakdown_row(60_000, "a", "country", "US", 3)],
        )
        .unwrap();

        let stats = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
        assert_eq!(stats.len(), 1, "write_rows must target the same _1m table");
        assert_eq!(stats[0].requests, 8, "counts accumulate identically");
        assert_eq!(stats[0].latency_tdigest, vec![7, 8], "sketch blobs replace");

        let paths = s.paths_range(Tier::M1, "a", 0, 120_000, 10).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].requests, 8);

        let bd = s
            .breakdown_range(Tier::M1, "a", "country", 0, 120_000, 10)
            .unwrap();
        assert_eq!(bd.len(), 1);
        assert_eq!(bd[0].requests, 8);
    }

    /// `write_rows` addresses whichever tier it is handed; a `1h` write must
    /// not leak into `1m` (or vice versa).
    #[test]
    fn write_rows_targets_the_requested_tier() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.write_rows(
            Tier::H1,
            &[stats_row(HOUR_MS, "a", "h", 7, vec![], vec![])],
            &[path_row(HOUR_MS, "a", "/x", 7)],
            &[breakdown_row(HOUR_MS, "a", "country", "US", 7)],
        )
        .unwrap();

        assert_eq!(s.stats_range(Tier::H1, "a", 0, i64::MAX).unwrap().len(), 1);
        assert!(
            s.stats_range(Tier::M1, "a", 0, i64::MAX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.paths_range(Tier::H1, "a", 0, i64::MAX, 10).unwrap().len(),
            1
        );
        assert!(
            s.paths_range(Tier::M1, "a", 0, i64::MAX, 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.breakdown_range(Tier::H1, "a", "country", 0, i64::MAX, 10)
                .unwrap()
                .len(),
            1
        );
        assert!(
            s.breakdown_range(Tier::M1, "a", "country", 0, i64::MAX, 10)
                .unwrap()
                .is_empty()
        );
    }

    /// The `*_rows_between` bulk reads are unfiltered by app — compaction
    /// needs every app's rows in the window, not one app's.
    #[test]
    fn rows_between_spans_all_apps_and_honors_bounds() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[
                stats_row(100, "a", "h", 1, vec![], vec![]),
                stats_row(200, "b", "h", 1, vec![], vec![]),
                stats_row(300, "c", "h", 1, vec![], vec![]),
            ],
            &[
                path_row(100, "a", "/x", 1),
                path_row(200, "b", "/y", 1),
                path_row(300, "c", "/z", 1),
            ],
            &[
                breakdown_row(100, "a", "country", "US", 1),
                breakdown_row(200, "b", "country", "DE", 1),
                breakdown_row(300, "c", "country", "FR", 1),
            ],
        )
        .unwrap();

        let stats = s.stats_rows_between(Tier::M1, i64::MIN, 300).unwrap();
        let apps: Vec<&str> = stats.iter().map(|r| r.app.as_str()).collect();
        assert_eq!(
            apps,
            vec!["a", "b"],
            "half-open [from, to): bucket 300 is excluded, all apps included"
        );

        let paths = s.paths_rows_between(Tier::M1, i64::MIN, 300).unwrap();
        assert_eq!(paths.len(), 2);
        let bd = s.breakdown_rows_between(Tier::M1, i64::MIN, 300).unwrap();
        assert_eq!(bd.len(), 2);

        assert_eq!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            3
        );
    }

    /// `delete_before` is strictly-older-than: the row exactly at the cutoff
    /// survives, as do newer rows.
    #[test]
    fn delete_before_removes_only_strictly_older_rows() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[
                stats_row(100, "a", "h", 1, vec![], vec![]),
                stats_row(200, "a", "h", 1, vec![], vec![]),
                stats_row(300, "a", "h", 1, vec![], vec![]),
            ],
            &[
                path_row(100, "a", "/x", 1),
                path_row(200, "a", "/x", 1),
                path_row(300, "a", "/x", 1),
            ],
            &[
                breakdown_row(100, "a", "country", "US", 1),
                breakdown_row(200, "a", "country", "US", 1),
                breakdown_row(300, "a", "country", "US", 1),
            ],
        )
        .unwrap();

        let deleted = s.delete_before(Tier::M1, 200).unwrap();
        assert_eq!(deleted, 3, "one row per table, only the bucket-100 rows");

        let stats = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(
            stats.iter().map(|r| r.bucket).collect::<Vec<_>>(),
            vec![200, 300],
            "the row exactly at the cutoff must survive"
        );
        assert_eq!(
            s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            s.breakdown_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            2
        );
    }

    /// Per-table deletes are tier-scoped: deleting from `1m` leaves `1h`
    /// and `1d` untouched.
    #[test]
    fn delete_before_is_tier_scoped() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        for tier in [Tier::M1, Tier::H1, Tier::D1] {
            s.write_rows(
                tier,
                &[stats_row(100, "a", "h", 1, vec![], vec![])],
                &[path_row(100, "a", "/x", 1)],
                &[breakdown_row(100, "a", "country", "US", 1)],
            )
            .unwrap();
        }

        assert_eq!(
            s.delete_before(Tier::M1, 200).unwrap(),
            3,
            "one row per table (stats + paths + breakdown), all in the 1m tier"
        );

        assert!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            1
        );
    }

    /// Retention applies a per-tier cutoff (`now - window`) across all three
    /// tiers in one call, keeping rows at or newer than each cutoff.
    #[test]
    fn retention_applies_per_tier_cutoffs() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let now = 1_000 * DAY_MS;

        // 1m tier: 48h window -> 47h old survives, 49h old goes.
        s.write_rows(
            Tier::M1,
            &[
                stats_row(now - 47 * HOUR_MS, "a", "h", 1, vec![], vec![]),
                stats_row(now - 49 * HOUR_MS, "a", "h", 1, vec![], vec![]),
            ],
            &[
                path_row(now - 47 * HOUR_MS, "a", "/x", 1),
                path_row(now - 49 * HOUR_MS, "a", "/x", 1),
            ],
            &[],
        )
        .unwrap();
        // 1h tier: 30d window -> 29d survives, 31d goes.
        s.write_rows(
            Tier::H1,
            &[
                stats_row(now - 29 * DAY_MS, "a", "h", 1, vec![], vec![]),
                stats_row(now - 31 * DAY_MS, "a", "h", 1, vec![], vec![]),
            ],
            &[],
            &[],
        )
        .unwrap();
        // 1d tier: 395d window -> 394d survives, 396d goes.
        s.write_rows(
            Tier::D1,
            &[
                stats_row(now - 394 * DAY_MS, "a", "h", 1, vec![], vec![]),
                stats_row(now - 396 * DAY_MS, "a", "h", 1, vec![], vec![]),
            ],
            &[],
            &[breakdown_row(now - 396 * DAY_MS, "a", "country", "US", 1)],
        )
        .unwrap();

        let deleted = s.retention(now, 48, 30, 395).unwrap();
        assert_eq!(
            deleted, 5,
            "1m: 1 stats + 1 paths, 1h: 1 stats, 1d: 1 stats + 1 breakdown"
        );

        let m1 = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].bucket, now - 47 * HOUR_MS);
        assert_eq!(
            s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            1
        );

        let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(h1.len(), 1);
        assert_eq!(h1[0].bucket, now - 29 * DAY_MS);

        let d1 = s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].bucket, now - 394 * DAY_MS);
        assert!(
            s.breakdown_rows_between(Tier::D1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// A retention window wide enough to predate the epoch must not overflow
    /// into a positive cutoff (which would delete everything).
    #[test]
    fn retention_saturates_instead_of_overflowing() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.write_rows(
            Tier::D1,
            &[stats_row(0, "a", "h", 1, vec![], vec![])],
            &[],
            &[],
        )
        .unwrap();
        // u32::MAX days is ~1.1e7 years of milliseconds: the subtraction must
        // saturate at i64::MIN, not wrap.
        let deleted = s
            .retention(i64::MIN + 1, u32::MAX, u32::MAX, u32::MAX)
            .unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(
            s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            1
        );
    }

    /// `compact_window` is read + merge + write + delete in one transaction:
    /// the callback sees the finer rows, and on return the coarse rows exist
    /// and the finer ones in that window are gone.
    #[test]
    fn compact_window_reads_merges_writes_and_deletes() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[
                stats_row(HOUR_MS, "a", "h", 2, vec![1], vec![2]),
                stats_row(HOUR_MS + 60_000, "a", "h", 3, vec![3], vec![4]),
            ],
            &[path_row(HOUR_MS, "a", "/x", 4)],
            &[breakdown_row(HOUR_MS, "a", "country", "US", 6)],
        )
        .unwrap();

        let written = s
            .compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, dst| {
                assert_eq!(src.stats.len(), 2, "callback sees the finer rows");
                assert_eq!(src.paths.len(), 1);
                assert_eq!(src.breakdown.len(), 1);
                assert_eq!(src.len(), 4);
                assert!(dst.is_empty(), "nothing in the coarse bucket yet");
                // Trivial "merge": one summed stats row for the window.
                TierRows {
                    stats: vec![stats_row(HOUR_MS, "a", "h", 5, vec![9], vec![9])],
                    paths: src.paths,
                    breakdown: src.breakdown,
                }
            })
            .unwrap();
        assert_eq!(written, 3, "1 stats + 1 paths + 1 breakdown");

        let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(h1.len(), 1);
        assert_eq!(h1[0].requests, 5);
        assert!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty(),
            "consumed finer rows are deleted in the same transaction"
        );
        assert!(
            s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
        assert!(
            s.breakdown_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// The delete is window-scoped, not `< to_bucket`: rows *older* than the
    /// window belong to a coarse bucket that has not been compacted yet, and
    /// dropping them here would lose them entirely.
    #[test]
    fn compact_window_deletes_only_its_own_window() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[
                stats_row(0, "a", "h", 1, vec![], vec![]),
                stats_row(HOUR_MS, "a", "h", 2, vec![], vec![]),
                stats_row(2 * HOUR_MS, "a", "h", 4, vec![], vec![]),
            ],
            &[],
            &[],
        )
        .unwrap();

        s.compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
            TierRows {
                stats: src.stats,
                ..Default::default()
            }
        })
        .unwrap();

        let left = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(
            left.iter().map(|r| r.bucket).collect::<Vec<_>>(),
            vec![0, 2 * HOUR_MS],
            "the earlier and later buckets both survive for their own passes"
        );
    }

    /// An empty window writes nothing and reports zero.
    #[test]
    fn compact_window_on_an_empty_window_is_a_noop() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let written = s
            .compact_window(Tier::M1, Tier::H1, 0, HOUR_MS, |_, _| {
                panic!("merge must not run for an empty window")
            })
            .unwrap();
        assert_eq!(written, 0);
        assert!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// Atomicity, tested for real: a `BEFORE DELETE` trigger that raises
    /// makes the delete half of `compact_window` fail *after* the coarse
    /// rows have been inserted. The whole transaction must roll back — no
    /// coarse rows, finer rows intact — so that the retry recomputes the
    /// same roll-up instead of adding a second copy of it.
    #[test]
    fn compact_window_rolls_back_the_write_when_the_delete_fails() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[stats_row(HOUR_MS, "a", "h", 5, vec![1], vec![2])],
            &[path_row(HOUR_MS, "a", "/x", 5)],
            &[breakdown_row(HOUR_MS, "a", "country", "US", 5)],
        )
        .unwrap();

        s.execute_batch_for_test(
            "CREATE TRIGGER boom BEFORE DELETE ON traffic_stats_1m
             BEGIN SELECT RAISE(ABORT, 'simulated crash'); END;",
        )
        .unwrap();

        let err = s
            .compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
                TierRows {
                    stats: src.stats,
                    paths: src.paths,
                    breakdown: src.breakdown,
                }
            })
            .unwrap_err();
        assert!(
            format!("{err}").contains("simulated crash"),
            "expected the injected failure, got {err}"
        );

        assert!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty(),
            "the coarse write must roll back with the failed delete, or the \
             retry would double-count this bucket"
        );
        assert!(
            s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
        assert!(
            s.breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            1,
            "the finer rows survive for the retry"
        );

        // With the fault removed, the retry produces exactly one coarse row.
        s.execute_batch_for_test("DROP TRIGGER boom").unwrap();
        s.compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
            TierRows {
                stats: src.stats,
                paths: src.paths,
                breakdown: src.breakdown,
            }
        })
        .unwrap();
        let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(h1.len(), 1);
        assert_eq!(h1[0].requests, 5, "retry recomputes, it does not add");
    }

    /// `distinct_buckets_before` unions all three tables, dedupes, sorts, and
    /// honors the strict `< cutoff` bound.
    #[test]
    fn distinct_buckets_before_unions_all_three_tables() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        s.flush_window(
            &[
                stats_row(100, "a", "h", 1, vec![], vec![]),
                stats_row(100, "b", "h", 1, vec![], vec![]),
                stats_row(300, "a", "h", 1, vec![], vec![]),
            ],
            &[path_row(200, "a", "/x", 1)],
            &[breakdown_row(400, "a", "country", "US", 1)],
        )
        .unwrap();

        assert_eq!(
            s.distinct_buckets_before(Tier::M1, 400).unwrap(),
            vec![100, 200, 300],
            "deduped across apps, unioned across tables, cutoff exclusive"
        );
        assert_eq!(
            s.distinct_buckets_before(Tier::M1, i64::MAX).unwrap(),
            vec![100, 200, 300, 400]
        );
        assert!(
            s.distinct_buckets_before(Tier::H1, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn paths_and_breakdown_flush_and_range() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let paths = vec![path_row(60_000, "a", "/x", 2)];
        let breakdown = vec![breakdown_row(60_000, "a", "country", "US", 2)];
        s.flush_window(&[], &paths, &breakdown).unwrap();

        let got_paths = s.paths_range(Tier::M1, "a", 0, 120_000, 10).unwrap();
        assert_eq!(got_paths.len(), 1);
        assert_eq!(got_paths[0].path, "/x");

        let got_breakdown = s
            .breakdown_range(Tier::M1, "a", "country", 0, 120_000, 10)
            .unwrap();
        assert_eq!(got_breakdown.len(), 1);
        assert_eq!(got_breakdown[0].value, "US");
    }
}
