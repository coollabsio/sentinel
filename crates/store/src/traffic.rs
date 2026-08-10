//! `analytics.sqlite`: traffic-analytics time series (Coolify traffic
//! dashboard), kept in a store separate from `metrics.sqlite`'s [`Store`] so
//! the once-a-minute flush's WAL churn never contends with the collector's
//! 5s metrics inserts (design spec §3/§4).
//!
//! Three roll-up tiers share one shape per table family:
//! - `traffic_stats_<tier>`: one row per (bucket, app, host) — request
//!   counts, byte counters, status-class counters, and two pre-merged
//!   sketches (t-digest for latency, HyperLogLog++ for unique visitors).
//! - `traffic_paths_<tier>`: one row per (bucket, app, path) — top-N path
//!   traffic with its own latency t-digest.
//! - `traffic_breakdown_<tier>`: one tall table per (bucket, app, dimension,
//!   value) for every other cardinality-bound dimension (country, device,
//!   status class, ...), instead of a wide table per dimension.
//!
//! [`AnalyticsStore::flush_window`] only ever writes the `1m` tier. Rolling
//! `1m` up into `1h`/`1d` is compaction's job, and it lives in the `traffic`
//! crate (`traffic::compaction`) because merging the persisted sketch BLOBs
//! needs that crate's sketch types — a `store → traffic` dependency would be
//! a cycle. This module therefore exposes only the raw primitives compaction
//! drives: [`AnalyticsStore::distinct_buckets_before`] to enumerate the
//! coarse buckets that have finer-tier data waiting, and
//! [`AnalyticsStore::compact_window`] to move one such bucket up a tier
//! atomically — it reads the finer rows *and* whatever the coarse bucket
//! already holds, calls back into the `traffic` crate to merge them (the one
//! step that needs the sketch types), replaces the coarse bucket with the
//! result, and deletes what it consumed, all inside one transaction on the
//! writer connection. [`AnalyticsStore::stats_rows_between`] and friends
//! remain for read-only inspection (and tests).
//! [`AnalyticsStore::retention`] is pure SQL deletion with no sketch
//! involvement, so it does live here.

use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::StoreError;

/// Typed, STRICT schema for all three roll-up tiers. `1h`/`1d` tables are
/// written by compaction (via `write_rows`), while `flush_window` only ever
/// inserts into the `1m` tables.
pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS traffic_stats_1m (
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

CREATE TABLE IF NOT EXISTS traffic_stats_1h (
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

CREATE TABLE IF NOT EXISTS traffic_stats_1d (
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

CREATE TABLE IF NOT EXISTS traffic_paths_1m (
    bucket          INTEGER NOT NULL,
    app             TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    requests        INTEGER NOT NULL,
    bytes_out       INTEGER NOT NULL,
    latency_tdigest BLOB    NOT NULL,
    PRIMARY KEY (bucket, app, path)
) STRICT;

CREATE TABLE IF NOT EXISTS traffic_paths_1h (
    bucket          INTEGER NOT NULL,
    app             TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    requests        INTEGER NOT NULL,
    bytes_out       INTEGER NOT NULL,
    latency_tdigest BLOB    NOT NULL,
    PRIMARY KEY (bucket, app, path)
) STRICT;

CREATE TABLE IF NOT EXISTS traffic_paths_1d (
    bucket          INTEGER NOT NULL,
    app             TEXT    NOT NULL,
    path            TEXT    NOT NULL,
    requests        INTEGER NOT NULL,
    bytes_out       INTEGER NOT NULL,
    latency_tdigest BLOB    NOT NULL,
    PRIMARY KEY (bucket, app, path)
) STRICT;

CREATE TABLE IF NOT EXISTS traffic_breakdown_1m (
    bucket    INTEGER NOT NULL,
    app       TEXT    NOT NULL,
    dimension TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    requests  INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    PRIMARY KEY (bucket, app, dimension, value)
) STRICT;

CREATE TABLE IF NOT EXISTS traffic_breakdown_1h (
    bucket    INTEGER NOT NULL,
    app       TEXT    NOT NULL,
    dimension TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    requests  INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    PRIMARY KEY (bucket, app, dimension, value)
) STRICT;

CREATE TABLE IF NOT EXISTS traffic_breakdown_1d (
    bucket    INTEGER NOT NULL,
    app       TEXT    NOT NULL,
    dimension TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    requests  INTEGER NOT NULL,
    bytes_out INTEGER NOT NULL,
    PRIMARY KEY (bucket, app, dimension, value)
) STRICT;

CREATE INDEX IF NOT EXISTS idx_ts_1m_app_bucket ON traffic_stats_1m     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_ts_1h_app_bucket ON traffic_stats_1h     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_ts_1d_app_bucket ON traffic_stats_1d     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_tp_1m_app_bucket ON traffic_paths_1m     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_tp_1h_app_bucket ON traffic_paths_1h     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_tp_1d_app_bucket ON traffic_paths_1d     (app, bucket);
CREATE INDEX IF NOT EXISTS idx_tb_1m_app_bucket ON traffic_breakdown_1m (app, bucket, dimension);
CREATE INDEX IF NOT EXISTS idx_tb_1h_app_bucket ON traffic_breakdown_1h (app, bucket, dimension);
CREATE INDEX IF NOT EXISTS idx_tb_1d_app_bucket ON traffic_breakdown_1d (app, bucket, dimension);
"#;

pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(DDL)
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

    /// Writes a batch of aggregated rows into `tier`'s three tables in a
    /// single transaction. The minute-flush uses [`Tier::M1`] (via
    /// [`Self::flush_window`]); compaction reaches the same upsert through
    /// [`Self::compact_window`], which additionally deletes the consumed
    /// finer tier inside the same transaction.
    ///
    /// `ON CONFLICT` sums the count/byte columns but *replaces* the sketch
    /// blobs (`latency_tdigest`, `uniques_hll`) with the incoming value:
    /// callers already hand over fully-merged sketches for the window, so
    /// summing raw bytes would be meaningless. Compaction never relies on
    /// either rule — it clears the destination window first, so its rows
    /// cannot conflict with a previous pass's; see [`Self::compact_window`].
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

    /// Rolls one coarse bucket up a tier, atomically.
    ///
    /// Inside a single transaction on the *writer* connection (so no other
    /// writer — another compaction pass, the minute flush, retention — can
    /// interleave):
    ///
    /// 1. reads every `from_tier` row whose bucket is in `[from_bucket,
    ///    to_bucket)`, across all three tables and all apps;
    /// 2. reads the `to_tier` rows in the *same* window — whatever an earlier
    ///    pass already left in the destination bucket;
    /// 3. hands both to `merge(finer, coarse)`, which is the `traffic`
    ///    crate's sketch-aware roll-up (the one step that cannot live in this
    ///    crate without a dependency cycle) and which returns the *complete*
    ///    new content of the destination window;
    /// 4. deletes the destination window and writes the merged rows in its
    ///    place;
    /// 5. deletes the consumed `from_tier` rows in the same window;
    /// 6. commits.
    ///
    /// Returns the number of coarser rows written (0 if the window held no
    /// finer rows at all, in which case the destination is not even read and
    /// nothing is written or deleted).
    ///
    /// **The merge is a recompute, not an increment.** Step 2 is what makes a
    /// second pass over an already-compacted bucket safe. A finer row can
    /// legitimately arrive after its coarse bucket was rolled up — the last
    /// minute of hour `H` is flushed at `H+1h`, exactly when the hourly sweep
    /// becomes eligible — and the next sweep then compacts bucket `H` a
    /// second time. Handing `merge` only the one late row would produce a
    /// coarse row describing only that row; because the sketch columns
    /// *replace* on conflict (see [`insert_rows`]), that fragment would
    /// silently overwrite the hour's real latency distribution and HLL while
    /// the summed counters stayed plausible. Feeding the destination's
    /// current state back in instead makes the callback's output the full
    /// picture, so replacing the window wholesale is correct — and it is a
    /// wholesale replace, not an upsert, so the counters are not added on top
    /// of themselves and a value the re-cap demotes into `__other__` does not
    /// linger as a stale row.
    ///
    /// The atomicity is the point: a crash, or a failure on any one of the
    /// statements, leaves *both* the write and the delete undone, so the
    /// next sweep re-reads exactly the same finer rows and redoes the same
    /// roll-up. Without it, a crash between the write and the delete would
    /// leave the finer rows in place for the next sweep to add a second time
    /// into a coarse row that already counted them.
    ///
    /// Reading inside the transaction (rather than through the read-only
    /// connection beforehand) closes the matching lost-update window: the
    /// `1h` tier is written by the `1m → 1h` pass *and* read-then-deleted by
    /// the `1h → 1d` pass, and those two run off independent tickers.
    ///
    /// Callers are expected to pass a window that is aligned to (and no
    /// wider than) one `to_tier` bucket, to only pass windows that are
    /// already closed, and to pass two *distinct* tiers — see
    /// `traffic::compaction`.
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

    /// Every distinct bucket timestamp present anywhere in `tier` (stats ∪
    /// paths ∪ breakdown) strictly before `cutoff`, ascending.
    ///
    /// Compaction uses this to enumerate the work waiting for it without
    /// loading a single row of it: flooring these to the coarse width yields
    /// exactly the set of coarse buckets that need a [`Self::compact_window`]
    /// pass, so a long backlog is processed one bounded transaction at a
    /// time rather than in one unbounded read.
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
                "SELECT bucket, app, host, requests, bytes_in, bytes_out, s2xx, s3xx, s4xx, s5xx, latency_tdigest, uniques_hll
                 FROM traffic_stats_{} WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3 ORDER BY bucket",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to), |r| {
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
                })?
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
                "SELECT bucket, app, path, requests, bytes_out, latency_tdigest
                 FROM traffic_paths_{} WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3
                 ORDER BY bucket LIMIT ?4",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to, limit as i64), |r| {
                    Ok(PathRow {
                        bucket: r.get(0)?,
                        app: r.get(1)?,
                        path: r.get(2)?,
                        requests: r.get(3)?,
                        bytes_out: r.get(4)?,
                        latency_tdigest: r.get(5)?,
                    })
                })?
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
                "SELECT bucket, app, dimension, value, requests, bytes_out
                 FROM traffic_breakdown_{} WHERE app = ?1 AND bucket >= ?2 AND bucket < ?3 AND dimension = ?4
                 ORDER BY requests DESC LIMIT ?5",
                suffix(tier)
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((app, from, to, dim, limit as i64), |r| {
                    Ok(BreakdownRow {
                        bucket: r.get(0)?,
                        app: r.get(1)?,
                        dimension: r.get(2)?,
                        value: r.get(3)?,
                        requests: r.get(4)?,
                        bytes_out: r.get(5)?,
                    })
                })?
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

    /// Deletes `tier` stats rows strictly older than `cutoff`; returns the
    /// number of rows removed.
    pub fn delete_stats_before(&self, tier: Tier, cutoff: i64) -> Result<usize, StoreError> {
        self.delete_table_before("traffic_stats", tier, cutoff)
    }

    /// Deletes `tier` path rows strictly older than `cutoff`; returns the
    /// number of rows removed.
    pub fn delete_paths_before(&self, tier: Tier, cutoff: i64) -> Result<usize, StoreError> {
        self.delete_table_before("traffic_paths", tier, cutoff)
    }

    /// Deletes `tier` breakdown rows strictly older than `cutoff`; returns
    /// the number of rows removed.
    pub fn delete_breakdown_before(&self, tier: Tier, cutoff: i64) -> Result<usize, StoreError> {
        self.delete_table_before("traffic_breakdown", tier, cutoff)
    }

    /// Deletes every `tier` row (stats + paths + breakdown) strictly older
    /// than `cutoff`; returns the total number of rows removed.
    pub fn delete_before(&self, tier: Tier, cutoff: i64) -> Result<usize, StoreError> {
        Ok(self.delete_stats_before(tier, cutoff)?
            + self.delete_paths_before(tier, cutoff)?
            + self.delete_breakdown_before(tier, cutoff)?)
    }

    /// Applies the per-tier retention windows (spec defaults: 48h / 30d /
    /// 395d), deleting everything older than `now - window` in each tier;
    /// returns the total number of rows removed.
    ///
    /// Pure deletion — no sketch merging happens here (that lives in the
    /// `traffic` crate's compaction, which is what *produces* the `1h`/`1d`
    /// rows this method later expires).
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

    /// Distinct app UUIDs with recorded traffic, across every tier.
    ///
    /// The `UNION` is required, not defensive. `1h`/`1d` rows are indeed
    /// derived from `1m` data, but compaction *deletes* the finer rows it
    /// consumes (that delete is its watermark against double-counting), so
    /// `traffic_stats_1m` only ever holds the window compaction has not swept
    /// yet — roughly the last hour or two. Querying it alone would hide any
    /// app idle for longer than that, even though its full 30-day/395-day
    /// history is still there and still queryable through every other
    /// endpoint.
    ///
    /// `UNION` (not `UNION ALL`) already de-duplicates, so the per-branch
    /// `DISTINCT`s only shrink what each branch feeds it.
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

/// Upserts a batch into `tier`'s three tables on an existing connection (in
/// practice a `Transaction`, which derefs to `Connection`). Shared by
/// [`AnalyticsStore::write_rows`] and [`AnalyticsStore::compact_window`] so
/// the minute flush and compaction cannot drift apart on conflict
/// resolution.
///
/// Counters sum on conflict; sketch blobs are replaced. Both are safe here
/// because every row that reaches this function contributes exactly once:
/// the flush owns a minute window that is closed before it writes, and
/// compaction clears the destination window and deletes the finer rows it
/// consumed in the same transaction as the write, so its rows never collide
/// with a previous pass's at all (see
/// [`AnalyticsStore::compact_window`] — the merge it drives is a recompute
/// of the whole coarse bucket, not an increment on top of it).
///
/// Summing is still the right conflict rule for the flush: a delayed flush
/// landing on a `1m` bucket that was already written is genuinely new
/// information, and adding it keeps the counters right, where replacing
/// would throw the bucket's existing counters away. Replacing is the right
/// rule for the sketches, since summing raw sketch bytes is meaningless —
/// callers hand over an already-merged sketch for the whole key.
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
        "SELECT bucket, app, host, requests, bytes_in, bytes_out, s2xx, s3xx, s4xx, s5xx, latency_tdigest, uniques_hll
         FROM traffic_stats_{} WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), |r| {
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
        })?
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
        "SELECT bucket, app, path, requests, bytes_out, latency_tdigest
         FROM traffic_paths_{} WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), |r| {
            Ok(PathRow {
                bucket: r.get(0)?,
                app: r.get(1)?,
                path: r.get(2)?,
                requests: r.get(3)?,
                bytes_out: r.get(4)?,
                latency_tdigest: r.get(5)?,
            })
        })?
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
        "SELECT bucket, app, dimension, value, requests, bytes_out
         FROM traffic_breakdown_{} WHERE bucket >= ?1 AND bucket < ?2 ORDER BY bucket",
        suffix(tier)
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt
        .query_map((from, to), |r| {
            Ok(BreakdownRow {
                bucket: r.get(0)?,
                app: r.get(1)?,
                dimension: r.get(2)?,
                value: r.get(3)?,
                requests: r.get(4)?,
                bytes_out: r.get(5)?,
            })
        })?
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
        let stats = vec![StatsRow {
            bucket: 60_000,
            app: "a".into(),
            host: "h".into(),
            requests: 5,
            bytes_in: 100,
            bytes_out: 200,
            s2xx: 5,
            s3xx: 0,
            s4xx: 0,
            s5xx: 0,
            latency_tdigest: vec![1, 2],
            uniques_hll: vec![3, 4],
        }];
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

        assert_eq!(s.delete_stats_before(Tier::M1, 200).unwrap(), 1);
        assert_eq!(s.delete_paths_before(Tier::M1, 200).unwrap(), 1);
        assert_eq!(s.delete_breakdown_before(Tier::M1, 200).unwrap(), 1);

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
        let paths = vec![PathRow {
            bucket: 60_000,
            app: "a".into(),
            path: "/x".into(),
            requests: 2,
            bytes_out: 50,
            latency_tdigest: vec![1],
        }];
        let breakdown = vec![BreakdownRow {
            bucket: 60_000,
            app: "a".into(),
            dimension: "country".into(),
            value: "US".into(),
            requests: 2,
            bytes_out: 50,
        }];
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
