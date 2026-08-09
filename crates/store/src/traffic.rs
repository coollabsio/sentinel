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
//! [`AnalyticsStore::flush_window`] only ever writes the `1m` tier — rolling
//! `1m` up into `1h`/`1d` is a later task's compaction job, not this module's
//! concern.

use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::StoreError;

/// Typed, STRICT schema for all three roll-up tiers. `1h`/`1d` tables are
/// created up front (compaction, a later task, writes into them) even though
/// `flush_window` here only ever inserts into the `1m` tables.
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

    /// Writes one minute-window's worth of aggregated rows in a single
    /// transaction. Only ever targets the `_1m` tier — rolling `1m` up into
    /// `1h`/`1d` is compaction's job (a later task), not this method's.
    ///
    /// `ON CONFLICT` sums the count/byte columns but *replaces* the sketch
    /// blobs (`latency_tdigest`, `uniques_hll`) with the incoming value:
    /// callers already hand over fully-merged sketches for the window, so
    /// summing raw bytes would be meaningless. Under normal operation each
    /// `(bucket, app, host)` is flushed exactly once, so the replace-not-merge
    /// behavior is only ever exercised by compaction's later idempotent
    /// re-flush case.
    pub fn flush_window(
        &self,
        stats: &[StatsRow],
        paths: &[PathRow],
        breakdown: &[BreakdownRow],
    ) -> Result<(), StoreError> {
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut ins = tx.prepare_cached(
                    "INSERT INTO traffic_stats_1m
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
                        uniques_hll = excluded.uniques_hll",
                )?;
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
                let mut ins = tx.prepare_cached(
                    "INSERT INTO traffic_paths_1m
                        (bucket, app, path, requests, bytes_out, latency_tdigest)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(bucket, app, path) DO UPDATE SET
                        requests = requests + excluded.requests,
                        bytes_out = bytes_out + excluded.bytes_out,
                        latency_tdigest = excluded.latency_tdigest",
                )?;
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
                let mut ins = tx.prepare_cached(
                    "INSERT INTO traffic_breakdown_1m
                        (bucket, app, dimension, value, requests, bytes_out)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(bucket, app, dimension, value) DO UPDATE SET
                        requests = requests + excluded.requests,
                        bytes_out = bytes_out + excluded.bytes_out",
                )?;
                for r in breakdown {
                    ins.execute((r.bucket, &r.app, &r.dimension, &r.value, r.requests, r.bytes_out))?;
                }
            }
            tx.commit()?;
            Ok(())
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

    /// Distinct app UUIDs with recorded traffic. Queries only the `1m` tier:
    /// compaction (a later task) always derives `1h`/`1d` rows from `1m`
    /// data, so the app set is identical across tiers and `1m` — the tier
    /// every flush populates first — is the cheapest, always-populated
    /// source (no `UNION` across three tables needed).
    pub fn apps(&self) -> Result<Vec<String>, StoreError> {
        self.with_reader(|c| {
            let mut stmt =
                c.prepare_cached("SELECT DISTINCT app FROM traffic_stats_1m ORDER BY app")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }
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
