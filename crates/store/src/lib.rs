#![forbid(unsafe_code)]

pub mod metrics;
pub mod retention;
pub mod schema;
pub mod stats;
pub mod traffic;

use std::path::Path;
use std::sync::{Arc, Mutex};

pub use metrics::{
    ContainerDiskRow, ContainerDiskSample, ContainerSample, CpuRow, DiskRow, DiskSample, MemRow,
};
pub use stats::{DbStats, TableStat};
pub use traffic::{AnalyticsStore, BreakdownRow, PathRow, StatsRow, Tier};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store lock poisoned")]
    Poisoned,
}

#[derive(Clone)]
pub struct Store {
    /// Single read-write connection; serializes all writes (collector inserts,
    /// retention, migration) through one `Mutex`.
    writer: Arc<Mutex<rusqlite::Connection>>,
    /// Dedicated read-only connection for the API's history/stats queries. In
    /// WAL mode a reader sees the latest committed snapshot without blocking the
    /// writer, so inbound reads no longer serialize behind the collector's 5s
    /// inserts or the daily retention rewrite. For in-memory stores (tests) the
    /// two separate `:memory:` databases would not share data, so `reader`
    /// aliases `writer` there — reads and writes hit the same connection.
    reader: Arc<Mutex<rusqlite::Connection>>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        // Path::parent() returns Some("") for a bare filename with no
        // directory component (e.g. "db.sqlite"), not None — create_dir_all("")
        // silently no-ops, but set_permissions("") fails with NotFound. Skip
        // the whole block when there's no real directory to create.
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))?;
            }
        }
        match rusqlite::Connection::open(path)
            .map_err(StoreError::from)
            .and_then(|conn| Self::from_writer(conn, Some(path)))
        {
            Ok(store) => Ok(store),
            Err(e) => {
                // Migration failure must never be fatal to startup: metrics
                // history is regenerable and retention-bounded, while the
                // agent itself (API, push, collection) is not optional. Move
                // the unreadable/unmigratable file aside and start fresh
                // rather than crash-looping on the same failure forever.
                tracing::error!(
                    error = %e,
                    path = %path.display(),
                    "failed to open or migrate metrics database, starting fresh"
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
                let conn = rusqlite::Connection::open(path)?;
                Self::from_writer(conn, Some(path))
            }
        }
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_writer(rusqlite::Connection::open_in_memory()?, None)
    }

    /// Migrates the writer connection, then (for file-backed stores) opens a
    /// separate read-only connection on the same path. `path == None` marks an
    /// in-memory store, where the reader must alias the writer.
    fn from_writer(conn: rusqlite::Connection, path: Option<&Path>) -> Result<Self, StoreError> {
        Self::init_conn(&conn)?;
        schema::migrate_legacy(&conn)?;
        schema::apply(&conn)?;
        let writer = Arc::new(Mutex::new(conn));

        let reader = match path {
            Some(path) => {
                use rusqlite::OpenFlags;
                let ro = rusqlite::Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
                )?;
                // A brief checkpoint can hold the DB; wait rather than error.
                ro.busy_timeout(std::time::Duration::from_secs(5))?;
                ro.pragma_update(None, "cache_size", -8000)?;
                Arc::new(Mutex::new(ro))
            }
            // In-memory: a second `:memory:` connection is a distinct empty DB,
            // so alias the writer to keep read-after-write visible in tests.
            None => writer.clone(),
        };

        Ok(Self { writer, reader })
    }

    fn init_conn(conn: &rusqlite::Connection) -> Result<(), StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // 8 MB, down from the Go implementation's 64 MB: the working set is
        // small and a large page cache works against the footprint goal.
        conn.pragma_update(None, "cache_size", -8000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(())
    }

    /// Read-write connection: collector inserts, retention, migration.
    pub(crate) fn with_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.writer.lock().map_err(|_| StoreError::Poisoned)?;
        f(&guard)
    }

    /// Read-only connection: API history/stats queries. Decoupled from the
    /// writer so inbound reads don't serialize behind writes.
    pub(crate) fn with_reader<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.reader.lock().map_err(|_| StoreError::Poisoned)?;
        f(&guard)
    }
}
