#![forbid(unsafe_code)]

pub mod metrics;
pub mod retention;
pub mod schema;
pub mod stats;

use std::path::Path;
use std::sync::{Arc, Mutex};

pub use metrics::{ContainerSample, CpuRow, MemRow};
pub use stats::{DbStats, TableStat};

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
    conn: Arc<Mutex<rusqlite::Connection>>,
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
        let conn = rusqlite::Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(rusqlite::Connection::open_in_memory()?)
    }

    fn init(conn: rusqlite::Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // 8 MB, down from the Go implementation's 64 MB: the working set is
        // small and a large page cache works against the footprint goal.
        conn.pragma_update(None, "cache_size", -8000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate_legacy(&conn)?;
        schema::apply(&conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    pub(crate) fn with_conn<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::Poisoned)?;
        f(&guard)
    }
}
