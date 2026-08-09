use crate::{Store, StoreError};
use rusqlite::OptionalExtension;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuRow {
    pub time: i64,
    pub percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemRow {
    pub time: i64,
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub used_percent: f64,
    pub free: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContainerSample {
    pub container_id: String,
    pub cpu_percent: f64,
    pub mem_total: u64,
    pub mem_available: u64,
    pub mem_used: u64,
    pub mem_used_percent: f64,
    pub mem_free: u64,
}

/// Server filesystem usage, one row per real mountpoint per cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskRow {
    pub time: i64,
    pub mount: String,
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub used_percent: f64,
}

/// Collector input for a single mountpoint (time is stamped once per cycle).
#[derive(Debug, Clone, PartialEq)]
pub struct DiskSample {
    pub mount: String,
    pub total: u64,
    pub used: u64,
    pub available: u64,
    pub used_percent: f64,
}

/// Per-container storage: Docker writable-layer size + summed volume/bind sizes.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerDiskRow {
    pub time: i64,
    pub container_id: String,
    pub writable_layer: u64,
    pub volumes_total: u64,
}

/// Collector input for a single container (time is stamped once per cycle).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerDiskSample {
    pub container_id: String,
    pub writable_layer: u64,
    pub volumes_total: u64,
}

const CPU_COLS: &str = "time, percent";
const MEM_COLS: &str = "time, total, available, used, used_percent, free";
const DISK_COLS: &str = "time, mount, total, used, available, used_percent";
const CONTAINER_DISK_COLS: &str = "time, container_id, writable_layer, volumes_total";

impl Store {
    pub fn insert_cpu(&self, time: i64, percent: f64) -> Result<(), StoreError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO cpu_usage (time, percent) VALUES (?1, ?2)",
                (time, percent),
            )?;
            Ok(())
        })
    }

    pub fn insert_memory(&self, row: &MemRow) -> Result<(), StoreError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO memory_usage
                 (time, total, available, used, used_percent, free)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    row.time,
                    row.total as i64,
                    row.available as i64,
                    row.used as i64,
                    row.used_percent,
                    row.free as i64,
                ),
            )?;
            Ok(())
        })
    }

    /// Single transaction for the whole cycle, matching the Go collector's
    /// batched prepared-statement insert.
    pub fn insert_container_batch(
        &self,
        time: i64,
        rows: &[ContainerSample],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut cpu = tx.prepare_cached(
                    "INSERT OR REPLACE INTO container_cpu_usage
                     (time, container_id, percent) VALUES (?1, ?2, ?3)",
                )?;
                let mut mem = tx.prepare_cached(
                    "INSERT OR REPLACE INTO container_memory_usage
                     (time, container_id, total, available, used, used_percent, free)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )?;
                for r in rows {
                    cpu.execute((time, &r.container_id, r.cpu_percent))?;
                    mem.execute((
                        time,
                        &r.container_id,
                        r.mem_total as i64,
                        r.mem_available as i64,
                        r.mem_used as i64,
                        r.mem_used_percent,
                        r.mem_free as i64,
                    ))?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn cpu_history(&self, from: i64, to: i64) -> Result<Vec<CpuRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CPU_COLS} FROM cpu_usage WHERE time >= ?1 AND time <= ?2 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((from, to), |r| {
                    Ok(CpuRow {
                        time: r.get(0)?,
                        percent: r.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn memory_history(&self, from: i64, to: i64) -> Result<Vec<MemRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {MEM_COLS} FROM memory_usage WHERE time >= ?1 AND time <= ?2 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((from, to), map_mem_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn container_cpu_history(
        &self,
        id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<CpuRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CPU_COLS} FROM container_cpu_usage
                 WHERE container_id = ?1 AND time >= ?2 AND time <= ?3 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((id, from, to), |r| {
                    Ok(CpuRow {
                        time: r.get(0)?,
                        percent: r.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn container_memory_history(
        &self,
        id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<MemRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {MEM_COLS} FROM container_memory_usage
                 WHERE container_id = ?1 AND time >= ?2 AND time <= ?3 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((id, from, to), map_mem_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Batched insert of one cycle's server-disk rows, one per mountpoint.
    pub fn insert_disk_batch(&self, time: i64, rows: &[DiskSample]) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO disk_usage
                     (time, mount, total, used, available, used_percent)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?;
                for r in rows {
                    stmt.execute((
                        time,
                        &r.mount,
                        r.total as i64,
                        r.used as i64,
                        r.available as i64,
                        r.used_percent,
                    ))?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Batched insert of one cycle's per-container storage rows.
    pub fn insert_container_disk_batch(
        &self,
        time: i64,
        rows: &[ContainerDiskSample],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO container_disk_usage
                     (time, container_id, writable_layer, volumes_total)
                     VALUES (?1, ?2, ?3, ?4)",
                )?;
                for r in rows {
                    stmt.execute((
                        time,
                        &r.container_id,
                        r.writable_layer as i64,
                        r.volumes_total as i64,
                    ))?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// All mounts from the most recent disk cycle (every mount in a cycle shares
    /// one timestamp, so `MAX(time)` selects the whole latest snapshot).
    pub fn disk_latest(&self) -> Result<Vec<DiskRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {DISK_COLS} FROM disk_usage
                 WHERE time = (SELECT MAX(time) FROM disk_usage) ORDER BY mount ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map([], map_disk_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn disk_history(&self, from: i64, to: i64) -> Result<Vec<DiskRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {DISK_COLS} FROM disk_usage
                 WHERE time >= ?1 AND time <= ?2 ORDER BY time ASC, mount ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((from, to), map_disk_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// All containers from the most recent container-storage cycle.
    pub fn container_disk_latest(&self) -> Result<Vec<ContainerDiskRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CONTAINER_DISK_COLS} FROM container_disk_usage
                 WHERE time = (SELECT MAX(time) FROM container_disk_usage)
                 ORDER BY container_id ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map([], map_container_disk_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Latest stored storage row for a single container, if any.
    pub fn container_disk_latest_one(
        &self,
        id: &str,
    ) -> Result<Option<ContainerDiskRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CONTAINER_DISK_COLS} FROM container_disk_usage
                 WHERE container_id = ?1 ORDER BY time DESC LIMIT 1"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let row = stmt.query_row((id,), map_container_disk_row).optional()?;
            Ok(row)
        })
    }

    pub fn container_disk_history(
        &self,
        id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<ContainerDiskRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CONTAINER_DISK_COLS} FROM container_disk_usage
                 WHERE container_id = ?1 AND time >= ?2 AND time <= ?3 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((id, from, to), map_container_disk_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }
}

fn map_disk_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<DiskRow> {
    Ok(DiskRow {
        time: r.get(0)?,
        mount: r.get(1)?,
        total: r.get::<_, i64>(2)? as u64,
        used: r.get::<_, i64>(3)? as u64,
        available: r.get::<_, i64>(4)? as u64,
        used_percent: r.get(5)?,
    })
}

fn map_container_disk_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerDiskRow> {
    Ok(ContainerDiskRow {
        time: r.get(0)?,
        container_id: r.get(1)?,
        writable_layer: r.get::<_, i64>(2)? as u64,
        volumes_total: r.get::<_, i64>(3)? as u64,
    })
}

fn map_mem_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MemRow> {
    Ok(MemRow {
        time: r.get(0)?,
        total: r.get::<_, i64>(1)? as u64,
        available: r.get::<_, i64>(2)? as u64,
        used: r.get::<_, i64>(3)? as u64,
        used_percent: r.get(4)?,
        free: r.get::<_, i64>(5)? as u64,
    })
}
