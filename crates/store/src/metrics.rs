use crate::{Store, StoreError};

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

const CPU_COLS: &str = "time, percent";
const MEM_COLS: &str = "time, total, available, used, used_percent, free";

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
