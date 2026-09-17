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

/// Host network throughput for one cycle, as a **rate** (bytes/sec) derived
/// from the delta between consecutive counter reads. Stored as a gauge, not a
/// cumulative counter, so the mean-based downsampler collapses aged rows
/// correctly — averaging a monotonic counter would be meaningless.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NetworkRow {
    pub time: i64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Host load average (1 / 5 / 15 minute).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadRow {
    pub time: i64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

/// Per-container network throughput rate for one cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerNetworkRow {
    pub time: i64,
    pub container_id: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

impl From<ContainerNetworkRow> for NetworkRow {
    fn from(r: ContainerNetworkRow) -> Self {
        NetworkRow {
            time: r.time,
            rx_bytes_per_sec: r.rx_bytes_per_sec,
            tx_bytes_per_sec: r.tx_bytes_per_sec,
        }
    }
}

/// Collector input for a single container's network rate.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerNetworkSample {
    pub container_id: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Latest status of one container: Docker `state` plus `health`/`restart_count`
/// from inspect. Current-only (no history) — keyed on the display name.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerStatusRow {
    pub container_id: String,
    pub state: String,
    pub health_status: String,
    pub restart_count: u64,
    pub time: i64,
}

/// Collector input for a single container's status (time stamped once/cycle).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerStatusSample {
    pub container_id: String,
    pub state: String,
    pub health_status: String,
    pub restart_count: u64,
}

/// Singleton host status: current-only uptime + swap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HostStatusRow {
    pub uptime_seconds: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub swap_free: u64,
    pub swap_used_percent: f64,
    pub time: i64,
}

/// Latest host CPU, memory and disk rows for `/api/summary`. Each is absent
/// when its table holds no rows; `disk` is empty rather than `None` for an
/// empty snapshot (the handler maps an empty vec to a `null` disk key).
#[derive(Debug, Clone, PartialEq)]
pub struct HostSummaryRows {
    pub cpu: Option<CpuRow>,
    pub memory: Option<MemRow>,
    pub disk: Vec<DiskRow>,
    pub network: Option<NetworkRow>,
    pub load: Option<LoadRow>,
    pub host: Option<HostStatusRow>,
}

/// One container's latest sample of each metric, joined by id in Rust from
/// three latest-row-per-id queries. Any metric with no rows for the container
/// is `None`; `latest_time` is the newest `time` across whichever are present.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerMetrics {
    pub container_id: String,
    pub cpu: Option<CpuRow>,
    pub memory: Option<MemRow>,
    pub disk: Option<ContainerDiskRow>,
    pub network: Option<ContainerNetworkRow>,
    pub status: Option<ContainerStatusRow>,
    pub latest_time: i64,
}

const CPU_COLS: &str = "time, percent";
const MEM_COLS: &str = "time, total, available, used, used_percent, free";
const DISK_COLS: &str = "time, mount, total, used, available, used_percent";
const CONTAINER_DISK_COLS: &str = "time, container_id, writable_layer, volumes_total";
const NETWORK_COLS: &str = "time, rx_bytes_per_sec, tx_bytes_per_sec";
const LOAD_COLS: &str = "time, load1, load5, load15";
const CONTAINER_NETWORK_COLS: &str = "time, container_id, rx_bytes_per_sec, tx_bytes_per_sec";
const HOST_STATUS_COLS: &str =
    "uptime_seconds, swap_total, swap_used, swap_free, swap_used_percent, time";

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

    pub fn insert_network(
        &self,
        time: i64,
        rx_bytes_per_sec: f64,
        tx_bytes_per_sec: f64,
    ) -> Result<(), StoreError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO network_usage (time, rx_bytes_per_sec, tx_bytes_per_sec)
                 VALUES (?1, ?2, ?3)",
                (time, rx_bytes_per_sec, tx_bytes_per_sec),
            )?;
            Ok(())
        })
    }

    pub fn insert_load(
        &self,
        time: i64,
        load1: f64,
        load5: f64,
        load15: f64,
    ) -> Result<(), StoreError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO load_average (time, load1, load5, load15)
                 VALUES (?1, ?2, ?3, ?4)",
                (time, load1, load5, load15),
            )?;
            Ok(())
        })
    }

    /// Singleton upsert (row id fixed at 0): latest uptime + swap.
    pub fn upsert_host_status(&self, row: &HostStatusRow) -> Result<(), StoreError> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO host_status
                 (id, uptime_seconds, swap_total, swap_used, swap_free, swap_used_percent, time)
                 VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    row.uptime_seconds as i64,
                    row.swap_total as i64,
                    row.swap_used as i64,
                    row.swap_free as i64,
                    row.swap_used_percent,
                    row.time,
                ),
            )?;
            Ok(())
        })
    }

    pub fn insert_container_network_batch(
        &self,
        time: i64,
        rows: &[ContainerNetworkSample],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO container_network_usage
                     (time, container_id, rx_bytes_per_sec, tx_bytes_per_sec)
                     VALUES (?1, ?2, ?3, ?4)",
                )?;
                for r in rows {
                    stmt.execute((
                        time,
                        &r.container_id,
                        r.rx_bytes_per_sec,
                        r.tx_bytes_per_sec,
                    ))?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Upserts each container's latest status keyed on its display name.
    pub fn upsert_container_status_batch(
        &self,
        time: i64,
        rows: &[ContainerStatusSample],
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            return Ok(());
        }
        self.with_conn(|c| {
            let tx = c.unchecked_transaction()?;
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO container_status
                     (container_id, state, health_status, restart_count, time)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for r in rows {
                    stmt.execute((
                        &r.container_id,
                        &r.state,
                        &r.health_status,
                        r.restart_count as i64,
                        time,
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
        self.with_reader(|c| Ok(latest_disk_rows(c)?))
    }

    /// Latest host network rate row, if any.
    pub fn network_latest(&self) -> Result<Option<NetworkRow>, StoreError> {
        self.with_reader(|c| Ok(latest_network(c)?))
    }

    pub fn network_history(&self, from: i64, to: i64) -> Result<Vec<NetworkRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {NETWORK_COLS} FROM network_usage
                 WHERE time >= ?1 AND time <= ?2 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((from, to), map_network_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Latest host load-average row, if any.
    pub fn load_latest(&self) -> Result<Option<LoadRow>, StoreError> {
        self.with_reader(|c| Ok(latest_load(c)?))
    }

    pub fn load_history(&self, from: i64, to: i64) -> Result<Vec<LoadRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {LOAD_COLS} FROM load_average
                 WHERE time >= ?1 AND time <= ?2 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((from, to), map_load_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn container_network_history(
        &self,
        id: &str,
        from: i64,
        to: i64,
    ) -> Result<Vec<ContainerNetworkRow>, StoreError> {
        self.with_reader(|c| {
            let sql = format!(
                "SELECT {CONTAINER_NETWORK_COLS} FROM container_network_usage
                 WHERE container_id = ?1 AND time >= ?2 AND time <= ?3 ORDER BY time ASC"
            );
            let mut stmt = c.prepare_cached(&sql)?;
            let rows = stmt
                .query_map((id, from, to), map_container_network_row)?
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

    /// Latest host cpu, memory, disk, network, load and host-status snapshot in
    /// a single reader-lock hold.
    ///
    /// The store exposes one read-only connection, so every API read serializes
    /// on its `Mutex`. Reading every host series under one `with_reader` gives
    /// `/api/summary` a single lock acquisition, which is what keeps this hot
    /// fleet-dashboard endpoint cheap under concurrency. Each read is an index
    /// tail read or a singleton lookup, not a scan.
    pub fn host_summary(&self) -> Result<HostSummaryRows, StoreError> {
        self.with_reader(|c| {
            let cpu = {
                let sql = format!("SELECT {CPU_COLS} FROM cpu_usage ORDER BY time DESC LIMIT 1");
                let mut stmt = c.prepare_cached(&sql)?;
                stmt.query_row([], |r| {
                    Ok(CpuRow {
                        time: r.get(0)?,
                        percent: r.get(1)?,
                    })
                })
                .optional()?
            };
            let memory = {
                let sql = format!("SELECT {MEM_COLS} FROM memory_usage ORDER BY time DESC LIMIT 1");
                let mut stmt = c.prepare_cached(&sql)?;
                stmt.query_row([], map_mem_row).optional()?
            };
            let disk = latest_disk_rows(c)?;
            let network = latest_network(c)?;
            let load = latest_load(c)?;
            let host = latest_host_status(c)?;
            Ok(HostSummaryRows {
                cpu,
                memory,
                disk,
                network,
                load,
                host,
            })
        })
    }

    /// Latest cpu, memory, disk, network and status for every container that has
    /// recorded any of them, joined by id in Rust. One reader lock covers every
    /// query; see [`latest_per_container_sql`] for why they stay index seeks.
    pub fn latest_container_metrics(&self) -> Result<Vec<ContainerMetrics>, StoreError> {
        use std::collections::{BTreeSet, HashMap};

        self.with_reader(|c| {
            let mut cpu: HashMap<String, CpuRow> = HashMap::new();
            {
                let sql =
                    latest_per_container_sql("container_cpu_usage", "container_id, time, percent");
                let mut stmt = c.prepare_cached(&sql)?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let id: String = r.get(0)?;
                    cpu.insert(
                        id,
                        CpuRow {
                            time: r.get(1)?,
                            percent: r.get(2)?,
                        },
                    );
                }
            }

            let mut mem: HashMap<String, MemRow> = HashMap::new();
            {
                let sql = latest_per_container_sql(
                    "container_memory_usage",
                    &format!("container_id, {MEM_COLS}"),
                );
                let mut stmt = c.prepare_cached(&sql)?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let id: String = r.get(0)?;
                    mem.insert(
                        id,
                        MemRow {
                            time: r.get(1)?,
                            total: r.get::<_, i64>(2)? as u64,
                            available: r.get::<_, i64>(3)? as u64,
                            used: r.get::<_, i64>(4)? as u64,
                            used_percent: r.get(5)?,
                            free: r.get::<_, i64>(6)? as u64,
                        },
                    );
                }
            }

            let mut disk: HashMap<String, ContainerDiskRow> = HashMap::new();
            {
                let sql = latest_per_container_sql("container_disk_usage", CONTAINER_DISK_COLS);
                let mut stmt = c.prepare_cached(&sql)?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let row = map_container_disk_row(r)?;
                    disk.insert(row.container_id.clone(), row);
                }
            }

            let mut net: HashMap<String, ContainerNetworkRow> = HashMap::new();
            {
                let sql =
                    latest_per_container_sql("container_network_usage", CONTAINER_NETWORK_COLS);
                let mut stmt = c.prepare_cached(&sql)?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let row = map_container_network_row(r)?;
                    net.insert(row.container_id.clone(), row);
                }
            }

            // Latest status per container (already one row each — PK on id).
            let mut status: HashMap<String, ContainerStatusRow> = HashMap::new();
            {
                let mut stmt = c.prepare_cached(
                    "SELECT container_id, state, health_status, restart_count, time
                     FROM container_status",
                )?;
                let mut rows = stmt.query([])?;
                while let Some(r) = rows.next()? {
                    let row = map_container_status_row(r)?;
                    status.insert(row.container_id.clone(), row);
                }
            }

            let ids: BTreeSet<String> = cpu
                .keys()
                .chain(mem.keys())
                .chain(disk.keys())
                .chain(net.keys())
                .chain(status.keys())
                .cloned()
                .collect();

            let out = ids
                .into_iter()
                .map(|id| {
                    let cpu = cpu.remove(&id);
                    let memory = mem.remove(&id);
                    let disk = disk.remove(&id);
                    let network = net.remove(&id);
                    let status = status.remove(&id);
                    // `container_status.time` is deliberately excluded: it is a
                    // last-seen stamp for a current-only row, not a metric
                    // sample, so it must not drive the sample recency here.
                    let latest_time = [
                        cpu.as_ref().map(|r| r.time),
                        memory.as_ref().map(|r| r.time),
                        disk.as_ref().map(|r| r.time),
                        network.as_ref().map(|r| r.time),
                    ]
                    .into_iter()
                    .flatten()
                    .max()
                    .unwrap_or(0);
                    ContainerMetrics {
                        container_id: id,
                        cpu,
                        memory,
                        disk,
                        network,
                        status,
                        latest_time,
                    }
                })
                .collect();
            Ok(out)
        })
    }
}

/// Newest row per container in `table`. A `GROUP BY container_id` + `MAX(time)`
/// reads the whole `(container_id, time)` index (~130 ms per table at 1.3M rows,
/// under the shared reader lock). Instead, a recursive CTE skips from one
/// distinct id to the next through that index, and each id seeks its own
/// `MAX(time)`, so the cost scales with the container count, not the row count.
fn latest_per_container_sql(table: &str, cols: &str) -> String {
    format!(
        "WITH RECURSIVE ids(id) AS (
             SELECT MIN(container_id) FROM {table}
             UNION ALL
             SELECT (SELECT MIN(container_id) FROM {table} WHERE container_id > ids.id)
             FROM ids WHERE ids.id IS NOT NULL
         )
         SELECT {cols} FROM ids JOIN {table}
           ON container_id = ids.id
          AND time = (SELECT MAX(time) FROM {table} WHERE container_id = ids.id)"
    )
}

/// The newest disk cycle's rows, one per mountpoint. Shared by `disk_latest`
/// and `host_summary` so both hit the same SQL from either lock hold.
fn latest_disk_rows(c: &rusqlite::Connection) -> rusqlite::Result<Vec<DiskRow>> {
    let sql = format!(
        "SELECT {DISK_COLS} FROM disk_usage
         WHERE time = (SELECT MAX(time) FROM disk_usage) ORDER BY mount ASC"
    );
    let mut stmt = c.prepare_cached(&sql)?;
    stmt.query_map([], map_disk_row)?.collect()
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

fn map_network_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkRow> {
    Ok(NetworkRow {
        time: r.get(0)?,
        rx_bytes_per_sec: r.get(1)?,
        tx_bytes_per_sec: r.get(2)?,
    })
}

fn map_load_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<LoadRow> {
    Ok(LoadRow {
        time: r.get(0)?,
        load1: r.get(1)?,
        load5: r.get(2)?,
        load15: r.get(3)?,
    })
}

fn map_container_network_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerNetworkRow> {
    Ok(ContainerNetworkRow {
        time: r.get(0)?,
        container_id: r.get(1)?,
        rx_bytes_per_sec: r.get(2)?,
        tx_bytes_per_sec: r.get(3)?,
    })
}

fn map_container_status_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ContainerStatusRow> {
    Ok(ContainerStatusRow {
        container_id: r.get(0)?,
        state: r.get(1)?,
        health_status: r.get(2)?,
        restart_count: r.get::<_, i64>(3)? as u64,
        time: r.get(4)?,
    })
}

/// Latest host network rate row. Shared by `network_latest` and `host_summary`.
fn latest_network(c: &rusqlite::Connection) -> rusqlite::Result<Option<NetworkRow>> {
    let sql = format!("SELECT {NETWORK_COLS} FROM network_usage ORDER BY time DESC LIMIT 1");
    let mut stmt = c.prepare_cached(&sql)?;
    stmt.query_row([], map_network_row).optional()
}

/// Latest host load-average row. Shared by `load_latest` and `host_summary`.
fn latest_load(c: &rusqlite::Connection) -> rusqlite::Result<Option<LoadRow>> {
    let sql = format!("SELECT {LOAD_COLS} FROM load_average ORDER BY time DESC LIMIT 1");
    let mut stmt = c.prepare_cached(&sql)?;
    stmt.query_row([], map_load_row).optional()
}

/// The singleton host-status row (uptime + swap), if it has been written.
fn latest_host_status(c: &rusqlite::Connection) -> rusqlite::Result<Option<HostStatusRow>> {
    let sql = format!("SELECT {HOST_STATUS_COLS} FROM host_status WHERE id = 0");
    let mut stmt = c.prepare_cached(&sql)?;
    stmt.query_row([], |r| {
        Ok(HostStatusRow {
            uptime_seconds: r.get::<_, i64>(0)? as u64,
            swap_total: r.get::<_, i64>(1)? as u64,
            swap_used: r.get::<_, i64>(2)? as u64,
            swap_free: r.get::<_, i64>(3)? as u64,
            swap_used_percent: r.get(4)?,
            time: r.get(5)?,
        })
    })
    .optional()
}
