use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use config::Config;
use docker::DockerClient;
use store::{ContainerDiskSample, DiskSample, Store};
use sysinfo::Disks;
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::now_millis;

/// Collects storage metrics on two independent cadences: cheap per-mount
/// filesystem stats on `storage_refresh_rate_seconds`, and the more expensive
/// per-container writable-layer + volume `du`-walk on
/// `storage_volumes_refresh_rate_seconds`. Splitting the tickers keeps the
/// heavy walk from being forced onto the fast disk-stat interval.
pub struct StorageCollector {
    config: Arc<Config>,
    store: Store,
    docker: DockerClient,
}

impl StorageCollector {
    pub fn new(config: Arc<Config>, store: Store, docker: DockerClient) -> Self {
        Self {
            config,
            store,
            docker,
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(
            disk_refresh_seconds = self.config.storage_refresh_rate_seconds,
            volumes_refresh_seconds = self.config.storage_volumes_refresh_rate_seconds,
            volumes_enabled = self.config.storage_volumes_enabled,
            "starting storage collector"
        );

        // interval_at defers the first tick by a full period, matching the
        // Collector/Pusher startup timing (no immediate burst at boot).
        let disk_period = Duration::from_secs(self.config.storage_refresh_rate_seconds);
        let mut disk_ticker = interval_at(Instant::now() + disk_period, disk_period);
        disk_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let vol_period = Duration::from_secs(self.config.storage_volumes_refresh_rate_seconds);
        let mut vol_ticker = interval_at(Instant::now() + vol_period, vol_period);
        vol_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("stopping storage collector");
                    return;
                }
                _ = disk_ticker.tick() => {
                    self.collect_disk(now_millis()).await;
                }
                _ = vol_ticker.tick() => {
                    self.collect_container_storage(now_millis()).await;
                }
            }
        }
    }

    /// Enumerate real filesystems via sysinfo and record one row per mount.
    /// A failed cycle logs and continues; it never propagates out of `run`.
    async fn collect_disk(&self, time: i64) {
        let store = self.store.clone();
        match tokio::task::spawn_blocking(move || {
            let samples = sample_disks();
            store.insert_disk_batch(time, &samples)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "failed to record disk usage"),
            Err(e) => tracing::warn!(error = %e, "disk usage insert task panicked"),
        }
    }

    /// One `size: true` container list gives every container's writable-layer
    /// size and mount sources; when volume walking is enabled, each mount's
    /// host path is `du`-walked (sequentially, to bound I/O) and summed.
    async fn collect_container_storage(&self, time: i64) {
        let containers = match self.docker.list_container_sizes().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list container sizes");
                return;
            }
        };
        if containers.is_empty() {
            return;
        }

        let store = self.store.clone();
        let volumes_enabled = self.config.storage_volumes_enabled;
        let prefix = self.config.host_mount_prefix.clone();

        match tokio::task::spawn_blocking(move || {
            // Cache measured sizes for the whole collection cycle: a host source
            // shared across containers (or mounted at several targets within one
            // container) is `du`-walked only once.
            let mut measured: HashMap<PathBuf, u64> = HashMap::new();
            let samples: Vec<ContainerDiskSample> = containers
                .into_iter()
                .map(|c| {
                    let volumes_total = if volumes_enabled {
                        c.mount_sources
                            .iter()
                            .map(|src| resolve_host_path(&prefix, src))
                            // Dedupe per container so one source mounted at
                            // multiple targets is counted once, not summed twice.
                            .collect::<HashSet<_>>()
                            .into_iter()
                            .map(|path| {
                                *measured
                                    .entry(path.clone())
                                    .or_insert_with(|| dir_size(&path))
                            })
                            .sum()
                    } else {
                        0
                    };
                    ContainerDiskSample {
                        container_id: c.id,
                        writable_layer: c.writable_layer,
                        volumes_total,
                    }
                })
                .collect();
            store.insert_container_disk_batch(time, &samples)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "failed to record container storage"),
            Err(e) => tracing::warn!(error = %e, "container storage insert task panicked"),
        }
    }
}

/// Prefixes a container mount source with `HOST_MOUNT_PREFIX` so Sentinel can
/// reach host paths mounted into its own container. Mount sources are absolute,
/// so an empty prefix leaves the path unchanged.
fn resolve_host_path(prefix: &str, source: &str) -> PathBuf {
    if prefix.is_empty() {
        PathBuf::from(source)
    } else {
        PathBuf::from(format!("{prefix}{source}"))
    }
}

/// Hard cap on directory entries visited in a single [`dir_size`] walk. A
/// pathological bind mount (a container mounting `/`, `/var`, or a home dir for
/// tooling) can otherwise enumerate millions of inodes on every storage cycle
/// and stall the storage collector loop. Set well above any realistic single
/// volume; when hit, [`dir_size`] logs a warning and records the partial sum.
const MAX_WALK_ENTRIES: u64 = 2_000_000;

/// Recursively sums on-disk block usage (like `du`) under `path`. Symlinks are
/// never followed and any I/O error degrades to 0 with a warning — the walk
/// must never crash a collection cycle.
///
/// The walk is unbounded by depth and does not stop at filesystem boundaries,
/// so a mount source that points at an arbitrarily large host tree (any bind
/// mount, not just a Docker volume) is walked in full. To keep one pathological
/// mount from stalling the collector, the walk is capped at [`MAX_WALK_ENTRIES`]
/// entries; past that it logs a warning and returns the partial sum. Operators
/// who don't want bind mounts walked can set `STORAGE_VOLUMES_ENABLED=false`.
///
/// `pub` so the host-only `sentinel-bench storage` harness can measure the real
/// walk (see BENCHMARK.md §4.9); not part of any runtime API surface.
pub fn dir_size(path: &Path) -> u64 {
    dir_size_bounded(path, MAX_WALK_ENTRIES)
}

/// [`dir_size`] with an explicit entry budget, so the cap behaviour is testable
/// without materializing millions of files.
fn dir_size_bounded(path: &Path, max_entries: u64) -> u64 {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "storage: cannot stat mount source");
            return 0;
        }
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        return 0;
    }
    if ft.is_file() {
        return meta.blocks() * 512;
    }
    if !ft.is_dir() {
        return 0;
    }

    let mut total = meta.blocks() * 512;
    let mut entries_seen: u64 = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(path = %dir.display(), error = %e, "storage: cannot read directory");
                continue;
            }
        };
        for entry in entries.flatten() {
            // DirEntry::metadata does not traverse symlinks, so symlinked
            // entries report their own (tiny) size and are not recursed into.
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ft = md.file_type();
            if ft.is_dir() {
                total += md.blocks() * 512;
                stack.push(entry.path());
            } else if ft.is_file() {
                total += md.blocks() * 512;
            }
            entries_seen += 1;
            if entries_seen >= max_entries {
                tracing::warn!(
                    path = %path.display(),
                    entries = entries_seen,
                    "storage: mount source walk exceeded entry budget, recording partial size \
                     (a large bind mount? disable with STORAGE_VOLUMES_ENABLED=false)"
                );
                return total;
            }
        }
    }
    total
}

/// Snapshot every real filesystem, one `DiskSample` per unique mountpoint.
/// Pseudo/virtual filesystems and zero-capacity devices are skipped.
///
/// `pub` for the host-only `sentinel-bench storage` harness (BENCHMARK.md §4.9).
pub fn sample_disks() -> Vec<DiskSample> {
    let disks = Disks::new_with_refreshed_list();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for d in disks.list() {
        let fs = d.file_system().to_string_lossy();
        if is_pseudo_fs(&fs) {
            continue;
        }
        let total = d.total_space();
        if total == 0 {
            continue;
        }
        let mount = d.mount_point().to_string_lossy().to_string();
        if !seen.insert(mount.clone()) {
            continue;
        }
        let available = d.available_space();
        let used = total.saturating_sub(available);
        let used_percent = used as f64 / total as f64 * 100.0;
        out.push(DiskSample {
            mount,
            total,
            used,
            available,
            used_percent,
        });
    }
    out
}

/// Kernel/pseudo filesystems that carry no meaningful capacity for a server
/// storage view (tmpfs, overlay, cgroup mounts, …).
fn is_pseudo_fs(fs: &str) -> bool {
    matches!(
        fs,
        "" | "tmpfs"
            | "devtmpfs"
            | "overlay"
            | "overlayfs"
            | "squashfs"
            | "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "mqueue"
            | "devpts"
            | "ramfs"
            | "nsfs"
            | "tracefs"
            | "debugfs"
            | "autofs"
            | "binfmt_misc"
            | "fusectl"
            | "configfs"
            | "securityfs"
            | "pstore"
            | "bpf"
            | "hugetlbfs"
    )
}

#[cfg(test)]
mod tests;
