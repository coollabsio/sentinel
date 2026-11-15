#![forbid(unsafe_code)]

pub mod calc;
mod inspect_cache;
pub mod model;

pub use model::{ContainerDisk, ContainerStats, ContainerSummary};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use bollard::query_parameters::{
    DataUsageOptions, InspectContainerOptions, ListContainersOptions, StatsOptions,
};
use bollard::{BollardRequest, Docker};
use futures_util::StreamExt;
use inspect_cache::InspectCache;

const SOCKET: &str = "/var/run/docker.sock";

/// Socket resolution: the standard `DOCKER_HOST` env var when it points at a
/// Unix socket (`unix:///run/user/1000/podman/podman.sock` or a bare path —
/// e.g. a rootless Podman socket), falling back to the default Docker socket.
/// Non-unix DOCKER_HOST schemes (tcp://, ssh://, ...) are ignored: sentinel
/// only speaks to a local socket.
fn socket_path() -> String {
    match std::env::var("DOCKER_HOST") {
        Ok(host)
            if host.starts_with("unix://") || (!host.contains("://") && host.starts_with('/')) =>
        {
            host
        }
        _ => SOCKET.to_string(),
    }
}
// Matches the Go client's `http.Client{Timeout: 10s}` (pkg/dockerClient). A
// single unresponsive container or a hung Docker daemon must not stall a whole
// collection/push cycle for two minutes — the collector drops missed ticks
// (MissedTickBehavior::Skip), so a long per-request timeout turns into large
// gaps in the recorded metrics.
const TIMEOUT_SECS: u64 = 10;

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error("docker: {0}")]
    Bollard(#[from] bollard::errors::Error),
    #[error("docker returned no stats for {0}")]
    NoStats(String),
}

#[derive(Clone)]
pub struct DockerClient {
    inner: Docker,
    /// Shared by every clone, so the collector and push reuse one inspect.
    inspect_cache: Arc<Mutex<InspectCache>>,
}

impl DockerClient {
    pub fn new() -> Result<Self, DockerError> {
        let inner =
            Docker::connect_with_unix(&socket_path(), TIMEOUT_SECS, bollard::API_DEFAULT_VERSION)?
                .with_request_modifier(only_volume_disk_usage);
        Ok(Self {
            inner,
            inspect_cache: Arc::default(),
        })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerError> {
        let opts = ListContainersOptions {
            all: true,
            ..Default::default()
        };
        let raw = self.inner.list_containers(Some(opts)).await?;
        let live: HashSet<&str> = raw.iter().filter_map(|c| c.id.as_deref()).collect();
        self.cache().retain_ids(&live);
        Ok(raw
            .into_iter()
            .map(|c| ContainerSummary {
                id: c.id.unwrap_or_default(),
                names: c.names.unwrap_or_default(),
                image: c.image.unwrap_or_default(),
                // bollard's ContainerSummaryStateEnum Display emits the exact
                // Docker wire strings ("running", "exited", ... and "" for the
                // empty state), matching Go's `string(container.State)`. Debug
                // + to_lowercase() would instead emit "empty" for the empty
                // variant and silently drift if a future bollard release
                // renamed a variant. See the wire-string test below.
                state: c.state.map(|s| s.to_string()).unwrap_or_default(),
                labels: c.labels.unwrap_or_default(),
            })
            .collect())
    }

    /// Lists all containers with `size: true`, yielding each container's
    /// writable-layer size (`SizeRw`) and mount source paths in one API call.
    /// `size: true` makes the daemon compute per-container sizes, so this is
    /// heavier than `list_containers` and runs on the slower storage ticker.
    pub async fn list_container_sizes(&self) -> Result<Vec<ContainerDisk>, DockerError> {
        let opts = ListContainersOptions {
            all: true,
            size: true,
            ..Default::default()
        };
        let raw = self.inner.list_containers(Some(opts)).await?;
        Ok(raw.into_iter().map(container_disk_from_summary).collect())
    }

    /// The size of every named volume, keyed by host mountpoint (the same
    /// path a container lists as its mount source). The daemon computes the
    /// sizes, so Sentinel needs no access to host paths. Empty on daemons older
    /// than API 1.52, see [`has_volume_usage`].
    pub async fn volume_sizes(&self) -> Result<HashMap<String, u64>, DockerError> {
        let version = self.inner.version().await?;
        if !has_volume_usage(version.api_version.as_deref()) {
            return Ok(HashMap::new());
        }
        // API 1.52+ only returns the per-object `Items` with `verbose`.
        let opts = DataUsageOptions {
            verbose: true,
            ..Default::default()
        };
        let df = self.inner.df(Some(opts)).await?;
        let volumes = df.volume_usage.and_then(|v| v.items).unwrap_or_default();
        Ok(volume_sizes_from_items(&volumes))
    }

    pub async fn stats(&self, id: &str) -> Result<ContainerStats, DockerError> {
        // one-shot returns at once instead of waiting a ~1 s collection cycle
        // inside dockerd for a second sample, so `pre_*` fields are zero. The
        // collector takes the CPU baseline from its previous sample instead.
        let opts = StatsOptions {
            stream: false,
            one_shot: true,
        };
        let mut stream = self.inner.stats(id, Some(opts));
        let s = stream
            .next()
            .await
            .ok_or_else(|| DockerError::NoStats(id.to_string()))??;

        let cpu = s.cpu_stats.as_ref();
        let pre = s.precpu_stats.as_ref();
        let mem = s.memory_stats.as_ref();

        // ContainerMemoryStats.stats is a plain Option<HashMap<String, u64>>
        // (verified against bollard-stubs 1.53.1-rc.29.3.1's models.rs — it is
        // NOT an enum with cgroup-version variants). cgroup v1 exposes
        // total_inactive_file; cgroup v2 only exposes inactive_file. This
        // mirrors the Go implementation's map lookup exactly:
        // `stat.MemoryStats.Stats["total_inactive_file"]`, falling back to
        // `stat.MemoryStats.Stats["inactive_file"]` when the first is zero.
        let mem_detail = mem.and_then(|m| m.stats.as_ref());
        let inactive_file = mem_detail
            .and_then(|st| st.get("total_inactive_file").copied())
            .filter(|v| *v != 0)
            .or_else(|| mem_detail.and_then(|st| st.get("inactive_file").copied()))
            .unwrap_or(0);

        // Sum cumulative rx/tx across every interface in the stats block. Docker
        // omits `networks` entirely for containers on `network_mode: host` (or
        // `none`), which reads as zero traffic here — correct, since there is no
        // per-container interface to account.
        let (net_rx, net_tx) = s
            .networks
            .as_ref()
            .map(|nets| {
                nets.values().fold((0u64, 0u64), |(rx, tx), n| {
                    (
                        rx.saturating_add(n.rx_bytes.unwrap_or(0)),
                        tx.saturating_add(n.tx_bytes.unwrap_or(0)),
                    )
                })
            })
            .unwrap_or((0, 0));

        Ok(ContainerStats {
            cpu_total: cpu
                .and_then(|c| c.cpu_usage.as_ref())
                .and_then(|u| u.total_usage)
                .unwrap_or(0),
            pre_cpu_total: pre
                .and_then(|c| c.cpu_usage.as_ref())
                .and_then(|u| u.total_usage)
                .unwrap_or(0),
            system_usage: cpu.and_then(|c| c.system_cpu_usage).unwrap_or(0),
            pre_system_usage: pre.and_then(|c| c.system_cpu_usage).unwrap_or(0),
            online_cpus: cpu.and_then(|c| c.online_cpus).unwrap_or(0),
            percpu_usage_len: cpu
                .and_then(|c| c.cpu_usage.as_ref())
                .and_then(|u| u.percpu_usage.as_ref())
                .map(|v| v.len() as u32)
                .unwrap_or(0),
            mem_usage: mem.and_then(|m| m.usage).unwrap_or(0),
            mem_limit: mem.and_then(|m| m.limit).unwrap_or(0),
            inactive_file,
            net_rx,
            net_tx,
        })
    }

    pub async fn inspect_health(&self, id: &str) -> Result<String, DockerError> {
        Ok(self.inspect_health_and_restart_count(id).await?.0)
    }

    /// Health and restart count, from the shared cache when the entry is fresh
    /// (see [`InspectCache::get`]), otherwise from a new inspect. `state` is the
    /// container's state from the latest listing. A failed inspect is not cached.
    pub async fn health_and_restart_count(
        &self,
        id: &str,
        state: &str,
    ) -> Result<(String, u64), DockerError> {
        if let Some(v) = self.cache().get(id, state, Instant::now()) {
            return Ok(v);
        }
        let v = self.inspect_health_and_restart_count(id).await?;
        self.cache().insert(id, state, &v, Instant::now());
        Ok(v)
    }

    fn cache(&self) -> MutexGuard<'_, InspectCache> {
        // The cache holds no invariant a panic could break, so a poisoned lock
        // is still safe to use.
        self.inspect_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub async fn inspect_health_and_restart_count(
        &self,
        id: &str,
    ) -> Result<(String, u64), DockerError> {
        let d = self
            .inner
            .inspect_container(id, None::<InspectContainerOptions>)
            .await?;
        let health_status = d
            .state
            .as_ref()
            .and_then(|st| st.health.as_ref())
            .and_then(|h| h.status.as_ref())
            // Display emits the Docker wire values ("healthy", "unhealthy",
            // "starting", "none", "") — matching Go's raw status string. See
            // the state field in list_containers for the rationale.
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let restart_count = d.restart_count.filter(|count| *count >= 0).unwrap_or(0) as u64;

        Ok((health_status, restart_count))
    }
}

/// Maps a `size: true` bollard container summary to our [`ContainerDisk`],
/// keying on the display name (not the raw Docker id) so the recorded series
/// matches the cpu/memory collector and the documented per-container disk
/// endpoint key. Pure and Docker-free so it can be unit-tested directly.
fn container_disk_from_summary(c: bollard::models::ContainerSummary) -> ContainerDisk {
    let id = c.id.unwrap_or_default();
    let names = c.names.unwrap_or_default();
    let labels = c.labels.unwrap_or_default();
    let mount_sources = c
        .mounts
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| m.source.filter(|s| !s.is_empty()))
        .collect();
    ContainerDisk {
        id: model::resolve_display_name(&labels, &names, &id),
        // SizeRw is Option<i64>; a missing or negative value means "unknown",
        // recorded as 0.
        writable_layer: c.size_rw.filter(|v| *v >= 0).unwrap_or(0) as u64,
        mount_sources,
    }
}

/// `/system/df` returns `VolumeUsage`, the only shape bollard parses, from API
/// 1.52 (Docker 29) on. Older daemons answer with the `Volumes` list, so the
/// call would make dockerd walk every volume for a result Sentinel cannot read.
fn has_volume_usage(api_version: Option<&str>) -> bool {
    let Some((major, minor)) = api_version.and_then(|v| v.split_once('.')) else {
        return false;
    };
    match (major.parse::<u32>(), minor.parse::<u32>()) {
        (Ok(major), Ok(minor)) => (major, minor) >= (1, 52),
        _ => false,
    }
}

/// Adds `type=volume` to `/system/df`, which bollard cannot encode (the
/// parameter is a list). Without it the daemon also sizes every image, layer,
/// container, and the build cache on each call (coollabsio/coolify#12518).
fn only_volume_disk_usage(mut request: BollardRequest) -> BollardRequest {
    let uri = request.uri();
    if !uri.path().ends_with("/system/df") {
        return request;
    }
    let separator = if uri.query().is_some() { '&' } else { '?' };
    if let Ok(uri) = format!("{uri}{separator}type=volume").parse() {
        *request.uri_mut() = uri;
    }
    request
}

/// Docker reports `UsageData.Size` as -1 when the size is not available
/// (volume drivers other than `local`); those volumes are left out.
fn volume_sizes_from_items(items: &[serde_json::Value]) -> HashMap<String, u64> {
    items
        .iter()
        .filter_map(|v| {
            let mountpoint = v.get("Mountpoint")?.as_str()?;
            let size = v.get("UsageData")?.get("Size")?.as_i64()?;
            let size = u64::try_from(size).ok()?;
            Some((mountpoint.to_string(), size))
        })
        .collect()
}

#[cfg(test)]
mod tests;
