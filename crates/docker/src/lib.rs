#![forbid(unsafe_code)]

pub mod calc;
pub mod model;

pub use model::{ContainerDisk, ContainerStats, ContainerSummary};

use bollard::Docker;
use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions, StatsOptions};
use futures_util::StreamExt;

const SOCKET: &str = "/var/run/docker.sock";
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
}

impl DockerClient {
    pub fn new() -> Result<Self, DockerError> {
        let inner = Docker::connect_with_unix(SOCKET, TIMEOUT_SECS, bollard::API_DEFAULT_VERSION)?;
        Ok(Self { inner })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerError> {
        let opts = ListContainersOptions {
            all: true,
            ..Default::default()
        };
        let raw = self.inner.list_containers(Some(opts)).await?;
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
        Ok(raw
            .into_iter()
            .map(|c| {
                let mount_sources = c
                    .mounts
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|m| m.source.filter(|s| !s.is_empty()))
                    .collect();
                ContainerDisk {
                    id: c.id.unwrap_or_default(),
                    // SizeRw is Option<i64>; a missing or negative value means
                    // "unknown", recorded as 0.
                    writable_layer: c.size_rw.filter(|v| *v >= 0).unwrap_or(0) as u64,
                    mount_sources,
                }
            })
            .collect())
    }

    pub async fn stats(&self, id: &str) -> Result<ContainerStats, DockerError> {
        // stream=false yields exactly one datapoint, matching the Go client's
        // /containers/{id}/stats?stream=false request.
        let opts = StatsOptions {
            stream: false,
            one_shot: false,
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
        })
    }

    pub async fn inspect_health(&self, id: &str) -> Result<String, DockerError> {
        let d = self
            .inner
            .inspect_container(id, None::<InspectContainerOptions>)
            .await?;
        Ok(d.state
            .as_ref()
            .and_then(|st| st.health.as_ref())
            .and_then(|h| h.status.as_ref())
            // Display emits the Docker wire values ("healthy", "unhealthy",
            // "starting", "none", "") — matching Go's raw status string. See
            // the state field in list_containers for the rationale.
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bollard::models::{ContainerSummaryStateEnum, HealthStatusEnum};

    // Coolify's PushServerUpdateJob keys container status on these exact
    // lowercase strings (running / restarting / exited / paused / dead ...),
    // and the push/list wire values come from these enums' Display impl. Pin
    // the mapping so a bollard upgrade that renames a variant or changes its
    // Display can't silently break status reporting to Coolify.
    #[test]
    fn container_state_wire_strings_match_docker() {
        use ContainerSummaryStateEnum::*;
        assert_eq!(CREATED.to_string(), "created");
        assert_eq!(RUNNING.to_string(), "running");
        assert_eq!(PAUSED.to_string(), "paused");
        assert_eq!(RESTARTING.to_string(), "restarting");
        assert_eq!(EXITED.to_string(), "exited");
        assert_eq!(REMOVING.to_string(), "removing");
        assert_eq!(DEAD.to_string(), "dead");
        // The empty state must serialize to "" (Go's empty string), NOT "empty".
        assert_eq!(EMPTY.to_string(), "");
    }

    #[test]
    fn health_status_wire_strings_match_docker() {
        use HealthStatusEnum::*;
        assert_eq!(NONE.to_string(), "none");
        assert_eq!(STARTING.to_string(), "starting");
        assert_eq!(HEALTHY.to_string(), "healthy");
        assert_eq!(UNHEALTHY.to_string(), "unhealthy");
        assert_eq!(EMPTY.to_string(), "");
    }
}
