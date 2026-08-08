#![forbid(unsafe_code)]

pub mod calc;
pub mod model;

pub use model::{ContainerStats, ContainerSummary};

use bollard::query_parameters::{
    InspectContainerOptions, ListContainersOptions, StatsOptions,
};
use bollard::Docker;
use futures_util::StreamExt;

const SOCKET: &str = "/var/run/docker.sock";
const TIMEOUT_SECS: u64 = 120;

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
        let inner =
            Docker::connect_with_unix(SOCKET, TIMEOUT_SECS, bollard::API_DEFAULT_VERSION)?;
        Ok(Self { inner })
    }

    pub async fn list_containers(&self) -> Result<Vec<ContainerSummary>, DockerError> {
        let opts = ListContainersOptions { all: true, ..Default::default() };
        let raw = self.inner.list_containers(Some(opts)).await?;
        Ok(raw
            .into_iter()
            .map(|c| ContainerSummary {
                id: c.id.unwrap_or_default(),
                names: c.names.unwrap_or_default(),
                image: c.image.unwrap_or_default(),
                state: c
                    .state
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_default(),
                labels: c.labels.unwrap_or_default(),
            })
            .collect())
    }

    pub async fn stats(&self, id: &str) -> Result<ContainerStats, DockerError> {
        // stream=false yields exactly one datapoint, matching the Go client's
        // /containers/{id}/stats?stream=false request.
        let opts = StatsOptions { stream: false, one_shot: false };
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
            .map(|s| format!("{s:?}").to_lowercase())
            .unwrap_or_else(|| "unknown".to_string()))
    }
}
