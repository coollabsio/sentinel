#![deny(unsafe_code)]

pub mod fs_usage;

use std::collections::HashMap;
use std::sync::Arc;

use config::Config;
use docker::DockerClient;
use serde::Serialize;
use store::Store;
use time::format_description::well_known::Rfc3339;
use tokio::sync::watch;
use tokio::task::JoinSet;

const MAX_CONCURRENT_INSPECTS: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("docker: {0}")]
    Docker(#[from] docker::DockerError),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("time format: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("push to {url} returned {status}: {body}")]
    Status {
        url: String,
        status: u16,
        body: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct Container {
    pub time: String,
    pub id: String,
    pub image: String,
    pub name: String,
    pub state: String,
    pub labels: HashMap<String, String>,
    pub health_status: String,
}

pub fn snapshot_metadata(inspection_failures: usize) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "complete": inspection_failures == 0,
        "inspection_failures": inspection_failures,
    })
}

pub struct Pusher {
    config: Arc<Config>,
    docker: DockerClient,
    store: Store,
    client: reqwest::Client,
}

impl Pusher {
    pub fn new(config: Arc<Config>, docker: DockerClient, store: Store) -> Result<Self, PushError> {
        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(100)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(Self {
            config,
            docker,
            store,
            client,
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        // See the collector's identical fix: tokio::time::interval's first
        // tick fires immediately, unlike Go's time.NewTicker. interval_at
        // restores the Go behavior of waiting a full period before the first
        // push, avoiding a push attempt (and possible failure/log noise) at
        // the moment the process starts, before Docker/network may be ready.
        let period = std::time::Duration::from_secs(self.config.push_interval_seconds);
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    tracing::info!("stopping push service");
                    return;
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.push_once().await {
                        tracing::warn!(error = %e, "push operation failed");
                    }
                }
            }
        }
    }

    pub async fn push_once(&self) -> Result<(), PushError> {
        tracing::info!(url = %self.config.push_url, "pushing");
        let payload = self.build_payload().await?;

        let response = self
            .client
            .post(&self.config.push_url)
            .header("Content-Type", "application/json")
            .bearer_auth(&self.config.token)
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(PushError::Status {
                url: self.config.push_url.clone(),
                status: status.as_u16(),
                body: body
                    .chars()
                    .take(4096)
                    .collect::<String>()
                    .trim()
                    .to_string(),
            });
        }
        Ok(())
    }

    pub async fn build_payload(&self) -> Result<serde_json::Value, PushError> {
        let (containers, failures) = self.container_data().await?;
        let used_percentage = fs_usage::root_used_percentage()?;
        let (filesystem_usage, container_storage) = self.storage_data().await;

        // `filesystem_usage` and `container_storage` are additive: Coolify
        // validates only `containers` and reads other keys with data_get(), so
        // it ignores these until updated to consume them. `filesystem_usage_root`
        // (the frozen root-disk field) is left untouched.
        Ok(serde_json::json!({
            "containers": containers,
            "filesystem_usage_root": {
                // Go formats this with %d into a string.
                "used_percentage": used_percentage.to_string(),
            },
            "filesystem_usage": filesystem_usage,
            "container_storage": container_storage,
            "snapshot": snapshot_metadata(failures),
        }))
    }

    /// Reads the latest stored storage rows (never samples live — the `du`-walk
    /// only runs on the storage collector's own cadence). A read failure logs
    /// and contributes empty arrays rather than failing the whole push.
    async fn storage_data(&self) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
        let store = self.store.clone();
        let (disks, containers) = match tokio::task::spawn_blocking(move || {
            (store.disk_latest(), store.container_disk_latest())
        })
        .await
        {
            Ok((d, c)) => (
                d.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to read disk usage for push");
                    Vec::new()
                }),
                c.unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "failed to read container storage for push");
                    Vec::new()
                }),
            ),
            Err(e) => {
                tracing::warn!(error = %e, "storage read task panicked");
                (Vec::new(), Vec::new())
            }
        };

        let filesystem_usage = disks
            .iter()
            .map(|d| {
                serde_json::json!({
                    "mount": d.mount,
                    "total": d.total,
                    "used": d.used,
                    "available": d.available,
                    "usedPercent": d.used_percent,
                })
            })
            .collect();
        let container_storage = containers
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.container_id,
                    "writableLayer": c.writable_layer,
                    "volumesTotal": c.volumes_total,
                })
            })
            .collect();
        (filesystem_usage, container_storage)
    }

    async fn container_data(&self) -> Result<(Vec<Container>, usize), PushError> {
        let summaries = self.docker.list_containers().await?;
        let total = summaries.len();
        if total == 0 {
            return Ok((Vec::new(), 0));
        }

        // One timestamp for the whole cycle so every container in a push shares
        // it, rather than each row carrying its own inspect-completion instant.
        let now = time::OffsetDateTime::now_utc().format(&Rfc3339)?;

        let mut out = Vec::with_capacity(total);
        let mut tasks = JoinSet::new();
        let mut queue = summaries.into_iter();

        for _ in 0..MAX_CONCURRENT_INSPECTS {
            match queue.next() {
                Some(c) => {
                    tasks.spawn(inspect(self.docker.clone(), c, now.clone()));
                }
                None => break,
            }
        }
        while let Some(joined) = tasks.join_next().await {
            if let Some(c) = queue.next() {
                tasks.spawn(inspect(self.docker.clone(), c, now.clone()));
            }
            if let Ok(Some(c)) = joined {
                out.push(c);
            }
        }

        let skipped = total - out.len();
        if skipped > 0 {
            tracing::warn!(
                skipped,
                total,
                "skipped containers due to inspection errors"
            );
        }
        Ok((out, skipped))
    }
}

async fn inspect(
    docker: DockerClient,
    summary: docker::ContainerSummary,
    now: String,
) -> Option<Container> {
    let health = match docker.inspect_health(&summary.id).await {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(id = %summary.id, error = %e, "failed to inspect container");
            return None;
        }
    };

    // The push payload uses the raw Docker name, NOT the coolify.name label
    // that the collector uses. Preserved from the Go implementation.
    let name = summary
        .names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| summary.id.chars().take(12).collect());

    Some(Container {
        time: now,
        id: summary.id,
        image: summary.image,
        name,
        state: summary.state,
        labels: summary.labels,
        health_status: health,
    })
}
