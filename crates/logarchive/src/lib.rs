#![forbid(unsafe_code)]

//! Archives the logs of Coolify-managed containers to files, so Coolify can
//! read them over SSH after Docker removes the container and its json log.
//! One task follows each running container; one loop owns the set of
//! followed containers, the Docker event stream, and the retention sweep.

mod file;
mod line;
mod retention;
mod target;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use bollard::Docker;
use bollard::models::EventMessage;
use bollard::query_parameters::{EventsOptions, ListContainersOptions, LogsOptions};
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinSet};

use file::{ArchiveWriter, read_resume_point};
use line::{Timestamp, exit_marker, parse_chunk};
use retention::Limits;
use target::Target;

const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// How long a finished log stream waits for the `die` event that carries the
/// exit code.
const EXIT_WAIT: Duration = Duration::from_secs(10);
/// Lines fetched for a container with no archive yet, so a long-running
/// container does not dump its whole history at Sentinel's first start.
const FIRST_FOLLOW_TAIL: &str = "10000";
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MANAGED_FILTER: &str = "coolify.managed=true";

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy)]
struct Exit {
    code: i64,
    oom_killed: bool,
}

struct Followed {
    path: PathBuf,
    exits: mpsc::UnboundedSender<Exit>,
    task: AbortHandle,
}

pub struct LogArchive {
    docker: Docker,
    root: PathBuf,
    max_file_bytes: u64,
    limits: Limits,
}

impl LogArchive {
    pub fn new(settings: &config::LogArchiveSettings) -> Result<Self, docker::DockerError> {
        const MB: u64 = 1024 * 1024;
        Ok(Self {
            docker: docker::streaming_client()?,
            root: settings.dir.clone(),
            max_file_bytes: settings.max_file_mb * MB,
            limits: Limits {
                max_age: Duration::from_secs(u64::from(settings.retention_days) * 24 * 60 * 60),
                max_total_bytes: settings.max_total_mb * MB,
            },
        })
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        tracing::info!(dir = %self.root.display(), "container log archive started");
        if let Err(error) = file::create_private_dir(&self.root).await {
            tracing::warn!(%error, dir = %self.root.display(), "cannot create the container log archive directory");
        }

        let mut state = State {
            followed: HashMap::new(),
            tasks: JoinSet::new(),
            oom_killed: HashSet::new(),
            last_event_secs: None,
        };
        let mut sweep_ticker = tokio::time::interval(SWEEP_INTERVAL);
        let mut events = self.events(None);
        let mut backoff = Duration::from_secs(1);
        self.reconcile(&mut state, &shutdown).await;

        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = sweep_ticker.tick() => self.sweep(&state).await,
                Some(_) = state.tasks.join_next() => {
                    state.followed.retain(|_, f| !f.task.is_finished());
                    // A container restarted while its old stream drained was
                    // not followed again on `start`.
                    self.reconcile(&mut state, &shutdown).await;
                }
                event = events.next() => match event {
                    Some(Ok(event)) => {
                        backoff = Duration::from_secs(1);
                        self.handle_event(event, &mut state, &shutdown);
                    }
                    failure => {
                        match failure {
                            Some(Err(error)) => tracing::warn!(%error, "docker event stream failed, reconnecting"),
                            _ => tracing::warn!("docker event stream ended, reconnecting"),
                        }
                        tokio::select! {
                            _ = shutdown.changed() => break,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(MAX_BACKOFF);
                        events = self.events(state.last_event_secs);
                        self.reconcile(&mut state, &shutdown).await;
                    }
                },
            }
        }
        while state.tasks.join_next().await.is_some() {}
    }

    fn events(
        &self,
        since_secs: Option<i64>,
    ) -> BoxStream<'static, Result<EventMessage, bollard::errors::Error>> {
        let filters = HashMap::from([
            ("type".to_string(), vec!["container".to_string()]),
            (
                "event".to_string(),
                ["start", "die", "destroy", "oom"]
                    .map(String::from)
                    .to_vec(),
            ),
            ("label".to_string(), vec![MANAGED_FILTER.to_string()]),
        ]);
        let options = EventsOptions {
            since: since_secs.map(|secs| secs.to_string()),
            filters: Some(filters),
            ..Default::default()
        };
        self.docker.events(Some(options)).boxed()
    }

    fn handle_event(
        &self,
        event: EventMessage,
        state: &mut State,
        shutdown: &watch::Receiver<bool>,
    ) {
        if let Some(secs) = event.time {
            state.last_event_secs = Some(secs);
        }
        let Some(actor) = event.actor else { return };
        let Some(id) = actor.id else { return };
        let attributes = actor.attributes.unwrap_or_default();
        match event.action.as_deref() {
            Some("start") => {
                let name = attributes.get("name").map(String::as_str).unwrap_or("");
                if let Some(target) = Target::from_container(&id, name, &attributes) {
                    self.follow(target, state, shutdown);
                }
            }
            Some("oom") => {
                state.oom_killed.insert(id);
            }
            Some("die") => {
                let oom_killed = state.oom_killed.remove(&id)
                    || attributes.get("oomKilled").map(String::as_str) == Some("true");
                let code = attributes.get("exitCode").and_then(|c| c.parse().ok());
                if let (Some(code), Some(followed)) = (code, state.followed.get(&id)) {
                    let _ = followed.exits.send(Exit { code, oom_killed });
                }
            }
            Some("destroy") => {
                state.oom_killed.remove(&id);
            }
            _ => {}
        }
    }

    /// Follows every running managed container that is not followed yet.
    async fn reconcile(&self, state: &mut State, shutdown: &watch::Receiver<bool>) {
        let options = ListContainersOptions {
            filters: Some(HashMap::from([
                ("label".to_string(), vec![MANAGED_FILTER.to_string()]),
                ("status".to_string(), vec!["running".to_string()]),
            ])),
            ..Default::default()
        };
        let containers = match self.docker.list_containers(Some(options)).await {
            Ok(containers) => containers,
            Err(error) => {
                tracing::warn!(%error, "cannot list containers to archive their logs");
                return;
            }
        };
        for container in containers {
            let id = container.id.unwrap_or_default();
            let name = container
                .names
                .and_then(|names| names.into_iter().next())
                .unwrap_or_default();
            let labels = container.labels.unwrap_or_default();
            if let Some(target) = Target::from_container(&id, &name, &labels) {
                self.follow(target, state, shutdown);
            }
        }
    }

    fn follow(&self, target: Target, state: &mut State, shutdown: &watch::Receiver<bool>) {
        if state.followed.contains_key(&target.id) {
            return;
        }
        let path = target.path(&self.root);
        let (exits, exit_rx) = mpsc::unbounded_channel();
        let follower = Follower {
            docker: self.docker.clone(),
            path: path.clone(),
            max_file_bytes: self.max_file_bytes,
            exits: exit_rx,
            shutdown: shutdown.clone(),
        };
        let id = target.id.clone();
        let task = state.tasks.spawn(async move {
            if let Err(error) = follower.run(&target).await {
                tracing::warn!(%error, container = %target.name, "container log archive stopped");
            }
        });
        state.followed.insert(id, Followed { path, exits, task });
    }

    async fn sweep(&self, state: &State) {
        let followed: HashSet<PathBuf> = state.followed.values().map(|f| f.path.clone()).collect();
        let root = self.root.clone();
        let limits = self.limits;
        match tokio::task::spawn_blocking(move || retention::sweep(&root, &followed, limits)).await
        {
            Ok(Ok(0)) => {}
            Ok(Ok(deleted)) => {
                tracing::info!(deleted, "container log archive retention pass complete")
            }
            Ok(Err(error)) => tracing::warn!(%error, "container log archive retention pass failed"),
            Err(error) => tracing::warn!(%error, "container log archive retention task panicked"),
        }
    }
}

/// State owned by the run loop alone.
struct State {
    followed: HashMap<String, Followed>,
    tasks: JoinSet<()>,
    oom_killed: HashSet<String>,
    last_event_secs: Option<i64>,
}

struct Follower {
    docker: Docker,
    path: PathBuf,
    max_file_bytes: u64,
    exits: mpsc::UnboundedReceiver<Exit>,
    shutdown: watch::Receiver<bool>,
}

impl Follower {
    async fn run(mut self, target: &Target) -> Result<(), Error> {
        // Lines up to the archive's last timestamp are already written: by an
        // earlier Sentinel run, or before the container restarted.
        let resume = read_resume_point(&self.path).await;
        let options = LogsOptions {
            follow: true,
            stdout: true,
            stderr: true,
            timestamps: true,
            since: resume.map_or(0, |at| i32::try_from(at.secs()).unwrap_or(0)),
            tail: match resume {
                Some(_) => "all".to_string(),
                None => FIRST_FOLLOW_TAIL.to_string(),
            },
            ..Default::default()
        };
        let mut writer = ArchiveWriter::open(self.path.clone(), self.max_file_bytes).await?;
        let mut stream = self
            .docker
            .logs(&target.id, Some(options))
            .ready_chunks(256);
        tracing::debug!(container = %target.name, path = %self.path.display(), "archiving container logs");

        loop {
            let batch = tokio::select! {
                _ = self.shutdown.changed() => return Ok(writer.flush().await?),
                batch = stream.next() => batch,
            };
            let Some(batch) = batch else { break };
            for output in batch {
                let output = match output {
                    Ok(output) => output,
                    Err(error) => {
                        writer.flush().await?;
                        return Err(error.into());
                    }
                };
                for record in parse_chunk(output.as_ref(), Timestamp::now()) {
                    if resume.is_some_and(|resume| record.at <= resume) {
                        continue;
                    }
                    writer.write_line(&record.to_line()).await?;
                }
            }
            writer.flush().await?;
        }

        let exit = tokio::select! {
            _ = self.shutdown.changed() => None,
            exit = tokio::time::timeout(EXIT_WAIT, self.exits.recv()) => exit.ok().flatten(),
        };
        if let Some(exit) = exit {
            let oom_killed = exit.oom_killed || self.inspect_oom_killed(&target.id).await;
            writer
                .write_line(&exit_marker(Timestamp::now(), exit.code, oom_killed))
                .await?;
            writer.flush().await?;
        }
        Ok(())
    }

    async fn inspect_oom_killed(&self, id: &str) -> bool {
        self.docker
            .inspect_container(id, None)
            .await
            .ok()
            .and_then(|c| c.state)
            .and_then(|s| s.oom_killed)
            .unwrap_or(false)
    }
}
