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
/// How long a failed follower keeps its container followed, so a failure that
/// repeats at once (an unwritable archive, a logging driver Docker cannot
/// read) is retried at this pace and not in a busy loop.
const RETRY_DELAY: Duration = Duration::from_secs(30);
const MANAGED_FILTER: &str = "coolify.managed=true";

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy)]
struct Exit {
    /// When Docker saw the container die, on Docker's clock.
    at: Timestamp,
    code: i64,
    oom_killed: bool,
}

struct Followed {
    /// When the follower started. A `die` before it is from an earlier run,
    /// replayed when the event stream reconnects.
    since: Timestamp,
    path: PathBuf,
    exits: mpsc::UnboundedSender<Exit>,
    task: AbortHandle,
}

pub struct LogArchive {
    /// For the log and event streams.
    docker: Docker,
    /// For list and inspect, with a timeout, so a hung daemon cannot stall the run loop.
    api: Docker,
    root: PathBuf,
    max_file_bytes: u64,
    limits: Limits,
}

impl LogArchive {
    pub fn new(settings: &config::LogArchiveSettings) -> Result<Self, docker::DockerError> {
        const MB: u64 = 1024 * 1024;
        Ok(Self {
            docker: docker::streaming_client()?,
            api: docker::request_client()?,
            root: settings.dir.clone(),
            max_file_bytes: settings.max_file_mb.saturating_mul(MB),
            limits: Limits {
                max_age: Duration::from_secs(u64::from(settings.retention_days) * 24 * 60 * 60),
                max_total_bytes: settings.max_total_mb.saturating_mul(MB),
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
                let at = event
                    .time_nano
                    .map(Timestamp::from_unix_nanos)
                    .or(event
                        .time
                        .map(|secs| Timestamp::from_unix_nanos(secs * 1_000_000_000)))
                    .unwrap_or_else(Timestamp::now);
                if let (Some(code), Some(followed)) = (code, state.followed.get(&id))
                    && at >= followed.since
                {
                    let _ = followed.exits.send(Exit {
                        at,
                        code,
                        oom_killed,
                    });
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
        let containers = match self.api.list_containers(Some(options)).await {
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
            api: self.api.clone(),
            path: path.clone(),
            max_file_bytes: self.max_file_bytes,
            exits: exit_rx,
            shutdown: shutdown.clone(),
        };
        let id = target.id.clone();
        let mut shutdown = shutdown.clone();
        let task = state.tasks.spawn(async move {
            if let Err(error) = follower.run(&target).await {
                tracing::warn!(%error, container = %target.name, "container log archive stopped, retrying");
                tokio::select! {
                    _ = shutdown.changed() => {}
                    _ = tokio::time::sleep(RETRY_DELAY) => {}
                }
            }
        });
        state.followed.insert(
            id,
            Followed {
                since: Timestamp::now(),
                path,
                exits,
                task,
            },
        );
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
    api: Docker,
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
        let mut last_at = resume;

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
                    last_at = Some(record.at);
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
            // Lines drained after the `die` can carry a later timestamp; the
            // marker must not be older than them, as it is the resume point.
            let at = last_at.map_or(exit.at, |last| last.max(exit.at));
            writer
                .write_line(&exit_marker(at, exit.code, oom_killed))
                .await?;
            writer.flush().await?;
        }
        Ok(())
    }

    async fn inspect_oom_killed(&self, id: &str) -> bool {
        self.api
            .inspect_container(id, None)
            .await
            .ok()
            .and_then(|c| c.state)
            .and_then(|s| s.oom_killed)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use bollard::models::EventActor;

    use super::*;

    const ID: &str = "0123456789abcdef";

    /// An archive whose Docker clients fail every request: the socket path
    /// is a plain file, which bollard accepts.
    fn archive(root: &std::path::Path, socket: &tempfile::NamedTempFile) -> LogArchive {
        let client = |timeout| {
            Docker::connect_with_unix(
                socket.path().to_str().unwrap(),
                timeout,
                bollard::API_DEFAULT_VERSION,
            )
            .unwrap()
        };
        LogArchive {
            docker: client(3600),
            api: client(10),
            root: root.to_path_buf(),
            max_file_bytes: 1024,
            limits: Limits {
                max_age: Duration::from_secs(60),
                max_total_bytes: 1024,
            },
        }
    }

    fn empty_state() -> State {
        State {
            followed: HashMap::new(),
            tasks: JoinSet::new(),
            oom_killed: HashSet::new(),
            last_event_secs: None,
        }
    }

    fn target() -> Target {
        let labels = HashMap::from([
            ("coolify.managed".to_string(), "true".to_string()),
            ("coolify.applicationUuid".to_string(), "app1".to_string()),
        ]);
        Target::from_container(ID, "web", &labels).unwrap()
    }

    /// Follows [`ID`] with a task that never ends, and returns the receiver
    /// of its exits.
    fn followed_since(state: &mut State, since: Timestamp) -> mpsc::UnboundedReceiver<Exit> {
        let (exits, exit_rx) = mpsc::unbounded_channel();
        let task = state.tasks.spawn(std::future::pending());
        state.followed.insert(
            ID.to_string(),
            Followed {
                since,
                path: PathBuf::new(),
                exits,
                task,
            },
        );
        exit_rx
    }

    fn event(action: &str, time_nano: i64, attributes: &[(&str, &str)]) -> EventMessage {
        EventMessage {
            action: Some(action.to_string()),
            actor: Some(EventActor {
                id: Some(ID.to_string()),
                attributes: Some(
                    attributes
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
            }),
            time: Some(time_nano / 1_000_000_000),
            time_nano: Some(time_nano),
            ..Default::default()
        }
    }

    const SINCE: i64 = 1_793_096_130_000_000_000;

    #[tokio::test]
    async fn sends_the_exit_of_a_followed_container() {
        let (root, socket) = (
            tempfile::tempdir().unwrap(),
            tempfile::NamedTempFile::new().unwrap(),
        );
        let archive = archive(root.path(), &socket);
        let (_tx, shutdown) = watch::channel(false);
        let mut state = empty_state();
        let mut exits = followed_since(&mut state, Timestamp::from_unix_nanos(SINCE));

        archive.handle_event(event("oom", SINCE + 1, &[]), &mut state, &shutdown);
        archive.handle_event(
            event("die", SINCE + 2, &[("exitCode", "137")]),
            &mut state,
            &shutdown,
        );

        let exit = exits.try_recv().unwrap();
        assert_eq!(exit.code, 137);
        assert!(exit.oom_killed);
        assert_eq!(exit.at, Timestamp::from_unix_nanos(SINCE + 2));
        assert!(state.oom_killed.is_empty());
        assert_eq!(state.last_event_secs, Some(SINCE / 1_000_000_000));
    }

    #[tokio::test]
    async fn drops_a_replayed_exit_of_an_earlier_run() {
        let (root, socket) = (
            tempfile::tempdir().unwrap(),
            tempfile::NamedTempFile::new().unwrap(),
        );
        let archive = archive(root.path(), &socket);
        let (_tx, shutdown) = watch::channel(false);
        let mut state = empty_state();
        let mut exits = followed_since(&mut state, Timestamp::from_unix_nanos(SINCE));

        archive.handle_event(
            event("die", SINCE - 1, &[("exitCode", "1")]),
            &mut state,
            &shutdown,
        );
        assert!(exits.try_recv().is_err());

        archive.handle_event(
            event("die", SINCE + 1, &[("exitCode", "0")]),
            &mut state,
            &shutdown,
        );
        assert_eq!(exits.try_recv().unwrap().code, 0);
    }

    #[tokio::test]
    async fn a_failed_follower_waits_before_it_is_followed_again() {
        let (root, socket) = (
            tempfile::tempdir().unwrap(),
            tempfile::NamedTempFile::new().unwrap(),
        );
        let archive = archive(root.path(), &socket);
        let (shutdown_tx, shutdown) = watch::channel(false);
        let mut state = empty_state();
        let path = target().path(root.path());
        archive.follow(target(), &mut state, &shutdown);

        // The log stream fails at once: the archive file exists, the task waits.
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!state.followed[ID].task.is_finished());

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), state.tasks.join_next())
            .await
            .expect("shutdown ends the retry wait")
            .unwrap()
            .unwrap();
    }
}
