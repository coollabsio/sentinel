//! Converges the containers of this Node to the desired set (decision 0026 of
//! Coolify), also while Flux or Coolify is down.
//!
//! Without a confirmed connection, Sentinel only keeps the containers of the
//! stored set running: it starts a stopped one with a backoff. A deploy, a
//! stop, and a removal wait until Coolify confirmed the current generation
//! on the connection, so a Node that was offline cannot run a workload that
//! Coolify moved away. A pull also waits, because the registry login is only
//! in the change from Coolify.
//!
//! A deploy runs as `workload.deploy.v1` does. A rolling deploy (decision
//! 0022) starts the new container beside the old one and removes the old one
//! after the new one is healthy. A new container that restarts, gets
//! unhealthy, or does not get healthy in time fails its revision; the new
//! container of a rolling deploy is then removed and the old one keeps
//! serving. A failed revision is not tried again while an older container of
//! the workload runs.

use std::sync::Arc;
use std::time::Duration;

use sentinel_protocol::control::v1::{
    ContainerObservation, StoredWorkloadEntry, WorkloadDeployRequest, WorkloadDesiredState,
    WorkloadLifecycleAction, WorkloadLifecycleRequest, WorkloadSetEntry, WorkloadStatusValue,
};
use tokio::sync::watch;

use crate::commands::CommandExecutor;
use crate::network::LocalPort;
use crate::workload_set::{Snapshot, WorkloadSet};

/// A container without a health check must keep running this long after the
/// start, so a crash right after the start is not a success.
pub(crate) const SETTLE_MILLIS: i64 = 10_000;
/// The longest wait for a health check to pass.
const MAX_HEALTH_WAIT_MILLIS: i64 = 300_000;
/// A failed revision without an older running container is tried again
/// after this time.
const FAILED_RETRY_MILLIS: i64 = 10 * 60_000;
const START_BACKOFF_INITIAL_MILLIS: i64 = 10_000;
const START_BACKOFF_MAX_MILLIS: i64 = 10 * 60_000;
/// A container that ran this long resets the start backoff.
const STABLE_RUN_MILLIS: i64 = 60_000;
const BUSY_INTERVAL: Duration = Duration::from_secs(2);
const IDLE_INTERVAL: Duration = Duration::from_secs(15);
const RUNNING_STATES: [&str; 3] = ["running", "restarting", "paused"];

pub(crate) async fn run(
    set: WorkloadSet,
    executor: Arc<tokio::sync::Mutex<CommandExecutor>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let changed = set.changed();
    loop {
        let pass_set = set.clone();
        let locked = executor.clone().lock_owned().await;
        let busy =
            tokio::task::spawn_blocking(move || converge_once(&pass_set, &*locked, now_millis()))
                .await
                .unwrap_or(true);
        let interval = if busy { BUSY_INTERVAL } else { IDLE_INTERVAL };
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = changed.notified() => {}
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// What the converger does with Podman. The command executor implements it;
/// the tests use a fake.
pub(crate) trait Runtime {
    fn containers(&self) -> Result<Vec<ContainerObservation>, String>;
    fn deploy(&self, request: &WorkloadDeployRequest) -> Result<String, String>;
    fn lifecycle(&self, request: &WorkloadLifecycleRequest) -> Result<(), String>;
    /// The network revision that this Node applied (the firewall state).
    fn network_revision(&self) -> u64;
    /// Sets the local rules of the published ports (decision 0037 of
    /// Coolify) in one change. An unchanged list changes nothing.
    fn local_ports(&self, ports: &[LocalPort]) -> Result<(), String>;
}

impl Runtime for CommandExecutor {
    fn containers(&self) -> Result<Vec<ContainerObservation>, String> {
        self.list_containers()
    }

    fn deploy(&self, request: &WorkloadDeployRequest) -> Result<String, String> {
        self.converge_deploy(request)
            .map(|result| result.runtime_id)
    }

    fn lifecycle(&self, request: &WorkloadLifecycleRequest) -> Result<(), String> {
        self.converge_lifecycle(request).map(|_| ())
    }

    fn network_revision(&self) -> u64 {
        self.applied_firewall_revision()
    }

    fn local_ports(&self, ports: &[LocalPort]) -> Result<(), String> {
        self.apply_local_ports(ports)
    }
}

/// Containers that a one-shot command stopped for a while, for example a
/// volume backup with `stop_container`. The converger does not start them.
fn held() -> &'static std::sync::Mutex<std::collections::HashMap<String, usize>> {
    static HELD: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, usize>>> =
        std::sync::OnceLock::new();
    HELD.get_or_init(Default::default)
}

/// Keeps the converger away from a container until the guard drops.
pub(crate) struct Hold(String);

pub(crate) fn hold(name: &str) -> Hold {
    *held()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(name.to_string())
        .or_default() += 1;
    Hold(name.to_string())
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut held = held()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.0);
            }
        }
    }
}

fn is_held(name: &str) -> bool {
    held()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(name)
}

fn label<'a>(container: &'a ContainerObservation, key: &str) -> Option<&'a str> {
    container.labels.get(key).map(String::as_str)
}

fn is_running(container: &ContainerObservation) -> bool {
    RUNNING_STATES.contains(&container.state.as_str())
}

/// One pass over the set. True when an entry is still in progress, so the
/// next pass comes soon.
pub(crate) fn converge_once(set: &WorkloadSet, runtime: &impl Runtime, now: i64) -> bool {
    let snapshot = set.snapshot();
    if snapshot.entries.is_empty() && snapshot.removing.is_empty() {
        // The last workload with a published port can be gone.
        if let Err(error) = runtime.local_ports(&[]) {
            tracing::warn!(%error, "Sentinel could not remove the local rules of the published ports");
            return true;
        }
        return false;
    }
    let containers = match runtime.containers() {
        Ok(containers) => containers,
        Err(error) => {
            tracing::warn!(%error, "Sentinel could not list the containers of the desired set");
            return true;
        }
    };
    let mut busy = false;
    if snapshot.confirmed {
        for workload_id in &snapshot.removing {
            busy |= remove_workload(set, runtime, &containers, workload_id);
        }
    }
    let network_revision = runtime.network_revision();
    for stored in &snapshot.entries {
        let Some(entry) = &stored.entry else {
            continue;
        };
        let own: Vec<&ContainerObservation> = containers
            .iter()
            .filter(|container| label(container, "coolify.workload") == Some(&entry.workload_id))
            .collect();
        let step = Step {
            set,
            runtime,
            snapshot: &snapshot,
            stored,
            entry,
            own: &own,
            containers: &containers,
            now,
            network_revision,
        };
        // A one-shot command stopped the container for a while (a backup).
        if entry
            .deploy
            .as_ref()
            .is_some_and(|deploy| is_held(&deploy.name))
        {
            busy = true;
            continue;
        }
        busy |= match WorkloadDesiredState::try_from(entry.desired_state) {
            Ok(WorkloadDesiredState::Stopped) => step.stopped(),
            _ => step.running(),
        };
    }
    // After the passes of the entries: a new container that got healthy in
    // this pass has its rule already (see `retire_replaced`).
    if let Err(error) = runtime.local_ports(&local_ports(&set.snapshot(), &containers)) {
        tracing::warn!(%error, "Sentinel could not set the local rules of the published ports");
        busy = true;
    }
    busy
}

/// The local rules of the published ports of the set (decision 0037 of
/// Coolify). Coolify puts a port in the entry only on a Node whose container
/// has the desired state running, so a stopped entry has none. The rule
/// points to the container of the entry after it is healthy. Before that, in
/// a rolling deploy, it points to the running container of `replaces`, so a
/// new container that fails never gets traffic. A port that 2 entries use is
/// kept for the first workload ID.
pub(crate) fn local_ports(
    snapshot: &Snapshot,
    containers: &[ContainerObservation],
) -> Vec<LocalPort> {
    let mut ports: Vec<LocalPort> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for stored in &snapshot.entries {
        let Some(entry) = &stored.entry else {
            continue;
        };
        let Some(deploy) = &entry.deploy else {
            continue;
        };
        if entry.published_ports.is_empty()
            || WorkloadDesiredState::try_from(entry.desired_state)
                != Ok(WorkloadDesiredState::Running)
        {
            continue;
        }
        let replaced_runs = !entry.replaces.is_empty()
            && !entry.replaces_container_ip.is_empty()
            && containers.iter().any(|container| {
                container.name == entry.replaces
                    && label(container, "coolify.workload") == Some(&entry.workload_id)
                    && is_running(container)
            });
        let container_ip = if !stored.applied && replaced_runs {
            &entry.replaces_container_ip
        } else {
            &deploy.container_ip
        };
        for port in &entry.published_ports {
            if !seen.insert((port.protocol.clone(), port.host_port)) {
                tracing::warn!(workload = %entry.workload_id, port = port.host_port, "Sentinel skips a published port that another workload of the set uses");
                continue;
            }
            let mut source_cidrs = port
                .source_cidrs
                .iter()
                .filter_map(|cidr| crate::network::ipv4_network(cidr))
                .collect::<Vec<_>>();
            source_cidrs.sort_unstable();
            source_cidrs.dedup();
            ports.push(LocalPort {
                protocol: port.protocol.clone(),
                host_port: port.host_port,
                container_ip: container_ip.clone(),
                container_port: port.container_port,
                source_cidrs,
                network_subnet: deploy.network_subnet.clone(),
            });
        }
    }
    ports.sort_by(|left, right| {
        (&left.protocol, left.host_port).cmp(&(&right.protocol, right.host_port))
    });
    ports
}

fn remove_workload(
    set: &WorkloadSet,
    runtime: &impl Runtime,
    containers: &[ContainerObservation],
    workload_id: &str,
) -> bool {
    let mut failed = false;
    for container in containers
        .iter()
        .filter(|container| label(container, "coolify.workload") == Some(workload_id))
    {
        if let Err(error) = runtime.lifecycle(&lifecycle(
            &container.name,
            WorkloadLifecycleAction::Remove,
            None,
        )) {
            tracing::warn!(%error, container = %container.name, "Sentinel could not remove a container of a removed workload");
            failed = true;
        }
    }
    if !failed {
        set.finish_removal(workload_id);
    }
    failed
}

fn lifecycle(
    name: &str,
    action: WorkloadLifecycleAction,
    stop_timeout_seconds: Option<u32>,
) -> WorkloadLifecycleRequest {
    WorkloadLifecycleRequest {
        name: name.into(),
        action: action as i32,
        stop_timeout_seconds,
    }
}

struct Step<'a, R: Runtime> {
    set: &'a WorkloadSet,
    runtime: &'a R,
    snapshot: &'a Snapshot,
    stored: &'a StoredWorkloadEntry,
    entry: &'a WorkloadSetEntry,
    own: &'a [&'a ContainerObservation],
    /// Every container of the Node, for the local rules.
    containers: &'a [ContainerObservation],
    now: i64,
    network_revision: u64,
}

impl<R: Runtime> Step<'_, R> {
    fn deploy(&self) -> &WorkloadDeployRequest {
        self.entry
            .deploy
            .as_ref()
            .expect("validated entries have a deploy")
    }

    fn named(&self, name: &str) -> Option<&ContainerObservation> {
        self.own
            .iter()
            .copied()
            .find(|container| container.name == name)
    }

    fn status(
        &self,
        status: WorkloadStatusValue,
        reason: &str,
        runtime_id: &str,
        autonomous: bool,
    ) {
        self.set
            .set_status(self.entry, status, reason, runtime_id, autonomous);
    }

    fn update(&self, update: impl FnOnce(&mut StoredWorkloadEntry)) {
        self.set.update_entry(
            &self.entry.workload_id,
            &self.entry.revision_id,
            &self.deploy().name,
            update,
        );
    }

    fn stopped(&self) -> bool {
        if !self.snapshot.confirmed {
            return false;
        }
        let mut failed = None;
        for container in self.own.iter().filter(|container| is_running(container)) {
            if let Err(error) = self.runtime.lifecycle(&lifecycle(
                &container.name,
                WorkloadLifecycleAction::Stop,
                self.entry.stop_timeout_seconds,
            )) {
                failed = Some(error);
            }
        }
        match failed {
            Some(error) => {
                self.status(WorkloadStatusValue::Failed, &error, "", false);
                true
            }
            None => {
                self.status(WorkloadStatusValue::Stopped, "", "", false);
                false
            }
        }
    }

    fn running(&self) -> bool {
        let deploy = self.deploy();
        let current = self.named(&deploy.name).filter(|container| {
            label(container, "coolify.revision") == Some(&self.entry.revision_id)
        });
        match current {
            _ if self.stored.redeploy_pending => self.start_new(),
            Some(container) if is_running(container) => self.verify(container),
            Some(container) => self.exited(container),
            None => self.start_new(),
        }
    }

    /// The container of the entry runs: judge a new one, or keep an applied
    /// one.
    fn verify(&self, container: &ContainerObservation) -> bool {
        if self.stored.applied {
            if self.snapshot.confirmed {
                self.retire_replaced();
            }
            let started = container.started_at_unix_ms.unwrap_or(self.now);
            if self.stored.start_attempts > 0 && self.now - started >= STABLE_RUN_MILLIS {
                self.update(|stored| stored.start_attempts = 0);
            }
            // A start that Sentinel made alone is also reported as its own.
            let autonomous = self
                .stored
                .status
                .as_ref()
                .is_some_and(|status| status.autonomous);
            if self.stored.start_requested {
                self.update(|stored| stored.start_requested = false);
            }
            self.status(
                WorkloadStatusValue::Healthy,
                if autonomous {
                    "Sentinel started the container again, and it runs."
                } else {
                    ""
                },
                &container.runtime_id,
                autonomous,
            );
            return false;
        }
        let started = container.started_at_unix_ms.unwrap_or(self.now);
        let elapsed = self.now - started;
        let health = container.health_status.as_deref();
        // Podman reports the start in whole seconds.
        if started < self.stored.put_at_unix_ms / 1_000 * 1_000 && health != Some("unhealthy") {
            // The container ran before Coolify put this entry, for example a
            // workload of the command path: adopt it.
            self.update(|stored| stored.applied = true);
            self.status(
                WorkloadStatusValue::Healthy,
                "",
                &container.runtime_id,
                false,
            );
            return false;
        }
        if container.restart_count.unwrap_or(0) > 0 {
            return self.fail("The application stopped right after the start, and Podman restarted it. Check the logs of the application: its start command or its configuration can be wrong.", Some(container));
        }
        if health == Some("unhealthy") {
            return self.fail(
                &format!(
                    "The application is unhealthy: its health check failed.{}",
                    self.health_check_note()
                ),
                Some(container),
            );
        }
        // With a Coolify health check, only `healthy` counts.
        let healthy = if self.deploy().health_check.is_some() {
            health == Some("healthy")
        } else {
            health != Some("starting")
        };
        if healthy && elapsed >= SETTLE_MILLIS {
            self.update(|stored| {
                stored.applied = true;
                stored.failed = false;
            });
            // Without a confirmed connection, the applied branch removes it
            // later.
            if self.snapshot.confirmed {
                self.retire_replaced();
            }
            self.status(
                WorkloadStatusValue::Healthy,
                "",
                &container.runtime_id,
                false,
            );
            return false;
        }
        if elapsed >= health_wait_millis(self.deploy()) {
            return self.fail(
                &format!(
                    "The health check did not pass in time.{}",
                    self.health_check_note()
                ),
                Some(container),
            );
        }
        self.status(
            WorkloadStatusValue::Progressing,
            "Sentinel waits until the new container is healthy.",
            &container.runtime_id,
            false,
        );
        true
    }

    fn health_check_note(&self) -> String {
        self.deploy()
            .health_check
            .as_ref()
            .map(|check| {
                format!(
                    " Health check (inside the container): {}.",
                    check.command.chars().take(200).collect::<String>()
                )
            })
            .unwrap_or_default()
    }

    /// The container of the entry exists but does not run.
    fn exited(&self, container: &ContainerObservation) -> bool {
        let one_time = self.deploy().restart_policy == "no";
        if one_time && container.exit_code == Some(0) {
            self.update(|stored| stored.applied = true);
            self.status(
                WorkloadStatusValue::Healthy,
                "The one-time container finished.",
                &container.runtime_id,
                false,
            );
            return false;
        }
        if !self.stored.applied {
            if self.stored.failed {
                return false;
            }
            return self.fail(
                &format!(
                    "The application stopped right after the start{}. Check the logs of the application.",
                    container
                        .exit_code
                        .map(|code| format!(" with exit code {code}"))
                        .unwrap_or_default()
                ),
                Some(container),
            );
        }
        if one_time {
            return false;
        }
        // An applied container stopped: a crash that Podman did not restart,
        // a kill, or a reboot. Start it again with a backoff, also without a
        // connection.
        let autonomous = !self.stored.start_requested;
        let backoff = (START_BACKOFF_INITIAL_MILLIS << self.stored.start_attempts.min(16))
            .min(START_BACKOFF_MAX_MILLIS);
        if self.stored.start_attempts > 0 && self.now - self.stored.last_start_unix_ms < backoff {
            return true;
        }
        let now = self.now;
        self.update(|stored| {
            stored.start_attempts = stored.start_attempts.saturating_add(1);
            stored.last_start_unix_ms = now;
        });
        match self.runtime.lifecycle(&lifecycle(
            &container.name,
            WorkloadLifecycleAction::Start,
            None,
        )) {
            Ok(()) => self.status(
                WorkloadStatusValue::Progressing,
                if autonomous {
                    "The container stopped. Sentinel started it again."
                } else {
                    "Sentinel started the container."
                },
                &container.runtime_id,
                autonomous,
            ),
            Err(error) => self.status(
                WorkloadStatusValue::Failed,
                &format!("Sentinel could not start the container: {error}"),
                &container.runtime_id,
                autonomous,
            ),
        }
        true
    }

    /// No container of this revision exists in the slot of the entry.
    fn start_new(&self) -> bool {
        let older_runs = self.own.iter().any(|container| is_running(container));
        if self.stored.failed {
            // Like v4, a failed revision is not tried again while an older
            // container serves.
            if older_runs || self.now - self.stored.failed_at_unix_ms < FAILED_RETRY_MILLIS {
                return false;
            }
        }
        if !self.snapshot.confirmed {
            self.status(
                WorkloadStatusValue::Progressing,
                "Sentinel waits for Coolify before it deploys the revision.",
                "",
                false,
            );
            return false;
        }
        if self.network_revision < self.entry.network_revision {
            self.status(
                WorkloadStatusValue::Progressing,
                &format!(
                    "Sentinel waits for network revision {}.",
                    self.entry.network_revision
                ),
                "",
                false,
            );
            return true;
        }
        let Some(payload) = self.snapshot.payloads.get(&self.entry.workload_id) else {
            // The secret values and the registry login are only in the change
            // from Coolify. The reported hash makes Coolify send it again.
            self.update(|stored| stored.applied = false);
            self.status(
                WorkloadStatusValue::Progressing,
                "Sentinel waits for Coolify to send the revision again.",
                "",
                false,
            );
            return false;
        };
        let deploy = self.deploy();
        if !self.entry.replaces.is_empty()
            && let Some(leftover) = self.named(&deploy.name)
        {
            // A leftover of an earlier deploy can still get traffic, so it is
            // drained and removed before the new container takes its name.
            if let Err(error) = self.runtime.lifecycle(&lifecycle(
                &leftover.name,
                WorkloadLifecycleAction::Remove,
                None,
            )) {
                return self.fail(&error, None);
            }
        }
        self.status(
            WorkloadStatusValue::Progressing,
            "Sentinel deploys the revision.",
            "",
            false,
        );
        match self.runtime.deploy(payload) {
            Ok(runtime_id) => {
                self.update(|stored| {
                    stored.applied = false;
                    stored.failed = false;
                    stored.redeploy_pending = false;
                });
                self.status(
                    WorkloadStatusValue::Progressing,
                    "Sentinel started the new container and waits until it is healthy.",
                    &runtime_id,
                    false,
                );
                true
            }
            Err(error) => self.fail(&error, None),
        }
    }

    /// Fails the revision. The new container of a rolling deploy is removed
    /// when the old one still runs.
    fn fail(&self, reason: &str, container: Option<&ContainerObservation>) -> bool {
        let replaced_runs = !self.entry.replaces.is_empty()
            && self.named(&self.entry.replaces).is_some_and(is_running);
        let mut reason = reason.to_string();
        if let Some(container) = container
            && replaced_runs
            && self.snapshot.confirmed
        {
            match self.runtime.lifecycle(&lifecycle(
                &container.name,
                WorkloadLifecycleAction::Remove,
                None,
            )) {
                Ok(()) => reason.push_str(" The previous version keeps running."),
                Err(error) => {
                    tracing::warn!(%error, container = %container.name, "Sentinel could not remove the new container of a failed revision");
                }
            }
        } else if replaced_runs {
            reason.push_str(" The previous version keeps running.");
        }
        let now = self.now;
        self.update(|stored| {
            stored.failed = true;
            stored.applied = false;
            stored.failed_at_unix_ms = now;
        });
        self.status(
            WorkloadStatusValue::Failed,
            &reason,
            container.map_or("", |container| container.runtime_id.as_str()),
            false,
        );
        false
    }

    /// Removes the container that a rolling deploy replaced. A failure leaves
    /// it: the next pass tries again. A published port first points to the
    /// new container, in one nftables change (decision 0037 of Coolify).
    fn retire_replaced(&self) {
        if self.entry.replaces.is_empty() {
            return;
        }
        let Some(replaced) = self.named(&self.entry.replaces) else {
            return;
        };
        if !self.entry.published_ports.is_empty()
            && let Err(error) = self
                .runtime
                .local_ports(&local_ports(&self.set.snapshot(), self.containers))
        {
            tracing::warn!(%error, container = %replaced.name, "Sentinel keeps the replaced container, because the published ports could not switch to the new one");
            return;
        }
        if let Err(error) = self.runtime.lifecycle(&lifecycle(
            &replaced.name,
            WorkloadLifecycleAction::Remove,
            self.entry.stop_timeout_seconds,
        )) {
            tracing::warn!(%error, container = %replaced.name, "Sentinel could not remove the replaced container");
        }
    }
}

/// The time that the health check may take: the start period and every
/// retry, as Coolify waits for a deploy of the command path.
pub(crate) fn health_wait_millis(deploy: &WorkloadDeployRequest) -> i64 {
    let Some(check) = &deploy.health_check else {
        return MAX_HEALTH_WAIT_MILLIS;
    };
    let seconds = i64::from(check.start_period_seconds)
        + (i64::from(check.interval_seconds) + i64::from(check.timeout_seconds))
            * i64::from(check.retries)
        + 30;
    (seconds * 1_000).clamp(SETTLE_MILLIS, MAX_HEALTH_WAIT_MILLIS)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    use sentinel_protocol::control::v1::{
        WorkloadLabel, WorkloadReconcileRequest, WorkloadSecret, WorkloadStatus,
    };

    use super::*;
    use crate::workload_set::set_hash;

    #[derive(Default)]
    struct FakeRuntime {
        containers: RefCell<Vec<ContainerObservation>>,
        actions: RefCell<Vec<String>>,
        network_revision: u64,
        now: std::cell::Cell<i64>,
        deploy_restarts: u32,
    }

    impl FakeRuntime {
        fn add(&self, name: &str, workload: &str, revision: &str, state: &str, started: i64) {
            self.containers.borrow_mut().push(ContainerObservation {
                runtime_id: format!("id-{name}"),
                name: name.into(),
                image: "nginx:alpine".into(),
                state: state.into(),
                labels: HashMap::from([
                    ("coolify.workload".into(), workload.into()),
                    ("coolify.revision".into(), revision.into()),
                ]),
                started_at_unix_ms: Some(started),
                restart_count: Some(0),
                ..Default::default()
            });
        }

        fn names(&self) -> Vec<String> {
            self.containers
                .borrow()
                .iter()
                .map(|container| format!("{}:{}", container.name, container.state))
                .collect()
        }
    }

    impl Runtime for FakeRuntime {
        fn containers(&self) -> Result<Vec<ContainerObservation>, String> {
            Ok(self.containers.borrow().clone())
        }

        fn deploy(&self, request: &WorkloadDeployRequest) -> Result<String, String> {
            assert!(
                request
                    .secrets
                    .iter()
                    .all(|secret| !secret.value.is_empty()),
                "a deploy needs the secret values"
            );
            self.actions
                .borrow_mut()
                .push(format!("deploy {}", request.name));
            let revision = request
                .labels
                .iter()
                .find(|label| label.key == "coolify.revision")
                .unwrap()
                .value
                .clone();
            let workload = request
                .labels
                .iter()
                .find(|label| label.key == "coolify.workload")
                .unwrap()
                .value
                .clone();
            self.containers
                .borrow_mut()
                .retain(|container| container.name != request.name);
            self.add(
                &request.name,
                &workload,
                &revision,
                "running",
                self.now.get(),
            );
            if let Some(container) = self.containers.borrow_mut().last_mut() {
                container.restart_count = Some(self.deploy_restarts);
            }
            Ok(format!("id-{}", request.name))
        }

        fn lifecycle(&self, request: &WorkloadLifecycleRequest) -> Result<(), String> {
            let action = WorkloadLifecycleAction::try_from(request.action).unwrap();
            self.actions
                .borrow_mut()
                .push(format!("{action:?} {}", request.name).to_lowercase());
            let mut containers = self.containers.borrow_mut();
            match action {
                WorkloadLifecycleAction::Remove => {
                    containers.retain(|container| container.name != request.name)
                }
                WorkloadLifecycleAction::Stop => containers
                    .iter_mut()
                    .filter(|container| container.name == request.name)
                    .for_each(|container| container.state = "exited".into()),
                WorkloadLifecycleAction::Start => containers
                    .iter_mut()
                    .filter(|container| container.name == request.name)
                    .for_each(|container| {
                        container.state = "running".into();
                        container.started_at_unix_ms = Some(self.now.get());
                    }),
                _ => {}
            }
            Ok(())
        }

        fn network_revision(&self) -> u64 {
            self.network_revision
        }

        fn local_ports(&self, _ports: &[LocalPort]) -> Result<(), String> {
            Ok(())
        }
    }

    fn entry(workload: &str, revision: &str, name: &str, replaces: &str) -> WorkloadSetEntry {
        WorkloadSetEntry {
            workload_id: workload.into(),
            revision_id: revision.into(),
            configuration_hash: "config".into(),
            desired_state: WorkloadDesiredState::Running as i32,
            network_revision: 0,
            deploy: Some(WorkloadDeployRequest {
                name: name.into(),
                image: "nginx:alpine".into(),
                restart_policy: "unless-stopped".into(),
                labels: vec![
                    WorkloadLabel {
                        key: "coolify.workload".into(),
                        value: workload.into(),
                    },
                    WorkloadLabel {
                        key: "coolify.revision".into(),
                        value: revision.into(),
                    },
                ],
                secrets: vec![WorkloadSecret {
                    key: "token".into(),
                    value: "secret-value".into(),
                    ..Default::default()
                }],
                registry_username: "user".into(),
                registry_password: "registry-secret".into(),
                ..Default::default()
            }),
            replaces: replaces.into(),
            operation_id: format!("operation-{revision}"),
            stop_timeout_seconds: None,
            entry_hash: format!("hash-{revision}"),
            redeploy: false,
            published_ports: vec![],
            replaces_container_ip: String::new(),
        }
    }

    fn change(
        generation: u64,
        full: bool,
        puts: Vec<WorkloadSetEntry>,
    ) -> WorkloadReconcileRequest {
        WorkloadReconcileRequest {
            generation,
            set_hash: set_hash(
                puts.iter()
                    .map(|put| (put.workload_id.as_str(), put.entry_hash.as_str())),
            ),
            full,
            puts,
            removes: vec![],
            releases: vec![],
        }
    }

    fn status_of(set: &WorkloadSet, workload: &str) -> WorkloadStatus {
        set.snapshot()
            .entries
            .into_iter()
            .find(|stored| stored.entry.as_ref().unwrap().workload_id == workload)
            .and_then(|stored| stored.status)
            .unwrap()
    }

    fn value(status: &WorkloadStatus) -> WorkloadStatusValue {
        WorkloadStatusValue::try_from(status.status).unwrap()
    }

    #[test]
    fn stores_the_set_without_secret_values_and_checks_the_generation() {
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let result = set
            .apply(change(3, true, vec![entry("w1", "r1", "coolify-w1", "")]))
            .unwrap();
        assert!(result.accepted);
        let path = root.path().join("var/lib/coolify/workloads/desired-set.pb");
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-value"));
        assert!(!String::from_utf8_lossy(&bytes).contains("registry-secret"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // An older generation changes nothing.
        let older = set
            .apply(change(2, true, vec![entry("w1", "r0", "coolify-w1", "")]))
            .unwrap();
        assert!(!older.accepted);
        assert_eq!(older.generation, 3);
        // The same generation with the same hash confirms the set.
        let mut confirm = change(3, false, vec![]);
        confirm.set_hash = result.set_hash.clone();
        assert!(set.apply(confirm).unwrap().accepted);
        // A change whose hash differs is applied, but Coolify must send the full set.
        let mut lost = change(4, false, vec![entry("w2", "r2", "coolify-w2", "")]);
        lost.set_hash = "0".repeat(64);
        assert!(!set.apply(lost).unwrap().accepted);

        // After a restart, the deploy values are gone: the reported hash differs.
        let reopened = WorkloadSet::open(root.path());
        let (generation, hash) = reopened.reported_state();
        assert_eq!(generation, 4);
        assert_ne!(hash, set.reported_state().1);
    }

    #[test]
    fn stores_the_runtime_options_v2_and_converges_a_change_again() {
        use sentinel_protocol::control::v1::{WorkloadHost, WorkloadSysctl};

        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let with_options = |revision: &str, somaxconn: &str| {
            let mut put = entry("w1", revision, "coolify-w1", "");
            put.entry_hash = format!("hash-{revision}-{somaxconn}");
            let deploy = put.deploy.as_mut().unwrap();
            deploy.user_labels = vec![WorkloadLabel {
                key: "com.example/app".into(),
                value: "web".into(),
            }];
            deploy.init = true;
            deploy.read_only = true;
            deploy.pids_limit = Some(512);
            deploy.hostname = "web".into();
            deploy.entrypoint = vec!["tini".into(), "--".into()];
            deploy.extra_hosts = vec![WorkloadHost {
                name: "db".into(),
                ip: "192.0.2.1".into(),
            }];
            deploy.cap_add = vec!["NET_ADMIN".into()];
            deploy.cap_drop = vec!["ALL".into()];
            deploy.no_new_privileges = true;
            deploy.sysctls = vec![WorkloadSysctl {
                name: "net.core.somaxconn".into(),
                value: somaxconn.into(),
            }];
            put
        };
        let first = set
            .apply(change(1, true, vec![with_options("r1", "1024")]))
            .unwrap();
        assert!(first.accepted);
        let runtime = FakeRuntime::default();
        runtime.now.set(now);
        converge_once(&set, &runtime, now);
        assert_eq!(*runtime.actions.borrow(), ["deploy coolify-w1"]);

        // The stored entry keeps every field, also after a restart.
        let reopened = WorkloadSet::open(root.path());
        let stored = reopened.snapshot().entries[0]
            .entry
            .clone()
            .unwrap()
            .deploy
            .unwrap();
        let sent = with_options("r1", "1024").deploy.unwrap();
        assert_eq!(stored.user_labels, sent.user_labels);
        assert_eq!(stored.entrypoint, sent.entrypoint);
        assert_eq!(stored.extra_hosts, sent.extra_hosts);
        assert_eq!(stored.cap_add, sent.cap_add);
        assert_eq!(stored.cap_drop, sent.cap_drop);
        assert_eq!(stored.sysctls, sent.sysctls);
        assert_eq!(
            (stored.init, stored.read_only, stored.no_new_privileges),
            (true, true, true)
        );
        assert_eq!(stored.pids_limit, Some(512));
        assert_eq!(stored.hostname, "web");

        // A changed option is a new revision with a new entry hash: the set
        // hash changes and the container is deployed again.
        let second = set
            .apply(change(2, true, vec![with_options("r2", "4096")]))
            .unwrap();
        assert!(second.accepted);
        assert_ne!(first.set_hash, second.set_hash);
        converge_once(&set, &runtime, now + 1_000);
        assert_eq!(
            *runtime.actions.borrow(),
            ["deploy coolify-w1", "deploy coolify-w1"]
        );
        let stored = set.snapshot().entries[0]
            .entry
            .clone()
            .unwrap()
            .deploy
            .unwrap();
        assert_eq!(stored.sysctls[0].value, "4096");
    }

    #[test]
    fn an_older_stored_entry_without_the_new_fields_still_parses() {
        use prost::Message;

        let older = entry("w1", "r1", "coolify-w1", "");
        let decoded = WorkloadSetEntry::decode(older.encode_to_vec().as_slice()).unwrap();
        let deploy = decoded.deploy.unwrap();
        assert!(deploy.cdi_devices.is_empty() && deploy.cap_add.is_empty());
        assert_eq!(deploy.pids_limit, None);
        assert!(!deploy.init);
    }

    #[test]
    fn deploys_only_after_coolify_confirmed_the_generation() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        set.apply(change(1, true, vec![entry("w1", "r1", "coolify-w1", "")]))
            .unwrap();
        set.connection_changed();
        let runtime = FakeRuntime::default();
        runtime.now.set(now);
        converge_once(&set, &runtime, now);
        assert!(runtime.actions.borrow().is_empty());
        assert_eq!(
            value(&status_of(&set, "w1")),
            WorkloadStatusValue::Progressing
        );

        let mut confirm = change(1, false, vec![]);
        confirm.set_hash = set.reported_state().1;
        assert!(set.apply(confirm).unwrap().accepted);
        converge_once(&set, &runtime, now);
        assert_eq!(*runtime.actions.borrow(), ["deploy coolify-w1"]);
    }

    #[test]
    fn a_rolling_deploy_removes_the_old_container_after_the_new_one_is_healthy() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let runtime = FakeRuntime::default();
        runtime.now.set(now);
        runtime.add("coolify-w1", "w1", "r1", "running", now - 600_000);
        set.apply(change(
            1,
            true,
            vec![entry("w1", "r2", "coolify-w1-blue", "coolify-w1")],
        ))
        .unwrap();
        assert!(converge_once(&set, &runtime, now));
        assert_eq!(*runtime.actions.borrow(), ["deploy coolify-w1-blue"]);
        // Not settled yet: both run.
        assert!(converge_once(&set, &runtime, now + 5_000));
        assert_eq!(runtime.names().len(), 2);
        assert!(!converge_once(&set, &runtime, now + SETTLE_MILLIS));
        assert_eq!(runtime.names(), ["coolify-w1-blue:running"]);
        assert_eq!(value(&status_of(&set, "w1")), WorkloadStatusValue::Healthy);
        assert!(!set.unreported().is_empty());
    }

    #[test]
    fn a_crash_looping_revision_fails_and_the_old_container_keeps_running() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let runtime = FakeRuntime {
            deploy_restarts: 1,
            ..Default::default()
        };
        runtime.now.set(now);
        runtime.add("coolify-w1", "w1", "r1", "running", now - 600_000);
        set.apply(change(
            1,
            true,
            vec![entry("w1", "r2", "coolify-w1-blue", "coolify-w1")],
        ))
        .unwrap();
        converge_once(&set, &runtime, now);
        converge_once(&set, &runtime, now + 2_000);
        let status = status_of(&set, "w1");
        assert_eq!(value(&status), WorkloadStatusValue::Failed);
        assert!(
            status
                .reason
                .contains("The previous version keeps running.")
        );
        assert_eq!(runtime.names(), ["coolify-w1:running"]);
        // Not retried while the old container runs, also after the backoff.
        converge_once(&set, &runtime, now + FAILED_RETRY_MILLIS * 2);
        assert_eq!(
            *runtime.actions.borrow(),
            ["deploy coolify-w1-blue", "remove coolify-w1-blue"]
        );
    }

    #[test]
    fn waits_for_the_network_revision_of_the_entry() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let mut waiting = entry("w1", "r1", "coolify-w1", "");
        waiting.network_revision = 8;
        set.apply(change(1, true, vec![waiting])).unwrap();
        let runtime = FakeRuntime {
            network_revision: 7,
            ..Default::default()
        };
        assert!(converge_once(&set, &runtime, now));
        assert!(runtime.actions.borrow().is_empty());
        assert!(status_of(&set, "w1").reason.contains("network revision 8"));
    }

    #[test]
    fn starts_a_stopped_container_of_the_set_without_a_connection_with_a_backoff() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let runtime = FakeRuntime::default();
        runtime.now.set(now);
        runtime.add("coolify-w1", "w1", "r1", "running", now - 600_000);
        set.apply(change(1, true, vec![entry("w1", "r1", "coolify-w1", "")]))
            .unwrap();
        // The running container is older than the entry: adopted.
        converge_once(&set, &runtime, now);
        assert_eq!(value(&status_of(&set, "w1")), WorkloadStatusValue::Healthy);

        set.connection_changed();
        runtime.containers.borrow_mut()[0].state = "exited".into();
        converge_once(&set, &runtime, now + 1_000);
        assert_eq!(*runtime.actions.borrow(), ["start coolify-w1"]);
        let status = status_of(&set, "w1");
        assert!(status.autonomous);
        runtime.containers.borrow_mut()[0].state = "exited".into();
        converge_once(&set, &runtime, now + 2_000);
        assert_eq!(runtime.actions.borrow().len(), 1, "the backoff waits");
        converge_once(
            &set,
            &runtime,
            now + 1_000 + START_BACKOFF_INITIAL_MILLIS * 2,
        );
        assert_eq!(runtime.actions.borrow().len(), 2);
    }

    #[test]
    fn removes_the_containers_of_a_removed_workload_and_reports_it() {
        // Later than the entries that the test puts.
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let runtime = FakeRuntime::default();
        runtime.add("coolify-w1", "w1", "r1", "running", now - 600_000);
        set.apply(change(1, true, vec![entry("w1", "r1", "coolify-w1", "")]))
            .unwrap();
        set.apply(change(2, true, vec![])).unwrap();
        converge_once(&set, &runtime, now);
        assert!(runtime.names().is_empty());
        let removed = set.unreported();
        assert_eq!(removed.len(), 1);
        assert_eq!(value(&removed[0]), WorkloadStatusValue::Removed);
        set.acknowledge(&removed[0].event_id);
        assert!(set.unreported().is_empty());
    }

    #[test]
    fn the_command_executor_applies_a_desired_set_change() {
        use sentinel_protocol::control::v1::command::Payload;
        use sentinel_protocol::control::v1::command_result;

        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let mut executor = CommandExecutor::new("dev").with_workload_set(set.clone());
        let execution = executor.execute(
            sentinel_protocol::control::v1::Command {
                command_id: "reconcile-1".into(),
                command_type: sentinel_protocol::CAPABILITY_WORKLOAD_RECONCILE.into(),
                payload_version: 1,
                created_at_unix_ms: 1,
                payload: Some(Payload::WorkloadReconcile(change(
                    1,
                    true,
                    vec![entry("w1", "r1", "coolify-w1", "")],
                ))),
                expires_at_unix_ms: i64::MAX,
            },
            true,
        );
        assert!(execution.accepted);
        assert!(matches!(
            execution.result.payload,
            Some(command_result::Payload::WorkloadReconcile(result)) if result.accepted && result.generation == 1
        ));
        assert_eq!(set.reported_state().0, 1);
    }

    #[test]
    fn does_not_start_a_container_that_a_backup_holds() {
        let now = now_millis() + 5_000;
        let root = tempfile::tempdir().unwrap();
        let set = WorkloadSet::open(root.path());
        let runtime = FakeRuntime::default();
        runtime.add("coolify-held", "held", "r1", "running", now - 600_000);
        set.apply(change(
            1,
            true,
            vec![entry("held", "r1", "coolify-held", "")],
        ))
        .unwrap();
        converge_once(&set, &runtime, now);
        runtime.containers.borrow_mut()[0].state = "exited".into();
        {
            let _hold = hold("coolify-held");
            assert!(converge_once(&set, &runtime, now + 1_000));
            assert!(runtime.actions.borrow().is_empty());
        }
        converge_once(&set, &runtime, now + 2_000);
        assert_eq!(*runtime.actions.borrow(), ["start coolify-held"]);
    }

    #[test]
    fn health_wait_covers_the_start_period_and_every_retry() {
        let mut deploy = entry("w1", "r1", "coolify-w1", "").deploy.unwrap();
        assert_eq!(health_wait_millis(&deploy), MAX_HEALTH_WAIT_MILLIS);
        deploy.health_check = Some(sentinel_protocol::control::v1::WorkloadHealthCheck {
            command: "true".into(),
            interval_seconds: 5,
            timeout_seconds: 5,
            retries: 3,
            start_period_seconds: 10,
        });
        assert_eq!(health_wait_millis(&deploy), 70_000);
    }
}
