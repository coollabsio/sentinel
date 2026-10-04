//! One restore pass per boot that brings back the Node state Coolify already
//! approved: the cluster network (WireGuard, firewall, resolver, Corrosion and
//! discovery DNS) and the managed workloads that a reboot stopped.
//!
//! It reads only state that Sentinel keeps on disk, so it needs neither Coolify
//! nor Flux.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{Mutex, Notify};

use crate::network::{self, RestoreStep};

const BOOT_ID_FILE: &str = "boot-restore.boot-id";
const STOPPED_MARKER_DIR: &str = "var/lib/coolify/workloads/stopped";
const STOPPED_MARKER_SUFFIX: &str = ".stopped";
const MANAGED_LABEL: &str = "coolify.managed";
const RESTARTING_POLICIES: [&str; 2] = ["always", "unless-stopped"];
const ACTIVE_STATES: [&str; 5] = ["running", "paused", "restarting", "stopping", "removing"];
const MAX_CONTAINERS: usize = 10_000;
const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(5);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestoreReport {
    /// Every step succeeded or had nothing to do.
    pub(crate) complete: bool,
    pub(crate) started_containers: usize,
}

fn known_boot_id(boot_id: &str) -> bool {
    !boot_id.is_empty() && boot_id != "unknown"
}

fn boot_id_path(root: &Path) -> PathBuf {
    network::state_path(root, BOOT_ID_FILE)
}

/// Whether this boot still needs a restore pass. An unknown boot ID always
/// restores, since it cannot be told apart from the previous boot.
pub(crate) fn restore_due(root: &Path, boot_id: &str) -> bool {
    !known_boot_id(boot_id)
        || fs::read_to_string(boot_id_path(root)).map_or(true, |stored| stored.trim() != boot_id)
}

pub(crate) fn record_restored(root: &Path, boot_id: &str) -> Result<(), String> {
    if !known_boot_id(boot_id) {
        return Ok(());
    }
    network::atomic_write(
        &boot_id_path(root),
        format!("{boot_id}\n").as_bytes(),
        0o600,
    )
}

/// Durable "stopped on purpose" markers, keyed by container name.
///
/// Podman resets `State.StoppedByUser` on reboot, so it cannot tell a workload
/// Coolify stopped from one the reboot stopped. `workload.lifecycle.v1` and
/// `workload.deploy.v1` keep these markers instead. An operator's out-of-band
/// `podman stop` writes no marker, so it is not durable across a reboot: the
/// boot restore starts such a workload again.
fn stopped_marker_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    if !crate::commands::valid_container_name(name) {
        return Err("The container name is invalid.".into());
    }
    Ok(root
        .join(STOPPED_MARKER_DIR)
        .join(format!("{name}{STOPPED_MARKER_SUFFIX}")))
}

/// Records that `name` was stopped on purpose. Returns whether it already was.
pub(crate) fn mark_stopped(root: &Path, name: &str) -> Result<bool, String> {
    let path = stopped_marker_path(root, name)?;
    let existed = path.exists();
    network::atomic_write(&path, b"stopped\n", 0o600)
        .map_err(|_| "The workload stop marker could not be written.".to_string())?;
    Ok(existed)
}

pub(crate) fn clear_stopped(root: &Path, name: &str) -> Result<(), String> {
    match fs::remove_file(stopped_marker_path(root, name)?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("The workload stop marker could not be removed.".into()),
    }
}

pub(crate) fn stopped_markers(root: &Path) -> Result<HashSet<String>, String> {
    let entries = match fs::read_dir(root.join(STOPPED_MARKER_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(_) => return Err("The workload stop markers could not be read.".into()),
    };
    let mut markers = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|_| "The workload stop markers could not be read.")?;
        if let Some(name) = entry
            .file_name()
            .to_str()
            .and_then(|file| file.strip_suffix(STOPPED_MARKER_SUFFIX))
            .filter(|name| crate::commands::valid_container_name(name))
        {
            markers.insert(name.to_string());
        }
    }
    Ok(markers)
}

/// Runs the boot restore if this boot has not completed one yet. An incomplete
/// pass, for example when Podman or the network is not ready yet at boot, runs
/// again with backoff until it completes, so a Node recovers without Coolify.
pub(crate) async fn run<T: Send + 'static>(
    root: PathBuf,
    boot_id: String,
    command_lock: Arc<Mutex<T>>,
    discovery_trigger: Arc<Notify>,
) -> RestoreReport {
    run_until_complete(
        root,
        boot_id,
        command_lock,
        discovery_trigger,
        RETRY_INITIAL_DELAY,
        RETRY_MAX_DELAY,
    )
    .await
}

async fn run_until_complete<T: Send + 'static>(
    root: PathBuf,
    boot_id: String,
    command_lock: Arc<Mutex<T>>,
    discovery_trigger: Arc<Notify>,
    mut retry_delay: Duration,
    max_retry_delay: Duration,
) -> RestoreReport {
    if !restore_due(&root, &boot_id) {
        tracing::debug!("Node state was already restored during this boot");
        return RestoreReport {
            complete: true,
            started_containers: 0,
        };
    }
    loop {
        let report = run_pass(&root, &command_lock, &discovery_trigger).await;
        if report.complete {
            match record_restored(&root, &boot_id) {
                Ok(()) => tracing::info!(
                    started_containers = report.started_containers,
                    "Node boot restore completed"
                ),
                Err(error) => {
                    tracing::warn!(%error, "could not record the completed Node boot restore")
                }
            }
            return report;
        }
        tracing::warn!(
            started_containers = report.started_containers,
            retry_in_seconds = retry_delay.as_secs_f32(),
            "Node boot restore was incomplete; it runs again"
        );
        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_retry_delay);
    }
}

/// One restore pass. It holds `command_lock` (the command executor) for the
/// whole pass so it cannot race a cluster leave or a WireGuard, firewall or
/// Corrosion reconcile, and releases it between passes.
async fn run_pass<T: Send + 'static>(
    root: &Path,
    command_lock: &Arc<Mutex<T>>,
    discovery_trigger: &Notify,
) -> RestoreReport {
    let commands = command_lock.clone().lock_owned().await;
    let task_root = root.to_path_buf();
    let report = tokio::task::spawn_blocking(move || {
        let _commands = commands;
        restore_once(&task_root)
    })
    .await
    .unwrap_or_else(|_| {
        tracing::warn!("the Node boot restore task failed");
        RestoreReport::default()
    });
    if report.started_containers > 0 {
        discovery_trigger.notify_one();
    }
    report
}

pub(crate) fn restore_once(root: &Path) -> RestoreReport {
    let mut complete = true;
    let applied = network::read_applied_network(root);
    for problem in &applied.problems {
        tracing::warn!(error = %problem, "applied cluster network state could not be read");
        complete = false;
    }
    let plan = if applied.is_empty() {
        network::RestorePlan::default()
    } else {
        let live = network::observe_live_network(root, &applied);
        network::restore_plan(&applied, &live)
    };

    complete &= apply_steps(root, &plan.before_workloads);
    let started_containers = match restore_containers(root) {
        Ok((started, failed)) => {
            complete &= failed == 0;
            started
        }
        Err(error) => {
            tracing::warn!(%error, "could not restore the managed workloads");
            complete = false;
            0
        }
    };
    complete &= apply_steps(root, &plan.after_workloads);

    RestoreReport {
        complete,
        started_containers,
    }
}

fn apply_steps(root: &Path, steps: &[RestoreStep]) -> bool {
    let mut complete = true;
    for step in steps {
        if let Err(error) = network::apply_restore_step(root, step) {
            tracing::warn!(?step, %error, "a Node boot restore step failed");
            complete = false;
        }
    }
    complete
}

/// Starts every managed workload that a reboot stopped. Returns the started
/// and failed counts.
fn restore_containers(root: &Path) -> Result<(usize, usize), String> {
    if root != Path::new("/") {
        return Ok((0, 0));
    }
    // Read the markers first: if they are unreadable, start nothing.
    let stopped = stopped_markers(root)?;
    let listed = match Command::new("podman")
        .args(["ps", "--all", "--no-trunc", "--format", "json"])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(_) => return Err("Podman is unavailable.".into()),
    };
    if !listed.status.success() {
        return Err("Podman could not list containers.".into());
    }
    let containers =
        crate::commands::parse_podman_containers(&listed.stdout).map_err(str::to_string)?;
    let candidates = containers
        .iter()
        .filter(|container| {
            container.labels.get(MANAGED_LABEL).map(String::as_str) == Some("true")
                && !container.state.eq_ignore_ascii_case("running")
        })
        .map(|container| container.runtime_id.as_str())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok((0, 0));
    }
    let inspected = Command::new("podman")
        .args(["inspect", "--format", "json"])
        .args(&candidates)
        .output()
        .map_err(|_| "Podman is unavailable.".to_string())?;
    // A container removed after `ps` makes inspect exit non-zero while still
    // printing the others, so use any parseable output.
    let restartable = match restartable_containers(&inspected.stdout, &stopped) {
        Ok(restartable) => restartable,
        Err(_) if !inspected.status.success() => {
            return Err("Podman could not inspect the managed containers.".into());
        }
        Err(message) => return Err(message.into()),
    };

    let (mut started, mut failed) = (0, 0);
    for id in restartable {
        match Command::new("podman").args(["start", &id]).output() {
            Ok(output) if output.status.success() => {
                tracing::info!(container = %id, "restarted a managed workload after boot");
                started += 1;
            }
            Ok(output) => {
                let error = String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .chars()
                    .take(2_000)
                    .collect::<String>();
                tracing::warn!(container = %id, %error, "could not restart a managed workload after boot");
                failed += 1;
            }
            Err(_) => {
                tracing::warn!(container = %id, "could not restart a managed workload after boot; Podman is unavailable");
                failed += 1;
            }
        }
    }
    Ok((started, failed))
}

/// Selects the IDs of managed containers that a reboot left stopped, from
/// `podman inspect --format json` output. A container qualifies only when it
/// is not running, its restart policy is `always` or `unless-stopped`, its
/// name has no durable stop marker in `stopped`, and `State.StoppedByUser` is
/// not set. Podman clears that flag on reboot, but it still catches a
/// `podman stop` earlier in the same boot when only Sentinel restarted.
pub(crate) fn restartable_containers(
    output: &[u8],
    stopped: &HashSet<String>,
) -> Result<Vec<String>, &'static str> {
    let values: Vec<Value> =
        serde_json::from_slice(output).map_err(|_| "Podman returned invalid inspect data.")?;
    if values.len() > MAX_CONTAINERS {
        return Err("Podman returned too many containers.");
    }
    Ok(values
        .iter()
        .filter_map(|value| restartable_container(value, stopped))
        .collect())
}

fn restartable_container(value: &Value, stopped: &HashSet<String>) -> Option<String> {
    let id = value.get("Id").and_then(Value::as_str).filter(|id| {
        !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric())
    })?;
    // Without a name the stop marker cannot be checked, so never start it.
    let name = value
        .get("Name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())?;
    if stopped.contains(name.trim_start_matches('/')) {
        return None;
    }
    let labels = value.pointer("/Config/Labels")?;
    if labels.get(MANAGED_LABEL).and_then(Value::as_str) != Some("true") {
        return None;
    }
    let policy = value
        .pointer("/HostConfig/RestartPolicy/Name")
        .and_then(Value::as_str)?;
    if !RESTARTING_POLICIES.contains(&policy) {
        return None;
    }
    let state = value.get("State")?;
    if state.get("StoppedByUser").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    let running = state.get("Running").and_then(Value::as_bool);
    let status = state
        .get("Status")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);
    if running.is_none() && status.is_none() {
        return None;
    }
    let active = running == Some(true)
        || state.get("Paused").and_then(Value::as_bool) == Some(true)
        || status
            .as_deref()
            .is_some_and(|status| ACTIVE_STATES.contains(&status));
    (!active).then(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn container(id: &str, managed: Option<&str>, policy: Option<&str>, state: Value) -> Value {
        let mut labels = serde_json::Map::new();
        if let Some(managed) = managed {
            labels.insert(MANAGED_LABEL.into(), managed.into());
        }
        let mut value = json!({
            "Id": id,
            "Name": id,
            "Config": { "Labels": labels },
            "State": state,
        });
        if let Some(policy) = policy {
            value["HostConfig"] = json!({ "RestartPolicy": { "Name": policy } });
        }
        value
    }

    fn exited() -> Value {
        json!({ "Status": "exited", "Running": false, "StoppedByUser": false })
    }

    fn select(containers: Vec<Value>) -> Vec<String> {
        select_with_markers(containers, &[])
    }

    fn select_with_markers(containers: Vec<Value>, stopped: &[&str]) -> Vec<String> {
        let stopped = stopped.iter().map(|name| name.to_string()).collect();
        restartable_containers(&serde_json::to_vec(&containers).unwrap(), &stopped).unwrap()
    }

    #[test]
    fn selects_only_managed_reboot_stopped_containers_with_a_restarting_policy() {
        let selected = select(vec![
            container(
                "unlessstopped",
                Some("true"),
                Some("unless-stopped"),
                exited(),
            ),
            container("always", Some("true"), Some("always"), exited()),
            container(
                "running",
                Some("true"),
                Some("unless-stopped"),
                json!({ "Status": "running", "Running": true }),
            ),
            container(
                "paused",
                Some("true"),
                Some("unless-stopped"),
                json!({ "Status": "paused", "Running": false, "Paused": true }),
            ),
            container(
                "stoppedbyuser",
                Some("true"),
                Some("unless-stopped"),
                json!({ "Status": "exited", "Running": false, "StoppedByUser": true }),
            ),
            container("policyno", Some("true"), Some("no"), exited()),
            container(
                "policyonfailure",
                Some("true"),
                Some("on-failure"),
                exited(),
            ),
            container("policyempty", Some("true"), Some(""), exited()),
            container("unmanaged", None, Some("unless-stopped"), exited()),
            container("notmanaged", Some("false"), Some("always"), exited()),
        ]);

        assert_eq!(selected, vec!["unlessstopped", "always"]);
    }

    #[test]
    fn missing_fields_never_start_a_container_except_an_absent_stop_marker() {
        let selected = select(vec![
            // A reboot leaves StoppedByUser absent on some Podman versions.
            container(
                "nomarker",
                Some("true"),
                Some("unless-stopped"),
                json!({ "Status": "exited", "Running": false }),
            ),
            container(
                "statusonly",
                Some("true"),
                Some("unless-stopped"),
                json!({ "Status": "exited" }),
            ),
            container("nopolicy", Some("true"), None, exited()),
            container("nostate", Some("true"), Some("unless-stopped"), json!({})),
            json!({ "Id": "nolabels", "HostConfig": { "RestartPolicy": { "Name": "always" } }, "State": exited() }),
            json!({ "Config": { "Labels": { MANAGED_LABEL: "true" } }, "HostConfig": { "RestartPolicy": { "Name": "always" } }, "State": exited() }),
            container("--all", Some("true"), Some("always"), exited()),
        ]);

        assert_eq!(selected, vec!["nomarker", "statusonly"]);
        let nameless = json!({ "Id": "nameless", "Config": { "Labels": { MANAGED_LABEL: "true" } }, "HostConfig": { "RestartPolicy": { "Name": "always" } }, "State": exited() });
        let mut unnamed = nameless.clone();
        unnamed["Name"] = json!("");
        assert!(select(vec![nameless, unnamed]).is_empty());
        assert!(restartable_containers(b"not json", &HashSet::new()).is_err());
        assert!(
            restartable_containers(b"[]", &HashSet::new())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn selection_skips_containers_with_a_durable_stop_marker() {
        // After a reboot Podman reports StoppedByUser=false even for a
        // workload Coolify stopped; only the marker remembers it.
        let mut docker_style = container("web2", Some("true"), Some("always"), exited());
        docker_style["Name"] = json!("/web2");
        let selected = select_with_markers(
            vec![
                container("web1", Some("true"), Some("unless-stopped"), exited()),
                docker_style,
                container("web3", Some("true"), Some("unless-stopped"), exited()),
            ],
            &["web1", "web2"],
        );

        assert_eq!(selected, vec!["web3"]);
    }

    #[test]
    fn stop_markers_are_durable_private_and_keyed_by_valid_names() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        assert!(stopped_markers(root).unwrap().is_empty());
        assert!(!mark_stopped(root, "coolify-web").unwrap());
        assert!(mark_stopped(root, "coolify-web").unwrap());
        assert!(!mark_stopped(root, "api.v2").unwrap());
        let path = root.join(STOPPED_MARKER_DIR).join("coolify-web.stopped");
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
                & 0o777,
            0o600
        );
        // Leftover staging files and foreign files are not markers.
        fs::write(root.join(STOPPED_MARKER_DIR).join("other.stopped.tmp"), "").unwrap();
        fs::write(root.join(STOPPED_MARKER_DIR).join("README"), "").unwrap();
        assert_eq!(
            stopped_markers(root).unwrap(),
            HashSet::from(["coolify-web".to_string(), "api.v2".to_string()])
        );

        clear_stopped(root, "coolify-web").unwrap();
        clear_stopped(root, "coolify-web").unwrap();
        assert_eq!(
            stopped_markers(root).unwrap(),
            HashSet::from(["api.v2".to_string()])
        );

        for invalid in [
            "", ".", "..", "../etc", "a/b", "-web", ".hidden", "bad name",
        ] {
            assert!(mark_stopped(root, invalid).is_err(), "{invalid}");
            assert!(clear_stopped(root, invalid).is_err(), "{invalid}");
        }
        assert!(mark_stopped(root, &"a".repeat(129)).is_err());
        assert!(
            !root
                .join("var/lib/coolify/workloads/stopped.stopped")
                .exists()
        );
    }

    #[test]
    fn boot_restore_is_due_once_per_boot_id() {
        let temp = tempfile::tempdir().unwrap();

        assert!(restore_due(temp.path(), "boot-a"));
        record_restored(temp.path(), "boot-a").unwrap();
        assert!(!restore_due(temp.path(), "boot-a"));
        assert!(restore_due(temp.path(), "boot-b"));
        assert_eq!(
            fs::read_to_string(boot_id_path(temp.path())).unwrap(),
            "boot-a\n"
        );

        // An unreadable boot ID never suppresses a restore and is never recorded.
        record_restored(temp.path(), "unknown").unwrap();
        assert!(restore_due(temp.path(), "unknown"));
        assert!(restore_due(temp.path(), ""));
        assert_eq!(
            fs::read_to_string(boot_id_path(temp.path())).unwrap(),
            "boot-a\n"
        );
    }

    #[tokio::test]
    async fn restore_without_an_applied_network_completes_and_records_the_boot() {
        let temp = tempfile::tempdir().unwrap();
        let lock = Arc::new(Mutex::new(()));
        let trigger = Arc::new(Notify::new());

        let report = run(
            temp.path().to_path_buf(),
            "boot-a".into(),
            lock.clone(),
            trigger.clone(),
        )
        .await;

        assert_eq!(
            report,
            RestoreReport {
                complete: true,
                started_containers: 0
            }
        );
        assert!(!restore_due(temp.path(), "boot-a"));
        // No network state was created by the no-op pass.
        assert!(!temp.path().join("etc").exists());
        assert!(network::read_applied_network(temp.path()).is_empty());
    }

    #[tokio::test]
    async fn restore_waits_for_a_running_command_and_releases_the_lock() {
        let temp = tempfile::tempdir().unwrap();
        let lock = Arc::new(Mutex::new(()));
        let trigger = Arc::new(Notify::new());
        let command = lock.clone().lock_owned().await;

        let task = tokio::spawn(run(
            temp.path().to_path_buf(),
            "boot-a".into(),
            lock.clone(),
            trigger,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!task.is_finished());
        assert!(restore_due(temp.path(), "boot-a"));

        drop(command);
        let report = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(report.complete);
        assert!(lock.try_lock().is_ok());
    }

    #[tokio::test]
    async fn an_incomplete_restore_runs_again_without_a_sentinel_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        // An applied interface whose config has no address cannot be restored.
        fs::create_dir_all(network::state_path(&root, "")).unwrap();
        fs::write(network::state_path(&root, "coolify0.state"), "1\n").unwrap();
        let config_path = root.join("etc/wireguard/coolify0.conf");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "[Interface]\nListenPort = 51820\n").unwrap();
        assert!(!restore_once(&root).complete);
        let lock = Arc::new(Mutex::new(()));

        let task = tokio::spawn(run_until_complete(
            root.clone(),
            "boot-a".into(),
            lock.clone(),
            Arc::new(Notify::new()),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished());
        assert!(restore_due(&root, "boot-a"));
        // Commands still run between passes.
        drop(
            tokio::time::timeout(Duration::from_secs(1), lock.lock())
                .await
                .unwrap(),
        );

        fs::remove_file(&config_path).unwrap();
        let report = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(report.complete);
        assert!(!restore_due(&root, "boot-a"));
    }

    #[tokio::test]
    async fn restore_is_skipped_after_it_completed_for_this_boot() {
        let temp = tempfile::tempdir().unwrap();
        record_restored(temp.path(), "boot-a").unwrap();
        let lock = Arc::new(Mutex::new(()));
        // Holding the lock proves a completed boot never waits on commands.
        let _command = lock.clone().lock_owned().await;

        let report = tokio::time::timeout(
            Duration::from_secs(5),
            run(
                temp.path().to_path_buf(),
                "boot-a".into(),
                lock.clone(),
                Arc::new(Notify::new()),
            ),
        )
        .await
        .unwrap();

        assert!(report.complete);
    }
}
