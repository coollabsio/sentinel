//! The desired set of the workloads of this Node (decision 0026 of Coolify).
//!
//! Coolify sends one change for each workload, or the full set, through
//! `workload.reconcile.v1`. The set is stored at
//! `/var/lib/coolify/workloads/desired-set.pb` (0600) without secret values
//! and registry logins: those stay in memory for the deploy of the change
//! that carried them. `crate::convergence` converges the containers to the
//! set and records the status of each workload here.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use prost::Message;
use sentinel_protocol::control::v1::{
    StoredWorkloadEntry, StoredWorkloadSet, WorkloadDeployRequest, WorkloadDesiredState,
    WorkloadReconcileRequest, WorkloadReconcileResult, WorkloadSetEntry, WorkloadStatus,
    WorkloadStatusValue,
};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

const SET_FILE: &str = "var/lib/coolify/workloads/desired-set.pb";
const MAX_ENTRIES: usize = 1_000;

/// The desired set, shared by the command lanes, the connection, and the
/// converger.
#[derive(Clone)]
pub(crate) struct WorkloadSet {
    inner: Arc<Mutex<Inner>>,
    changed: Arc<Notify>,
    status_changed: Arc<Notify>,
}

struct Inner {
    path: PathBuf,
    stored: StoredWorkloadSet,
    /// The deploys of the received changes with their secret values and
    /// registry logins. Never on disk.
    payloads: HashMap<String, WorkloadDeployRequest>,
    /// Coolify confirmed the stored generation on the current connection.
    confirmed: bool,
    sequence: u64,
}

/// The set hash: SHA-256 (hex) of the lines `<workload_id> <entry_hash>\n`,
/// sorted by workload ID. Coolify computes the same hash.
pub(crate) fn set_hash<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let sorted: BTreeMap<&str, &str> = entries.into_iter().collect();
    let mut digest = Sha256::new();
    for (workload_id, entry_hash) in sorted {
        digest.update(workload_id.as_bytes());
        digest.update(b" ");
        digest.update(entry_hash.as_bytes());
        digest.update(b"\n");
    }
    format!("{:x}", digest.finalize())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
}

/// The deploy as it is stored: without secret values and the registry login.
pub(crate) fn stored_deploy(deploy: &WorkloadDeployRequest) -> WorkloadDeployRequest {
    let mut stored = deploy.clone();
    for secret in &mut stored.secrets {
        secret.value.clear();
    }
    stored.registry_username.clear();
    stored.registry_password.clear();
    stored
}

fn validate_entry(entry: &WorkloadSetEntry) -> Result<(), String> {
    let Some(deploy) = &entry.deploy else {
        return Err("A desired set entry has no container.".into());
    };
    if !valid_id(&entry.workload_id)
        || !valid_id(&entry.revision_id)
        || (!entry.operation_id.is_empty() && !valid_id(&entry.operation_id))
        || entry.entry_hash.is_empty()
        || entry.entry_hash.len() > 128
        || !crate::commands::valid_container_name(&deploy.name)
        || (!entry.replaces.is_empty()
            && (!crate::commands::valid_container_name(&entry.replaces)
                || entry.replaces == deploy.name))
        || !matches!(
            WorkloadDesiredState::try_from(entry.desired_state),
            Ok(WorkloadDesiredState::Running | WorkloadDesiredState::Stopped)
        )
        || entry
            .stop_timeout_seconds
            .is_some_and(|seconds| !(1..=600).contains(&seconds))
    {
        return Err(format!(
            "The desired set entry of workload {} is invalid.",
            entry.workload_id
        ));
    }
    // The labels tie each container to its entry; the converger finds the
    // containers of a workload by them.
    let label = |key: &str| {
        deploy
            .labels
            .iter()
            .find(|label| label.key == key)
            .map(|label| label.value.as_str())
    };
    if label("coolify.workload") != Some(entry.workload_id.as_str())
        || label("coolify.revision") != Some(entry.revision_id.as_str())
    {
        return Err(format!(
            "The container of workload {} needs its workload and revision labels.",
            entry.workload_id
        ));
    }
    crate::commands::podman_deploy_args(Path::new("/"), deploy).map(|_| ())
}

pub(crate) fn validate(request: &WorkloadReconcileRequest) -> Result<(), String> {
    if request.generation == 0
        || request.set_hash.len() != 64
        || request.puts.len() + request.removes.len() + request.releases.len() > MAX_ENTRIES
    {
        return Err("The desired set change is invalid.".into());
    }
    let mut seen = HashSet::new();
    for entry in &request.puts {
        validate_entry(entry)?;
        if !seen.insert(entry.workload_id.as_str()) {
            return Err("A workload is two times in the desired set change.".into());
        }
    }
    for id in request.removes.iter().chain(&request.releases) {
        if !valid_id(id) || !seen.insert(id.as_str()) {
            return Err("A removed workload ID is invalid.".into());
        }
    }
    let mut names = HashSet::new();
    for entry in &request.puts {
        let name = entry.deploy.as_ref().map(|deploy| deploy.name.as_str());
        if !names.insert(name) {
            return Err("Two workloads of the desired set use the same container.".into());
        }
    }
    Ok(())
}

impl WorkloadSet {
    pub(crate) fn open(root: &Path) -> Self {
        let path = root.join(SET_FILE);
        let stored = std::fs::read(&path)
            .ok()
            .and_then(|bytes| StoredWorkloadSet::decode(bytes.as_slice()).ok())
            .unwrap_or_default();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                path,
                stored,
                payloads: HashMap::new(),
                confirmed: false,
                sequence: 0,
            })),
            changed: Arc::new(Notify::new()),
            status_changed: Arc::new(Notify::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn changed(&self) -> Arc<Notify> {
        self.changed.clone()
    }

    pub(crate) fn status_changed(&self) -> Arc<Notify> {
        self.status_changed.clone()
    }

    /// The generation and the hash for `Hello` and `Heartbeat`. An entry
    /// whose deploy needs a value that is not in memory (a secret, the
    /// registry login) counts with an empty entry hash, so Coolify sees a
    /// difference and sends the full set again.
    pub(crate) fn reported_state(&self) -> (u64, String) {
        let inner = self.lock();
        if inner.stored.generation == 0 {
            return (0, String::new());
        }
        let missing: HashSet<&str> = inner
            .stored
            .entries
            .iter()
            .filter(|stored| needs_payload(stored, &inner.payloads))
            .filter_map(|stored| {
                stored
                    .entry
                    .as_ref()
                    .map(|entry| entry.workload_id.as_str())
            })
            .collect();
        let hash = set_hash(inner.stored.entries.iter().filter_map(|stored| {
            let entry = stored.entry.as_ref()?;
            let entry_hash = if missing.contains(entry.workload_id.as_str()) {
                ""
            } else {
                entry.entry_hash.as_str()
            };
            Some((entry.workload_id.as_str(), entry_hash))
        }));
        (inner.stored.generation, hash)
    }

    /// A new connection must get the generation from Coolify again before
    /// Sentinel deploys or removes anything.
    pub(crate) fn connection_changed(&self) {
        self.lock().confirmed = false;
    }

    pub(crate) fn apply(
        &self,
        request: WorkloadReconcileRequest,
    ) -> Result<WorkloadReconcileResult, String> {
        validate(&request)?;
        let mut inner = self.lock();
        let accepted = if request.generation < inner.stored.generation {
            false
        } else if request.generation == inner.stored.generation {
            // The same generation only confirms the set.
            request.puts.is_empty()
                && request.removes.is_empty()
                && request.releases.is_empty()
                && request.set_hash == inner.stored.set_hash
        } else {
            inner.replace(request)?
        };
        if accepted {
            inner.confirmed = true;
            self.changed.notify_one();
        }
        Ok(WorkloadReconcileResult {
            generation: inner.stored.generation,
            set_hash: inner.stored.set_hash.clone(),
            accepted,
            statuses: inner
                .stored
                .entries
                .iter()
                .filter_map(|stored| stored.status.clone())
                .collect(),
        })
    }

    /// A copy of the stored entries and of the deploys in memory.
    pub(crate) fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        Snapshot {
            confirmed: inner.confirmed,
            entries: inner.stored.entries.clone(),
            payloads: inner.payloads.clone(),
            removing: inner.stored.removing.clone(),
        }
    }

    /// Changes the stored state of one entry, when it still has the same
    /// revision and container. Returns false for an entry that changed in
    /// between.
    pub(crate) fn update_entry(
        &self,
        workload_id: &str,
        revision_id: &str,
        name: &str,
        update: impl FnOnce(&mut StoredWorkloadEntry),
    ) -> bool {
        let mut inner = self.lock();
        let Some(stored) = inner.stored.entries.iter_mut().find(|stored| {
            stored.entry.as_ref().is_some_and(|entry| {
                entry.workload_id == workload_id
                    && entry.revision_id == revision_id
                    && entry.deploy.as_ref().map(|deploy| deploy.name.as_str()) == Some(name)
            })
        }) else {
            return false;
        };
        update(stored);
        inner.persist();
        true
    }

    /// Records a new status of an entry and queues its event. A status that
    /// equals the current one (with the same reason) is not sent again.
    pub(crate) fn set_status(
        &self,
        entry: &WorkloadSetEntry,
        status: WorkloadStatusValue,
        reason: &str,
        runtime_id: &str,
        autonomous: bool,
    ) {
        let mut inner = self.lock();
        let generation = inner.stored.generation;
        inner.sequence += 1;
        let sequence = inner.sequence;
        let Some(stored) = inner.stored.entries.iter_mut().find(|stored| {
            stored.entry.as_ref().is_some_and(|stored| {
                stored.workload_id == entry.workload_id && stored.revision_id == entry.revision_id
            })
        }) else {
            return;
        };
        if stored.status.as_ref().is_some_and(|current| {
            current.status == status as i32
                && current.reason == reason
                && current.operation_id == entry.operation_id
        }) {
            return;
        }
        let now = now_millis();
        stored.status = Some(WorkloadStatus {
            event_id: format!("workload-{}-{now}-{sequence}", entry.workload_id),
            workload_id: entry.workload_id.clone(),
            revision_id: entry.revision_id.clone(),
            operation_id: entry.operation_id.clone(),
            status: status as i32,
            reason: reason.chars().take(2_000).collect(),
            generation,
            observed_at_unix_ms: now,
            container_name: entry
                .deploy
                .as_ref()
                .map(|deploy| deploy.name.clone())
                .unwrap_or_default(),
            runtime_id: runtime_id.into(),
            autonomous,
        });
        stored.unreported = true;
        inner.persist();
        self.status_changed.notify_one();
    }

    /// Forgets a workload that Coolify removed from the set, after its
    /// containers are gone, and queues its `removed` status.
    pub(crate) fn finish_removal(&self, workload_id: &str) {
        let mut inner = self.lock();
        inner.stored.removing.retain(|id| id != workload_id);
        inner.sequence += 1;
        let now = now_millis();
        let status = WorkloadStatus {
            event_id: format!("workload-{workload_id}-{now}-{}", inner.sequence),
            workload_id: workload_id.into(),
            status: WorkloadStatusValue::Removed as i32,
            generation: inner.stored.generation,
            observed_at_unix_ms: now,
            ..Default::default()
        };
        inner
            .stored
            .removed_statuses
            .retain(|stored| stored.workload_id != workload_id);
        inner.stored.removed_statuses.push(status);
        inner.persist();
        self.status_changed.notify_one();
    }

    /// The statuses that Coolify did not acknowledge yet.
    pub(crate) fn unreported(&self) -> Vec<WorkloadStatus> {
        let inner = self.lock();
        inner
            .stored
            .entries
            .iter()
            .filter(|stored| stored.unreported)
            .filter_map(|stored| stored.status.clone())
            .chain(inner.stored.removed_statuses.iter().cloned())
            .collect()
    }

    pub(crate) fn acknowledge(&self, event_id: &str) {
        let mut inner = self.lock();
        let mut changed = false;
        for stored in &mut inner.stored.entries {
            if stored.unreported
                && stored
                    .status
                    .as_ref()
                    .is_some_and(|status| status.event_id == event_id)
            {
                stored.unreported = false;
                changed = true;
            }
        }
        let removed = inner.stored.removed_statuses.len();
        inner
            .stored
            .removed_statuses
            .retain(|status| status.event_id != event_id);
        if changed || removed != inner.stored.removed_statuses.len() {
            inner.persist();
        }
    }

    /// The images of the stored set. The image cleanup keeps them (decision
    /// 0027 of Coolify).
    pub(crate) fn images(&self) -> Vec<String> {
        self.lock()
            .stored
            .entries
            .iter()
            .filter_map(|stored| stored.entry.as_ref()?.deploy.as_ref())
            .map(|deploy| deploy.image.clone())
            .collect()
    }
}

/// An entry that must start a new container, but its deploy is not in
/// memory. The stored deploy has no secret values and no registry login, so
/// Sentinel waits for Coolify to send the entry again.
fn needs_payload(
    stored: &StoredWorkloadEntry,
    payloads: &HashMap<String, WorkloadDeployRequest>,
) -> bool {
    stored.entry.as_ref().is_some_and(|entry| {
        !stored.applied
            && !stored.failed
            && entry.desired_state == WorkloadDesiredState::Running as i32
            && !payloads.contains_key(&entry.workload_id)
    })
}

pub(crate) struct Snapshot {
    pub(crate) confirmed: bool,
    pub(crate) entries: Vec<StoredWorkloadEntry>,
    pub(crate) payloads: HashMap<String, WorkloadDeployRequest>,
    pub(crate) removing: Vec<String>,
}

impl Inner {
    /// Applies a change with a newer generation. True when the set hash after
    /// the change is the hash that Coolify computed.
    fn replace(&mut self, request: WorkloadReconcileRequest) -> Result<bool, String> {
        let mut entries: BTreeMap<String, StoredWorkloadEntry> = self
            .stored
            .entries
            .drain(..)
            .filter_map(|stored| Some((stored.entry.as_ref()?.workload_id.clone(), stored)))
            .collect();
        let mut removing: Vec<String> = std::mem::take(&mut self.stored.removing);
        let put_ids: HashSet<String> = request
            .puts
            .iter()
            .map(|entry| entry.workload_id.clone())
            .collect();
        let mut removed: Vec<String> = request.removes.clone();
        if request.full {
            removed.extend(
                entries
                    .keys()
                    .filter(|id| !put_ids.contains(*id) && !request.releases.contains(id))
                    .cloned(),
            );
        }
        for id in &request.releases {
            entries.remove(id);
            self.payloads.remove(id);
        }
        for id in removed {
            entries.remove(&id);
            self.payloads.remove(&id);
            if !removing.contains(&id) {
                removing.push(id);
            }
        }
        for mut entry in request.puts {
            let Some(deploy) = entry.deploy.take() else {
                continue;
            };
            removing.retain(|id| id != &entry.workload_id);
            let previous = entries.remove(&entry.workload_id);
            let same_container = previous.as_ref().is_some_and(|previous| {
                previous.entry.as_ref().is_some_and(|stored| {
                    stored.revision_id == entry.revision_id
                        && stored.deploy.as_ref().map(|deploy| deploy.name.as_str())
                            == Some(deploy.name.as_str())
                })
            });
            entry.deploy = Some(stored_deploy(&deploy));
            self.payloads.insert(entry.workload_id.clone(), deploy);
            let now = now_millis();
            let stored = match previous {
                // The same container with a new desired state or operation:
                // keep what Sentinel knows about it.
                Some(mut previous) if same_container => {
                    let (operation_changed, started) = previous
                        .entry
                        .as_ref()
                        .map(|stored| {
                            (
                                stored.operation_id != entry.operation_id,
                                stored.desired_state != entry.desired_state
                                    && entry.desired_state == WorkloadDesiredState::Running as i32,
                            )
                        })
                        .unwrap_or_default();
                    if operation_changed {
                        // A new operation of the same revision tries it again.
                        previous.failed = false;
                        previous.start_attempts = 0;
                        if entry.redeploy
                            && entry.desired_state == WorkloadDesiredState::Running as i32
                        {
                            previous.redeploy_pending = true;
                            previous.applied = false;
                            previous.put_at_unix_ms = now;
                        }
                    }
                    if started {
                        previous.start_requested = true;
                        previous.start_attempts = 0;
                    }
                    previous.entry = Some(entry);
                    previous
                }
                _ => StoredWorkloadEntry {
                    entry: Some(entry),
                    put_at_unix_ms: now,
                    ..Default::default()
                },
            };
            entries.insert(stored.entry.as_ref().unwrap().workload_id.clone(), stored);
        }
        self.stored.entries = entries.into_values().collect();
        self.stored.removing = removing;
        self.stored.generation = request.generation;
        self.stored.set_hash = set_hash(self.stored.entries.iter().filter_map(|stored| {
            let entry = stored.entry.as_ref()?;
            Some((entry.workload_id.as_str(), entry.entry_hash.as_str()))
        }));
        self.persist_or_err()?;
        Ok(self.stored.set_hash == request.set_hash)
    }

    fn persist_or_err(&self) -> Result<(), String> {
        crate::network::atomic_write(&self.path, &self.stored.encode_to_vec(), 0o600)
    }

    fn persist(&self) {
        if let Err(error) = self.persist_or_err() {
            tracing::warn!(%error, "could not store the desired workload set");
        }
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
