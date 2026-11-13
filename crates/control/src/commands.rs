use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    ClusterLeaveResult, Command, CommandError, CommandResult, CommandStatus, ContainerListResult,
    ContainerObservation, ContainerPort, LogSource, LogsReadResult, SystemInfoResult,
    SystemPingResult, TrustBundleUpdateResult, WireguardInspectResult, WireguardKeyEnsureResult,
    WorkloadDeployRequest, WorkloadDeployResult, WorkloadHealthCheck, WorkloadLifecycleAction,
    WorkloadLifecycleRequest, WorkloadLifecycleResult,
};
use sentinel_protocol::{
    CAPABILITY_BUILDER_RECONCILE, CAPABILITY_IMAGE_BUILD, CAPABILITY_IMAGE_LOAD,
    CAPABILITY_REGISTRY_INSPECT, CAPABILITY_REGISTRY_RECONCILE, REGISTRY_HOST,
};
use sentinel_protocol::{
    CAPABILITY_CLUSTER_LEAVE, CAPABILITY_CONTAINER_LIST, CAPABILITY_CONTAINER_LOGS,
    CAPABILITY_CORROSION_INSPECT, CAPABILITY_CORROSION_RECONCILE, CAPABILITY_FIREWALL_INSPECT,
    CAPABILITY_FIREWALL_RECONCILE, CAPABILITY_INGRESS_RECONCILE, CAPABILITY_LOGS_READ,
    CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING, CAPABILITY_TRUST_BUNDLE_UPDATE,
    CAPABILITY_WIREGUARD_INSPECT, CAPABILITY_WIREGUARD_KEY_ENSURE, CAPABILITY_WIREGUARD_RECONCILE,
    CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_LIFECYCLE,
};
use sentinel_protocol::{CAPABILITY_DATABASE_DUMP, CAPABILITY_DATABASE_RESTORE};
use sentinel_protocol::{
    CAPABILITY_VOLUME_BACKUP, CAPABILITY_VOLUME_DELETE, CAPABILITY_VOLUME_RECEIVE,
    CAPABILITY_VOLUME_RESTORE, CAPABILITY_VOLUME_SERVE,
};
use sentinel_protocol::{CAPABILITY_WORKLOAD_EXEC, CAPABILITY_WORKLOAD_TERMINAL};
use store::{CommandJournal, CommandLookup, CommandStart};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::Notify;

use crate::network::output_with_timeout;

/// Pulls of large images can take long; this only stops a stalled pull or
/// runtime from holding the command executor forever.
pub(crate) const PODMAN_DEPLOY_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PODMAN_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub(crate) const PODMAN_QUERY_TIMEOUT: Duration = Duration::from_secs(2 * 60);

pub(crate) const CONTAINER_RUNTIMES: [&str; 2] = ["podman", "docker"];

pub(crate) struct CommandExecution {
    pub(crate) accepted: bool,
    pub(crate) result: CommandResult,
}

pub(crate) struct CommandExecutor {
    sentinel_version: String,
    journal: CommandJournal,
    network_root: PathBuf,
    podman: PathBuf,
    system: System,
    discovery_trigger: Option<Arc<Notify>>,
    ingress_trigger: Option<Arc<Notify>>,
    control_tls: Option<config::ControlTlsConfig>,
}

impl CommandExecutor {
    #[cfg(test)]
    pub(crate) fn new(sentinel_version: &str) -> Self {
        Self::with_journal(
            sentinel_version,
            CommandJournal::open_in_memory(7, 100_000).expect("in-memory command journal"),
        )
    }

    pub(crate) fn with_journal(sentinel_version: &str, journal: CommandJournal) -> Self {
        Self {
            sentinel_version: sentinel_version.into(),
            journal,
            network_root: PathBuf::from("/"),
            podman: PathBuf::from("podman"),
            system: host_system(),
            discovery_trigger: None,
            ingress_trigger: None,
            control_tls: None,
        }
    }

    /// Lets `trust.bundle.update.v1` replace the Flux trust bundle files.
    pub(crate) fn with_control_tls(mut self, control_tls: config::ControlTlsConfig) -> Self {
        self.control_tls = Some(control_tls);
        self
    }

    /// Wakes the discovery publisher after a command changes local workloads.
    pub(crate) fn with_discovery_trigger(mut self, trigger: Arc<Notify>) -> Self {
        self.discovery_trigger = Some(trigger);
        self
    }

    /// Wakes the ingress renderer after a command changes routes or workloads.
    pub(crate) fn with_ingress_trigger(mut self, trigger: Arc<Notify>) -> Self {
        self.ingress_trigger = Some(trigger);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_network_root(mut self, root: &Path) -> Self {
        self.network_root = root.to_path_buf();
        self
    }

    #[cfg(test)]
    pub(crate) fn with_podman(mut self, podman: &Path) -> Self {
        self.podman = podman.to_path_buf();
        self
    }

    /// Takes the endpoint of a container that stops or is removed out of
    /// service first, so ingress sends its traffic to another endpoint of the
    /// workload instead of a container that is going away.
    fn drain_before_stopping(
        &self,
        request: &WorkloadLifecycleRequest,
    ) -> Option<crate::discovery::Drain> {
        let action = WorkloadLifecycleAction::try_from(request.action).ok()?;
        if !matches!(
            action,
            WorkloadLifecycleAction::Stop | WorkloadLifecycleAction::Remove
        ) || !valid_container_name(&request.name)
        {
            return None;
        }
        let (drain, wait) = crate::discovery::drain_endpoint(&self.network_root, &request.name);
        if let Some(trigger) = &self.ingress_trigger {
            trigger.notify_one();
        }
        if !wait.is_zero() {
            tracing::info!(container = %request.name, seconds = wait.as_secs(), "draining the endpoint before the container stops");
            std::thread::sleep(wait);
        }
        Some(drain)
    }

    pub(crate) fn execute(
        &mut self,
        command: Command,
        capability_accepted: bool,
    ) -> CommandExecution {
        let request = journal_request(&command);
        // logs.read and container.logs are read-only, frequently polled
        // commands. Their results are never replayed, so they are not
        // journaled; a repeated ID reads again. volume.serve and
        // volume.receive are idempotent per transfer and carry the transfer
        // secret, which must not be stored. registry.inspect is a read-only report.
        // volume.backup, volume.restore, database.dump, and database.restore
        // carry presigned S3 URLs.
        // workload.exec and workload.terminal carry commands and sessions.
        let journaled = !matches!(
            command.command_type.as_str(),
            CAPABILITY_LOGS_READ
                | CAPABILITY_CONTAINER_LOGS
                | CAPABILITY_VOLUME_SERVE
                | CAPABILITY_VOLUME_RECEIVE
                | CAPABILITY_REGISTRY_INSPECT
                | CAPABILITY_VOLUME_BACKUP
                | CAPABILITY_VOLUME_RESTORE
                | CAPABILITY_DATABASE_DUMP
                | CAPABILITY_DATABASE_RESTORE
                | CAPABILITY_WORKLOAD_EXEC
                | CAPABILITY_WORKLOAD_TERMINAL
        );
        let lookup = if journaled {
            self.journal.lookup(&command.command_id, &request)
        } else {
            Ok(CommandLookup::Missing)
        };
        match lookup {
            Ok(CommandLookup::Completed(result)) => {
                return match CommandResult::decode(result.as_slice()) {
                    Ok(result) => CommandExecution {
                        accepted: true,
                        result,
                    },
                    Err(_) => CommandExecution {
                        accepted: false,
                        result: failed(
                            &command.command_id,
                            "command_journal_corrupt",
                            "The stored command result is invalid.",
                        ),
                    },
                };
            }
            Ok(CommandLookup::Conflict) => {
                return CommandExecution {
                    accepted: false,
                    result: failed(
                        &command.command_id,
                        "command_id_conflict",
                        "Command ID was already used for another request.",
                    ),
                };
            }
            Ok(CommandLookup::Interrupted) => {
                return CommandExecution {
                    accepted: true,
                    result: failed(
                        &command.command_id,
                        "command_interrupted",
                        "The prior execution was interrupted and was not repeated.",
                    ),
                };
            }
            Err(_) => {
                return CommandExecution {
                    accepted: false,
                    result: failed(
                        &command.command_id,
                        "command_journal_unavailable",
                        "The durable command journal is unavailable.",
                    ),
                };
            }
            Ok(CommandLookup::Missing) => {}
        }
        let has_valid_payload = match (command.command_type.as_str(), command.payload.as_ref()) {
            (CAPABILITY_SYSTEM_PING, Some(Payload::SystemPing(ping))) => !ping.nonce.is_empty(),
            (CAPABILITY_SYSTEM_INFO, Some(Payload::SystemInfo(_))) => true,
            (CAPABILITY_CONTAINER_LIST, Some(Payload::ContainerList(_))) => true,
            (CAPABILITY_LOGS_READ, Some(Payload::LogsRead(request))) => {
                (1..=crate::logs::LOGS_READ_MAX_LIMIT).contains(&request.limit)
                    && matches!(
                        LogSource::try_from(request.source),
                        Ok(LogSource::Sentinel | LogSource::Corrosion | LogSource::DiscoveryDns)
                    )
            }
            (CAPABILITY_CONTAINER_LOGS, Some(Payload::ContainerLogs(request))) => {
                crate::container_logs::validate(request).is_ok()
            }
            (CAPABILITY_CLUSTER_LEAVE, Some(Payload::ClusterLeave(request))) => {
                crate::network::validate_cluster_leave(request).is_ok()
            }
            (CAPABILITY_WORKLOAD_DEPLOY, Some(Payload::WorkloadDeploy(request))) => {
                podman_deploy_args(request).is_ok()
            }
            (CAPABILITY_WORKLOAD_LIFECYCLE, Some(Payload::WorkloadLifecycle(request))) => {
                podman_lifecycle_args(request).is_ok()
            }
            (CAPABILITY_WIREGUARD_KEY_ENSURE, Some(Payload::WireguardKeyEnsure(request))) => {
                crate::network::validate_interface(&request.interface).is_ok()
            }
            (CAPABILITY_WIREGUARD_INSPECT, Some(Payload::WireguardInspect(request))) => {
                crate::network::validate_interface(&request.interface).is_ok()
            }
            (CAPABILITY_WIREGUARD_RECONCILE, Some(Payload::WireguardReconcile(request))) => {
                crate::network::validate_wireguard(request).is_ok()
            }
            (CAPABILITY_FIREWALL_INSPECT, Some(Payload::FirewallInspect(_))) => true,
            (CAPABILITY_FIREWALL_RECONCILE, Some(Payload::FirewallReconcile(request))) => {
                crate::network::render_firewall(request).is_ok()
            }
            (CAPABILITY_TRUST_BUNDLE_UPDATE, Some(Payload::TrustBundleUpdate(request))) => {
                request.version > 0
                    && !request.bundle_pem.is_empty()
                    && request.bundle_pem.len() <= crate::trust::MAX_BUNDLE_BYTES
            }
            (CAPABILITY_CORROSION_INSPECT, Some(Payload::CorrosionInspect(_))) => true,
            (CAPABILITY_CORROSION_RECONCILE, Some(Payload::CorrosionReconcile(request))) => {
                crate::network::render_corrosion(request).is_ok()
            }
            (CAPABILITY_INGRESS_RECONCILE, Some(Payload::IngressReconcile(request))) => {
                crate::ingress::validate_routes(request).is_ok()
            }
            (CAPABILITY_IMAGE_BUILD, Some(Payload::ImageBuild(request))) => {
                crate::builder::validate_build(request).is_ok()
            }
            (CAPABILITY_BUILDER_RECONCILE, Some(Payload::BuilderReconcile(request))) => {
                crate::builder::validate_reconcile(request).is_ok()
            }
            (CAPABILITY_REGISTRY_RECONCILE, Some(Payload::RegistryReconcile(request))) => {
                crate::registry::validate(request).is_ok()
            }
            (CAPABILITY_REGISTRY_INSPECT, Some(Payload::RegistryInspect(_))) => true,
            (CAPABILITY_IMAGE_LOAD, Some(Payload::ImageLoad(request))) => {
                crate::builder::validate_load(request).is_ok()
            }
            (CAPABILITY_VOLUME_DELETE, Some(Payload::VolumeDelete(request))) => {
                crate::volumes::validate_delete(request).is_ok()
            }
            (CAPABILITY_VOLUME_SERVE, Some(Payload::VolumeServe(request))) => {
                crate::volume_transfer::validate_serve(request).is_ok()
            }
            (CAPABILITY_VOLUME_RECEIVE, Some(Payload::VolumeReceive(request))) => {
                crate::volume_transfer::validate_receive(request).is_ok()
            }
            (CAPABILITY_VOLUME_BACKUP, Some(Payload::VolumeBackup(request))) => {
                crate::volume_backup::validate_backup(request).is_ok()
            }
            (CAPABILITY_VOLUME_RESTORE, Some(Payload::VolumeRestore(request))) => {
                crate::volume_backup::validate_restore(request).is_ok()
            }
            (CAPABILITY_DATABASE_DUMP, Some(Payload::DatabaseDump(request))) => {
                crate::database_dump::validate_dump(request).is_ok()
            }
            (CAPABILITY_DATABASE_RESTORE, Some(Payload::DatabaseRestore(request))) => {
                crate::database_dump::validate_restore(request).is_ok()
            }
            (CAPABILITY_WORKLOAD_EXEC, Some(Payload::WorkloadExec(request))) => {
                crate::exec::validate(request).is_ok()
            }
            (CAPABILITY_WORKLOAD_TERMINAL, Some(Payload::WorkloadTerminal(request))) => {
                crate::terminal::validate(request).is_ok()
            }
            _ => false,
        };
        let accepted = !(command.command_id.is_empty()
            || !matches!(
                command.command_type.as_str(),
                CAPABILITY_SYSTEM_PING
                    | CAPABILITY_CLUSTER_LEAVE
                    | CAPABILITY_SYSTEM_INFO
                    | CAPABILITY_CONTAINER_LIST
                    | CAPABILITY_LOGS_READ
                    | CAPABILITY_CONTAINER_LOGS
                    | CAPABILITY_TRUST_BUNDLE_UPDATE
                    | CAPABILITY_WORKLOAD_DEPLOY
                    | CAPABILITY_WORKLOAD_LIFECYCLE
                    | CAPABILITY_WIREGUARD_KEY_ENSURE
                    | CAPABILITY_WIREGUARD_INSPECT
                    | CAPABILITY_WIREGUARD_RECONCILE
                    | CAPABILITY_FIREWALL_INSPECT
                    | CAPABILITY_FIREWALL_RECONCILE
                    | CAPABILITY_CORROSION_INSPECT
                    | CAPABILITY_CORROSION_RECONCILE
                    | CAPABILITY_INGRESS_RECONCILE
                    | CAPABILITY_IMAGE_BUILD
                    | CAPABILITY_BUILDER_RECONCILE
                    | CAPABILITY_REGISTRY_RECONCILE
                    | CAPABILITY_REGISTRY_INSPECT
                    | CAPABILITY_IMAGE_LOAD
                    | CAPABILITY_VOLUME_DELETE
                    | CAPABILITY_VOLUME_SERVE
                    | CAPABILITY_VOLUME_RECEIVE
                    | CAPABILITY_VOLUME_BACKUP
                    | CAPABILITY_VOLUME_RESTORE
                    | CAPABILITY_DATABASE_DUMP
                    | CAPABILITY_DATABASE_RESTORE
                    | CAPABILITY_WORKLOAD_EXEC
                    | CAPABILITY_WORKLOAD_TERMINAL
            )
            || command.payload_version != 1
            || command.expires_at_unix_ms <= now_millis()
            || !capability_accepted)
            && has_valid_payload;
        if !accepted {
            return CommandExecution {
                accepted: false,
                result: failed(
                    &command.command_id,
                    "invalid_command",
                    "Command is invalid or expired.",
                ),
            };
        }

        let start = if journaled {
            self.journal
                .start(&command.command_id, &request, now_millis())
        } else {
            Ok(CommandStart::Started)
        };
        match start {
            Ok(CommandStart::Completed(result)) => {
                return match CommandResult::decode(result.as_slice()) {
                    Ok(result) => CommandExecution {
                        accepted: true,
                        result,
                    },
                    Err(_) => CommandExecution {
                        accepted: false,
                        result: failed(
                            &command.command_id,
                            "command_journal_corrupt",
                            "The stored command result is invalid.",
                        ),
                    },
                };
            }
            Ok(CommandStart::Conflict) => {
                return CommandExecution {
                    accepted: false,
                    result: failed(
                        &command.command_id,
                        "command_id_conflict",
                        "Command ID was already used for another request.",
                    ),
                };
            }
            Ok(CommandStart::Interrupted) => {
                return CommandExecution {
                    accepted: true,
                    result: failed(
                        &command.command_id,
                        "command_interrupted",
                        "The prior execution was interrupted and was not repeated.",
                    ),
                };
            }
            Err(_) => {
                return CommandExecution {
                    accepted: false,
                    result: failed(
                        &command.command_id,
                        "command_journal_unavailable",
                        "The durable command journal is unavailable.",
                    ),
                };
            }
            Ok(CommandStart::Started) => {}
        }

        let result = if let Some(Payload::SystemPing(ping)) = command.payload {
            CommandResult {
                event_id: format!("{}:result", command.command_id),
                command_id: command.command_id.clone(),
                status: CommandStatus::Succeeded.into(),
                observed_at_unix_ms: now_millis(),
                payload: Some(command_result::Payload::SystemPing(SystemPingResult {
                    nonce: ping.nonce,
                    sentinel_time_unix_ms: now_millis(),
                    sentinel_version: self.sentinel_version.clone(),
                    boot_id: boot_id(),
                })),
            }
        } else if let Some(Payload::SystemInfo(_)) = command.payload {
            CommandResult {
                event_id: format!("{}:result", command.command_id),
                command_id: command.command_id.clone(),
                status: CommandStatus::Succeeded.into(),
                observed_at_unix_ms: now_millis(),
                payload: Some(command_result::Payload::SystemInfo(system_info(
                    &self.sentinel_version,
                    &mut self.system,
                ))),
            }
        } else if let Some(Payload::ContainerList(_)) = command.payload {
            match container_list().and_then(|containers| {
                crate::volumes::list(&self.podman).map(|volumes| (containers, volumes))
            }) {
                Ok((containers, volumes)) => CommandResult {
                    event_id: format!("{}:result", command.command_id),
                    command_id: command.command_id.clone(),
                    status: CommandStatus::Succeeded.into(),
                    observed_at_unix_ms: now_millis(),
                    payload: Some(command_result::Payload::ContainerList(
                        ContainerListResult {
                            containers,
                            volumes,
                        },
                    )),
                },
                Err(message) => failed(&command.command_id, "container_list_failed", message),
            }
        } else if let Some(Payload::LogsRead(request)) = command.payload {
            match crate::logs::read_logs(request.source(), request.limit) {
                Ok((events, truncated)) => succeeded(
                    &command.command_id,
                    command_result::Payload::LogsRead(LogsReadResult {
                        source: request.source,
                        events,
                        truncated,
                    }),
                ),
                Err(message) => failed(&command.command_id, "logs_read_failed", &message),
            }
        } else if let Some(Payload::ContainerLogs(request)) = command.payload {
            match crate::container_logs::read(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::ContainerLogs(result),
                ),
                Err(message) => failed(&command.command_id, "container_logs_failed", &message),
            }
        } else if let Some(Payload::TrustBundleUpdate(request)) = command.payload {
            match self.control_tls.as_ref() {
                Some(control_tls) => {
                    match crate::trust::install(control_tls, request.version, &request.bundle_pem) {
                        Ok(update) => succeeded(
                            &command.command_id,
                            command_result::Payload::TrustBundleUpdate(TrustBundleUpdateResult {
                                installed_version: update.installed_version,
                                changed: update.changed,
                            }),
                        ),
                        Err(message) => {
                            failed(&command.command_id, "trust_bundle_update_failed", &message)
                        }
                    }
                }
                None => failed(
                    &command.command_id,
                    "trust_bundle_unavailable",
                    "This Sentinel has no Flux trust bundle to update.",
                ),
            }
        } else if let Some(Payload::ClusterLeave(request)) = command.payload {
            match crate::network::leave_cluster(&self.network_root, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::ClusterLeave(ClusterLeaveResult {
                        wireguard_removed: result.wireguard_removed,
                        firewall_removed: result.firewall_removed,
                        discovery_removed: result.discovery_removed,
                        resolver_reverted: result.resolver_reverted,
                    }),
                ),
                Err(message) => failed(&command.command_id, "cluster_leave_failed", &message),
            }
        } else if let Some(Payload::WorkloadDeploy(request)) = command.payload {
            match workload_deploy(&self.network_root, &self.podman, &request) {
                Ok(result) => CommandResult {
                    event_id: format!("{}:result", command.command_id),
                    command_id: command.command_id.clone(),
                    status: CommandStatus::Succeeded.into(),
                    observed_at_unix_ms: now_millis(),
                    payload: Some(command_result::Payload::WorkloadDeploy(result)),
                },
                Err(message) => failed(&command.command_id, "workload_deploy_failed", &message),
            }
        } else if let Some(Payload::WorkloadLifecycle(request)) = command.payload {
            let _drain = self.drain_before_stopping(&request);
            match workload_lifecycle(&self.network_root, &self.podman, &request) {
                Ok(result) => CommandResult {
                    event_id: format!("{}:result", command.command_id),
                    command_id: command.command_id.clone(),
                    status: CommandStatus::Succeeded.into(),
                    observed_at_unix_ms: now_millis(),
                    payload: Some(command_result::Payload::WorkloadLifecycle(result)),
                },
                Err(message) => failed(&command.command_id, "workload_lifecycle_failed", &message),
            }
        } else if let Some(Payload::WireguardKeyEnsure(request)) = command.payload {
            match crate::network::ensure_key(&self.network_root, &request.interface) {
                Ok(public_key) => succeeded(
                    &command.command_id,
                    command_result::Payload::WireguardKeyEnsure(WireguardKeyEnsureResult {
                        public_key,
                    }),
                ),
                Err(message) => {
                    failed(&command.command_id, "wireguard_key_ensure_failed", &message)
                }
            }
        } else if let Some(Payload::WireguardInspect(request)) = command.payload {
            succeeded(
                &command.command_id,
                command_result::Payload::WireguardInspect(wireguard_inspect(
                    &self.network_root,
                    &request.interface,
                    request.expected_revision,
                    &request.expected_hash,
                )),
            )
        } else if let Some(Payload::WireguardReconcile(request)) = command.payload {
            match crate::network::reconcile_wireguard(&self.network_root, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::WireguardReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "wireguard_reconcile_failed", &message),
            }
        } else if let Some(Payload::FirewallInspect(request)) = command.payload {
            succeeded(
                &command.command_id,
                command_result::Payload::FirewallInspect(crate::network::inspect_firewall(
                    &self.network_root,
                    request.expected_revision,
                    &request.expected_hash,
                )),
            )
        } else if let Some(Payload::FirewallReconcile(request)) = command.payload {
            match crate::network::reconcile_firewall(&self.network_root, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::FirewallReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "firewall_reconcile_failed", &message),
            }
        } else if let Some(Payload::CorrosionInspect(_)) = command.payload {
            succeeded(
                &command.command_id,
                command_result::Payload::CorrosionInspect(crate::network::inspect_corrosion(
                    &self.network_root,
                )),
            )
        } else if let Some(Payload::CorrosionReconcile(request)) = command.payload {
            match crate::network::reconcile_corrosion(&self.network_root, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::CorrosionReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "corrosion_reconcile_failed", &message),
            }
        } else if let Some(Payload::IngressReconcile(request)) = command.payload {
            match crate::ingress::reconcile(&self.network_root, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::IngressReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "ingress_reconcile_failed", &message),
            }
        } else if let Some(Payload::ImageBuild(request)) = command.payload {
            match crate::builder::start(&self.network_root, &self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::ImageBuild(result),
                ),
                Err(message) => failed(&command.command_id, "image_build_failed", &message),
            }
        } else if let Some(Payload::BuilderReconcile(request)) = command.payload {
            match crate::builder::reconcile(&self.network_root, &self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::BuilderReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "builder_reconcile_failed", &message),
            }
        } else if let Some(Payload::ImageLoad(request)) = command.payload {
            match crate::builder::load(&self.network_root, &self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::ImageLoad(result),
                ),
                Err(message) => failed(&command.command_id, "image_load_failed", &message),
            }
        } else if let Some(Payload::RegistryInspect(_)) = command.payload {
            succeeded(
                &command.command_id,
                command_result::Payload::RegistryInspect(crate::registry_inspect::inspect(
                    &self.network_root,
                    &self.podman,
                )),
            )
        } else if let Some(Payload::RegistryReconcile(request)) = command.payload {
            let result = crate::registry::reconcile(&self.network_root, &self.podman, &request);
            // The registry Node publishes `registry.cluster.coolify.internal`.
            if let Some(trigger) = &self.discovery_trigger {
                trigger.notify_one();
            }
            match result {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::RegistryReconcile(result),
                ),
                Err(message) => failed(&command.command_id, "registry_reconcile_failed", &message),
            }
        } else if let Some(Payload::VolumeDelete(request)) = command.payload {
            match crate::volumes::delete(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::VolumeDelete(result),
                ),
                Err(message) => failed(&command.command_id, "volume_delete_failed", &message),
            }
        } else if let Some(Payload::VolumeServe(request)) = command.payload {
            match crate::volume_transfer::serve(&self.network_root, &self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::VolumeServe(result),
                ),
                Err(message) => failed(&command.command_id, "volume_serve_failed", &message),
            }
        } else if let Some(Payload::VolumeReceive(request)) = command.payload {
            match crate::volume_transfer::receive(&self.network_root, &self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::VolumeReceive(result),
                ),
                Err(message) => failed(&command.command_id, "volume_receive_failed", &message),
            }
        } else if let Some(Payload::VolumeBackup(request)) = command.payload {
            match crate::volume_backup::backup(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::VolumeBackup(result),
                ),
                Err(message) => failed(&command.command_id, "volume_backup_failed", &message),
            }
        } else if let Some(Payload::DatabaseDump(request)) = command.payload {
            match crate::database_dump::dump(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::DatabaseDump(result),
                ),
                Err(message) => failed(&command.command_id, "database_dump_failed", &message),
            }
        } else if let Some(Payload::DatabaseRestore(request)) = command.payload {
            match crate::database_dump::restore(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::DatabaseRestore(result),
                ),
                Err(message) => failed(&command.command_id, "database_restore_failed", &message),
            }
        } else if let Some(Payload::VolumeRestore(request)) = command.payload {
            match crate::volume_backup::restore(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::VolumeRestore(result),
                ),
                Err(message) => failed(&command.command_id, "volume_restore_failed", &message),
            }
        } else if let Some(Payload::WorkloadExec(request)) = command.payload {
            match crate::exec::exec(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::WorkloadExec(result),
                ),
                Err(message) => failed(&command.command_id, "workload_exec_failed", &message),
            }
        } else if let Some(Payload::WorkloadTerminal(request)) = command.payload {
            match crate::terminal::open(&self.podman, &request) {
                Ok(result) => succeeded(
                    &command.command_id,
                    command_result::Payload::WorkloadTerminal(result),
                ),
                Err(message) => failed(&command.command_id, "workload_terminal_failed", &message),
            }
        } else {
            failed(
                &command.command_id,
                "invalid_payload",
                "Command payload is missing.",
            )
        };
        if matches!(
            result.payload,
            Some(
                command_result::Payload::WorkloadDeploy(_)
                    | command_result::Payload::WorkloadLifecycle(_)
            )
        ) && let Some(trigger) = &self.discovery_trigger
        {
            trigger.notify_one();
        }
        if matches!(
            result.payload,
            Some(
                command_result::Payload::IngressReconcile(_)
                    | command_result::Payload::WorkloadDeploy(_)
                    | command_result::Payload::WorkloadLifecycle(_)
            )
        ) && let Some(trigger) = &self.ingress_trigger
        {
            trigger.notify_one();
        }
        if journaled
            && let Err(error) =
                self.journal
                    .finish(&command.command_id, &result.encode_to_vec(), now_millis())
        {
            tracing::warn!(%error, command_id = %command.command_id, "could not persist command result");
        }
        CommandExecution {
            accepted: true,
            result,
        }
    }
}

fn succeeded(command_id: &str, payload: command_result::Payload) -> CommandResult {
    CommandResult {
        event_id: format!("{command_id}:result"),
        command_id: command_id.into(),
        status: CommandStatus::Succeeded.into(),
        observed_at_unix_ms: now_millis(),
        payload: Some(payload),
    }
}

fn wireguard_inspect(
    root: &Path,
    interface: &str,
    expected_revision: u64,
    expected_hash: &str,
) -> WireguardInspectResult {
    crate::network::inspect_wireguard(root, interface, expected_revision, expected_hash)
}

/// Runs a lifecycle action and keeps the durable stop marker in step with it.
///
/// A stop writes the marker before Podman runs, so a crash in between never
/// leaves a stopped workload without one. If the stop fails, the marker goes
/// back to its prior state: it is removed only when this stop created it.
/// Start, restart and remove clear the marker only after Podman succeeded.
fn workload_lifecycle(
    root: &Path,
    podman: &Path,
    request: &WorkloadLifecycleRequest,
) -> Result<WorkloadLifecycleResult, String> {
    let arguments = podman_lifecycle_args(request)?;
    let stopping = request.action == WorkloadLifecycleAction::Stop as i32;
    let previously_marked = if stopping {
        Some(crate::restore::mark_stopped(root, &request.name)?)
    } else {
        None
    };
    // Podman needs the stop timeout plus the time to remove the container.
    let timeout = PODMAN_LIFECYCLE_TIMEOUT.max(Duration::from_secs(
        u64::from(stop_timeout_seconds(request)?) + 60,
    ));
    let output = output_with_timeout(std::process::Command::new(podman).args(arguments), timeout)
        .map_err(podman_error);
    let failure = match output {
        Ok(output) if output.status.success() => None,
        Ok(output) => {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Some(if message.is_empty() {
                "Podman could not change the workload state.".into()
            } else {
                message.chars().take(2_000).collect()
            })
        }
        Err(message) => Some(message),
    };
    if let Some(message) = failure {
        if previously_marked == Some(false)
            && let Err(error) = crate::restore::clear_stopped(root, &request.name)
        {
            tracing::warn!(%error, container = %request.name, "could not remove the stop marker after a failed stop");
        }
        return Err(message);
    }
    if !stopping {
        crate::restore::clear_stopped(root, &request.name)?;
    }
    if request.action == WorkloadLifecycleAction::Remove as i32 {
        crate::secrets::delete_all(podman, &request.name)?;
    }

    Ok(WorkloadLifecycleResult {
        name: request.name.clone(),
        action: request.action,
    })
}

const DEFAULT_STOP_TIMEOUT_SECONDS: u32 = 10;
const MAX_STOP_TIMEOUT_SECONDS: u32 = 600;

fn stop_timeout_seconds(request: &WorkloadLifecycleRequest) -> Result<u32, String> {
    match request.stop_timeout_seconds {
        None => Ok(DEFAULT_STOP_TIMEOUT_SECONDS),
        Some(seconds) if (1..=MAX_STOP_TIMEOUT_SECONDS).contains(&seconds) => Ok(seconds),
        Some(_) => Err("The stop timeout must be 1 to 600 seconds.".into()),
    }
}

pub(crate) fn podman_lifecycle_args(
    request: &WorkloadLifecycleRequest,
) -> Result<Vec<String>, String> {
    if !valid_container_name(&request.name) {
        return Err("The container name is invalid.".into());
    }

    let name = request.name.clone();
    let stop_timeout = stop_timeout_seconds(request)?.to_string();
    match WorkloadLifecycleAction::try_from(request.action).ok() {
        Some(WorkloadLifecycleAction::Start) => Ok(vec!["start".into(), name]),
        Some(WorkloadLifecycleAction::Stop) => {
            Ok(vec!["stop".into(), "--time".into(), stop_timeout, name])
        }
        Some(WorkloadLifecycleAction::Restart) => {
            Ok(vec!["restart".into(), "--time".into(), stop_timeout, name])
        }
        Some(WorkloadLifecycleAction::Remove) => Ok(vec!["rm".into(), "--force".into(), name]),
        _ => Err("The workload lifecycle action is invalid.".into()),
    }
}

pub(crate) fn journal_request(command: &Command) -> Vec<u8> {
    let mut command = command.clone();
    command.created_at_unix_ms = 0;
    command.expires_at_unix_ms = 0;
    command.encode_to_vec()
}

/// Container names Podman accepts. They also name the durable stop markers,
/// so a leading dot (`.`, `..`) is never allowed.
pub(crate) fn valid_container_name(name: &str) -> bool {
    sentinel_protocol::valid_container_name(name)
}

fn workload_deploy(
    root: &Path,
    podman: &Path,
    request: &WorkloadDeployRequest,
) -> Result<WorkloadDeployResult, String> {
    let mut deploy = podman_deploy_args(request)?;
    let auth = crate::registry::pull_auth_path(root);
    // Lives until `podman run` has pulled the image; dropping it deletes the file.
    let mut _login = None;
    if request.image.starts_with(&format!("{REGISTRY_HOST}/")) && auth.exists() {
        deploy
            .arguments
            .splice(1..1, ["--authfile".to_string(), auth.display().to_string()]);
    } else if !request.registry_username.is_empty() {
        let login = TemporaryAuthFile::write(
            root,
            &request.name,
            &crate::registry::login_auth_file(
                &crate::registry::image_registry_host(&request.image),
                &request.registry_username,
                &request.registry_password,
            ),
        )?;
        deploy.arguments.splice(
            1..1,
            ["--authfile".to_string(), login.0.display().to_string()],
        );
        _login = Some(login);
    }
    if !request.network_name.is_empty() {
        ensure_workload_network(podman, &request.network_name, &request.network_subnet)?;
    }
    // `podman run` would create a missing volume itself, without the Coolify labels.
    crate::volumes::ensure_volumes(
        podman,
        request
            .mounts
            .iter()
            .map(|mount| mount.volume_name.as_str()),
    )?;
    crate::secrets::create(podman, request)?;
    let mut command = std::process::Command::new(podman);
    command
        .args(deploy.arguments)
        .env_clear()
        .envs(std::env::vars_os().filter(|(name, _)| {
            name.to_str()
                .is_some_and(|name| podman_runtime_variable(name) && name != "NOTIFY_SOCKET")
        }))
        .envs(deploy.environment);
    let output = output_with_timeout(&mut command, PODMAN_DEPLOY_TIMEOUT).map_err(podman_error)?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if message.is_empty() {
            "Podman could not deploy the workload.".into()
        } else {
            message.chars().take(2_000).collect()
        });
    }
    let runtime_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if runtime_id.is_empty() {
        return Err("Podman did not return a container ID.".into());
    }
    // A deploy means "run": the workload must come back after a reboot.
    crate::restore::clear_stopped(root, &request.name)?;
    // The new container runs, so the secrets of older revisions are unused. A
    // failure leaves them until the next deploy or remove.
    if let Err(error) = crate::secrets::delete_unused(podman, request) {
        tracing::warn!(%error, container = %request.name, "could not delete unused workload secrets");
    }
    Ok(WorkloadDeployResult {
        runtime_id,
        name: request.name.clone(),
        image: request.image.clone(),
    })
}

fn ensure_workload_network(podman: &Path, name: &str, subnet: &str) -> Result<(), String> {
    let inspected = output_with_timeout(
        std::process::Command::new(podman).args(["network", "inspect", name]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(podman_error)?;
    if inspected.status.success() {
        return network_inspect_has_subnet(&inspected.stdout, subnet)
            .then_some(())
            .ok_or_else(|| "The existing workload network uses a different subnet.".to_string());
    }
    let created = output_with_timeout(
        std::process::Command::new(podman).args(["network", "create", "--subnet", subnet, name]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(podman_error)?;
    if created.status.success() {
        return Ok(());
    }
    let raced = output_with_timeout(
        std::process::Command::new(podman).args(["network", "inspect", name]),
        PODMAN_QUERY_TIMEOUT,
    );
    if raced.is_ok_and(|output| {
        output.status.success() && network_inspect_has_subnet(&output.stdout, subnet)
    }) {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&created.stderr).trim().to_string();
    Err(if message.is_empty() {
        "Podman could not create the workload network.".into()
    } else {
        message.chars().take(2_000).collect()
    })
}

pub(crate) fn network_inspect_has_subnet(output: &[u8], subnet: &str) -> bool {
    serde_json::from_slice::<Vec<serde_json::Value>>(output)
        .ok()
        .and_then(|networks| networks.into_iter().next())
        .and_then(|network| {
            network
                .get("subnets")
                .or_else(|| network.get("Subnets"))
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .is_some_and(|subnets| {
            subnets.iter().any(|value| {
                value
                    .get("subnet")
                    .or_else(|| value.get("Subnet"))
                    .and_then(serde_json::Value::as_str)
                    == Some(subnet)
            })
        })
}

fn valid_network_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

fn valid_ipv4_subnet_and_address(subnet: &str, address: &str) -> bool {
    let Some((network, prefix)) = subnet.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 30 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    u32::from(network) & mask == u32::from(network)
        && u32::from(address) & mask == u32::from(network)
        && address != network
}

/// A stable, locally administered MAC for a workload address, derived from it
/// like Docker does. The workload keeps its address across restarts and
/// redeploys; a random MAC per start would leave the host and other containers
/// with a stale neighbor entry, so traffic to the address fails for up to a
/// minute until the entry expires.
pub(crate) fn container_mac_address(address: std::net::Ipv4Addr) -> String {
    let [a, b, c, d] = address.octets();
    format!("02:42:{a:02x}:{b:02x}:{c:02x}:{d:02x}")
}

/// A `podman run` invocation. Workload environment values travel in the
/// child's process environment, not in its argument list, because
/// `/proc/<pid>/cmdline` is readable by every local user.
#[derive(Debug)]
pub(crate) struct PodmanDeploy {
    pub(crate) arguments: Vec<String>,
    pub(crate) environment: Vec<(String, String)>,
}

/// Environment variables that Podman or its helpers read themselves. Sentinel
/// passes these from its own environment to Podman. A workload variable with
/// such a name stays in the argument list, so it cannot change how Podman runs.
pub(crate) fn podman_runtime_variable(name: &str) -> bool {
    const NAMES: [&str; 18] = [
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TZ",
        "TMPDIR",
        "NOTIFY_SOCKET",
        "DBUS_SESSION_BUS_ADDRESS",
        "REGISTRY_AUTH_FILE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "STORAGE_DRIVER",
        "STORAGE_OPTS",
        "GODEBUG",
        "GOMAXPROCS",
        "GOMEMLIMIT",
    ];
    const PREFIXES: [&str; 10] = [
        "LC_",
        "XDG_",
        "CONTAINERS_",
        "CONTAINER_",
        "PODMAN_",
        "BUILDAH_",
        "DOCKER_",
        "NETAVARK_",
        "AARDVARK_",
        "_",
    ];
    let upper = name.to_ascii_uppercase();
    NAMES.contains(&name)
        || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || matches!(
            upper.as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY" | "ALL_PROXY" | "FTP_PROXY"
        )
}

/// The `podman run` flags of a health check. Podman runs a command that is not
/// a JSON array with `/bin/sh -c`, like the `CMD-SHELL` form of `HEALTHCHECK`.
pub(crate) fn podman_health_args(check: &WorkloadHealthCheck) -> Result<Vec<String>, String> {
    let command = check.command.trim();
    if command.is_empty()
        || command.len() > 4_096
        || command.starts_with('[')
        || command.contains(['\0', '\n', '\r'])
    {
        return Err("The health check command is invalid.".into());
    }
    let seconds = |value: u32, minimum: u32| (minimum..=3_600).contains(&value);
    if !seconds(check.interval_seconds, 1)
        || !seconds(check.timeout_seconds, 1)
        || !seconds(check.start_period_seconds, 0)
        || !(1..=100).contains(&check.retries)
    {
        return Err("The health check timing is invalid.".into());
    }
    Ok(vec![
        "--health-cmd".into(),
        command.into(),
        "--health-interval".into(),
        format!("{}s", check.interval_seconds),
        "--health-timeout".into(),
        format!("{}s", check.timeout_seconds),
        "--health-retries".into(),
        check.retries.to_string(),
        "--health-start-period".into(),
        format!("{}s", check.start_period_seconds),
    ])
}

/// The registry login of one deploy on the host `/run` (tmpfs), 0600 in a 0700
/// directory of root, so it never reaches the disk. Dropping it deletes it.
struct TemporaryAuthFile(PathBuf);

const REGISTRY_LOGIN_DIR: &str = "run/coolify-registry-login";

impl TemporaryAuthFile {
    fn write(root: &Path, name: &str, contents: &[u8]) -> Result<Self, String> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        let error = || "The registry login could not be written.".to_string();
        let dir = root.join(REGISTRY_LOGIN_DIR);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|_| error())?;
        let path = dir.join(format!("{name}.json"));
        let _ = std::fs::remove_file(&path);
        let file = Self(path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file.0)
            .and_then(|mut handle| handle.write_all(contents))
            .map_err(|_| error())?;
        Ok(file)
    }
}

impl Drop for TemporaryAuthFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(%error, "could not remove a registry login file"),
        }
    }
}

pub(crate) fn podman_deploy_args(request: &WorkloadDeployRequest) -> Result<PodmanDeploy, String> {
    if !valid_container_name(&request.name) {
        return Err("The container name is invalid.".into());
    }
    if crate::registry::validate_login(&request.registry_username, &request.registry_password)?
        && (request.image.starts_with(&format!("{REGISTRY_HOST}/"))
            || request
                .image
                .starts_with(crate::builder::LOCAL_IMAGE_PREFIX))
    {
        return Err("A registry login is not used for a cluster image.".into());
    }
    if request.image.is_empty()
        || request.image.starts_with('-')
        || request.image.len() > 2_048
        || !request
            .image
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/:@".contains(c))
    {
        return Err("The image reference is invalid.".into());
    }
    if !matches!(
        request.restart_policy.as_str(),
        "no" | "always" | "on-failure" | "unless-stopped"
    ) {
        return Err("The restart policy is invalid.".into());
    }
    let pull_policy = match request.pull_policy.as_str() {
        "" | "missing" => "missing",
        "newer" => "newer",
        "always" => "always",
        _ => return Err("The image pull policy is invalid.".into()),
    };
    if request.command.len() > 64 || request.labels.len() > 128 || request.ports.len() > 128 {
        return Err("The workload configuration is too large.".into());
    }
    let uses_managed_network = !request.network_name.is_empty()
        || !request.network_subnet.is_empty()
        || !request.container_ip.is_empty();
    if uses_managed_network
        && (!valid_network_name(&request.network_name)
            || !valid_ipv4_subnet_and_address(&request.network_subnet, &request.container_ip))
    {
        return Err("The workload network configuration is invalid.".into());
    }
    if !request.dns_server.is_empty() && request.dns_server.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("The workload DNS server is invalid.".into());
    }
    if request
        .cpu_limit
        .is_some_and(|value| !value.is_finite() || value <= 0.0 || value > 1_024.0)
        || request
            .cpu_reservation
            .is_some_and(|value| !value.is_finite() || value <= 0.0 || value > 1_024.0)
        || matches!((request.cpu_limit, request.cpu_reservation), (Some(limit), Some(reservation)) if reservation > limit)
        || request.memory_limit_bytes.is_some_and(|value| value == 0)
        || request
            .memory_reservation_bytes
            .is_some_and(|value| value == 0)
        || matches!((request.memory_limit_bytes, request.memory_reservation_bytes), (Some(limit), Some(reservation)) if reservation > limit)
    {
        return Err("The workload resource configuration is invalid.".into());
    }
    let mut args = vec![
        "run".into(),
        "--detach".into(),
        "--replace".into(),
        "--pull".into(),
        pull_policy.into(),
        "--name".into(),
        request.name.clone(),
        "--restart".into(),
        request.restart_policy.clone(),
    ];
    if uses_managed_network {
        args.extend(["--network".into(), request.network_name.clone()]);
        args.extend(["--ip".into(), request.container_ip.clone()]);
        if let Ok(address) = request.container_ip.parse::<std::net::Ipv4Addr>() {
            args.extend(["--mac-address".into(), container_mac_address(address)]);
        }
    }
    if !request.dns_server.is_empty() {
        args.extend(["--dns".into(), request.dns_server.clone()]);
    }
    if let Some(cpu_limit) = request.cpu_limit {
        args.extend(["--cpus".into(), cpu_limit.to_string()]);
    }
    if let Some(cpu_reservation) = request.cpu_reservation {
        let cpu_shares = (cpu_reservation * 1_024.0).round().clamp(2.0, 262_144.0) as u64;
        args.extend(["--cpu-shares".into(), cpu_shares.to_string()]);
    }
    if let Some(memory_limit_bytes) = request.memory_limit_bytes {
        args.extend(["--memory".into(), format!("{memory_limit_bytes}b")]);
    }
    if let Some(memory_reservation_bytes) = request.memory_reservation_bytes {
        args.extend([
            "--memory-reservation".into(),
            format!("{memory_reservation_bytes}b"),
        ]);
    }
    if let Some(check) = &request.health_check {
        args.extend(podman_health_args(check)?);
    }
    let mut environment = Vec::new();
    for variable in &request.environment {
        let key = &variable.key;
        let value = &variable.value;
        // Podman accepts any name and value; only `=` in a name and null bytes can be passed neither as `--env KEY=VALUE` nor in a process environment.
        if key.is_empty() || key.contains('=') || key.contains('\0') || value.contains('\0') {
            return Err("An environment variable is invalid.".into());
        }
        // `--env KEY` reads the value from Podman's environment. A `*` in the
        // name is a Podman wildcard import, so such names stay inline.
        if key.contains('*') || podman_runtime_variable(key) {
            args.extend(["--env".into(), format!("{key}={value}")]);
        } else {
            args.extend(["--env".into(), key.clone()]);
            environment.push((key.clone(), value.clone()));
        }
    }
    for label in &request.labels {
        let key = &label.key;
        let value = &label.value;
        if key.is_empty()
            || key.len() > 255
            || value.len() > 4_096
            || key.contains('=')
            || key.contains('\0')
            || value.contains('\0')
        {
            return Err("A container label is invalid.".into());
        }
        args.extend(["--label".into(), format!("{key}={value}")]);
    }
    for port in &request.ports {
        if port.container_port == 0
            || port.container_port > 65_535
            || port.host_port.is_some_and(|p| p == 0 || p > 65_535)
            || !matches!(port.protocol.as_str(), "tcp" | "udp" | "sctp")
        {
            return Err("A published port is invalid.".into());
        }
        let mut published = String::new();
        if let Some(host_ip) = &port.host_ip {
            if host_ip.parse::<std::net::IpAddr>().is_err() {
                return Err("A published port host IP is invalid.".into());
            }
            published.push_str(host_ip);
            published.push(':');
        }
        if let Some(host_port) = port.host_port {
            published.push_str(&host_port.to_string());
            published.push(':');
        }
        published.push_str(&format!("{}/{}", port.container_port, port.protocol));
        args.extend(["--publish".into(), published]);
    }
    if request
        .command
        .iter()
        .any(|v| v.len() > 4_096 || v.contains('\0'))
    {
        return Err("A command argument is invalid.".into());
    }
    args.extend(crate::volumes::mount_args(&request.mounts)?);
    args.extend(crate::secrets::mount_args(request)?);
    args.push(request.image.clone());
    args.extend(request.command.clone());
    Ok(PodmanDeploy {
        arguments: args,
        environment,
    })
}

fn container_list() -> Result<Vec<ContainerObservation>, &'static str> {
    let output = output_with_timeout(
        std::process::Command::new("podman").args([
            "ps",
            "--all",
            "--no-trunc",
            "--format",
            "json",
        ]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|_| "Podman is unavailable or did not answer.")?;
    if !output.status.success() {
        return Err("Podman could not list containers.");
    }

    parse_podman_containers(&output.stdout)
}

pub(crate) fn parse_podman_containers(
    output: &[u8],
) -> Result<Vec<ContainerObservation>, &'static str> {
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(output).map_err(|_| "Podman returned invalid container data.")?;
    if values.len() > 10_000 {
        return Err("Podman returned too many containers.");
    }

    values
        .iter()
        .map(|value| {
            let runtime_id = string_field(value, &["Id", "ID"])
                .filter(|value| !value.is_empty())
                .ok_or("Podman returned a container without an ID.")?;
            let name = value
                .get("Names")
                .and_then(serde_json::Value::as_array)
                .and_then(|names| names.first())
                .and_then(serde_json::Value::as_str)
                .or_else(|| string_field(value, &["Name"]))
                .filter(|value| !value.is_empty())
                .ok_or("Podman returned a container without a name.")?;
            let image = string_field(value, &["Image"])
                .filter(|value| !value.is_empty())
                .ok_or("Podman returned a container without an image.")?;
            let state = string_field(value, &["State"])
                .filter(|value| !value.is_empty())
                .ok_or("Podman returned a container without a state.")?;
            let labels = value
                .get("Labels")
                .and_then(serde_json::Value::as_object)
                .map(|labels| {
                    labels
                        .iter()
                        .filter_map(|(key, value)| {
                            value.as_str().map(|value| (key.clone(), value.into()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let ports = value
                .get("Ports")
                .and_then(serde_json::Value::as_array)
                .map(|ports| ports.iter().filter_map(container_port).collect())
                .unwrap_or_default();

            Ok(ContainerObservation {
                runtime_id: runtime_id.into(),
                name: name.into(),
                image: image.into(),
                state: state.into(),
                health_status: container_health(value),
                restart_count: value
                    .get("Restarts")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                ports,
                labels,
                created_at_unix_ms: unix_millis(value, &["Created"]),
                started_at_unix_ms: unix_millis(value, &["StartedAt"]),
            })
        })
        .collect()
}

/// `podman ps --format json` puts the health check state in `Status`: empty
/// without a check, else `starting`, `healthy`, or `unhealthy`. Podman builds
/// the "Up 5 seconds (healthy)" text of the table output from it.
/// Podman 6 has no `Health` field in `podman ps --format json`; the health is only the
/// suffix of `Status`, as in "Up 3 minutes (healthy)".
fn container_health(value: &serde_json::Value) -> Option<String> {
    ["Health", "HealthStatus", "Status"]
        .iter()
        .find_map(|name| {
            let field = value.get(*name)?.as_str()?.trim().to_ascii_lowercase();
            let health = match field
                .strip_suffix(')')
                .and_then(|rest| rest.rsplit_once('('))
            {
                Some((_, suffix)) => suffix.trim_start_matches("health:").trim().to_string(),
                None => field,
            };
            matches!(health.as_str(), "starting" | "healthy" | "unhealthy").then_some(health)
        })
}

fn string_field<'a>(value: &'a serde_json::Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| value.get(name)?.as_str())
}

fn unix_millis(value: &serde_json::Value, names: &[&str]) -> Option<i64> {
    names
        .iter()
        .find_map(|name| value.get(name)?.as_i64())
        .and_then(|seconds| seconds.checked_mul(1_000))
        .filter(|value| *value > 0)
}

fn container_port(value: &serde_json::Value) -> Option<ContainerPort> {
    let container_port = value
        .get("container_port")
        .or_else(|| value.get("ContainerPort"))?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())?;

    Some(ContainerPort {
        host_ip: string_field(value, &["host_ip", "HostIp"]).map(str::to_string),
        host_port: value
            .get("host_port")
            .or_else(|| value.get("HostPort"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        container_port,
        protocol: string_field(value, &["protocol", "Protocol"])
            .unwrap_or("tcp")
            .into(),
    })
}

fn host_system() -> System {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    );
    system.refresh_cpu_usage();
    system.refresh_memory();

    system
}

fn system_info(sentinel_version: &str, system: &mut System) -> SystemInfoResult {
    system.refresh_cpu_usage();
    system.refresh_memory();
    let disks = Disks::new_with_refreshed_list();
    let root_disk = disks
        .list()
        .iter()
        .find(|disk| disk.mount_point() == std::path::Path::new("/"));
    let (container_runtime, container_runtime_version) = container_runtime();
    let load = System::load_average();

    SystemInfoResult {
        hostname: System::host_name(),
        operating_system: System::name(),
        operating_system_version: System::os_version(),
        kernel_version: System::kernel_version(),
        architecture: Some(System::cpu_arch()),
        cpu_count: std::thread::available_parallelism()
            .ok()
            .and_then(|count| u32::try_from(count.get()).ok()),
        memory_bytes: Some(system.total_memory()),
        disk_total_bytes: root_disk.map(|disk| disk.total_space()),
        disk_available_bytes: root_disk.map(|disk| disk.available_space()),
        sentinel_version: sentinel_version.into(),
        boot_id: Some(boot_id()),
        uptime_seconds: Some(System::uptime()),
        container_runtime,
        container_runtime_version,
        cpu_usage_percent: Some(f64::from(system.global_cpu_usage()).clamp(0.0, 100.0)),
        memory_used_bytes: Some(system.used_memory()),
        memory_available_bytes: Some(system.available_memory()),
        load_average_one: Some(load.one),
        load_average_five: Some(load.five),
        load_average_fifteen: Some(load.fifteen),
        ingress_certificates: crate::ingress_tls::issuer_statuses(std::path::Path::new("/")),
    }
}

fn container_runtime() -> (Option<String>, Option<String>) {
    for runtime in CONTAINER_RUNTIMES {
        let output = output_with_timeout(
            std::process::Command::new(runtime).args([
                "version",
                "--format",
                "{{.Server.Version}}",
            ]),
            Duration::from_secs(30),
        );
        if let Ok(output) = output
            && output.status.success()
        {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !version.is_empty() {
                return (Some(runtime.into()), Some(version));
            }
        }
    }

    (None, None)
}

fn podman_error(error: std::io::Error) -> String {
    podman_failure(&error)
}

pub(crate) fn podman_failure(error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::TimedOut {
        "Podman did not finish in time.".into()
    } else {
        "Podman is unavailable.".into()
    }
}

fn failed(command_id: &str, code: &str, message: &str) -> CommandResult {
    CommandResult {
        event_id: format!("{command_id}:result"),
        command_id: command_id.into(),
        status: CommandStatus::Failed.into(),
        observed_at_unix_ms: now_millis(),
        payload: Some(command_result::Payload::Error(CommandError {
            code: code.into(),
            message: message.into(),
        })),
    }
}

pub(crate) fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
