use std::path::{Path, PathBuf};

use prost::Message;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    Command, CommandError, CommandResult, CommandStatus, ContainerListResult, ContainerObservation,
    ContainerPort, SystemInfoResult, SystemPingResult, WireguardInspectResult,
    WireguardKeyEnsureResult, WorkloadDeployRequest, WorkloadDeployResult, WorkloadLifecycleAction,
    WorkloadLifecycleRequest, WorkloadLifecycleResult,
};
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_CORROSION_INSPECT, CAPABILITY_CORROSION_RECONCILE,
    CAPABILITY_FIREWALL_INSPECT, CAPABILITY_FIREWALL_RECONCILE, CAPABILITY_SYSTEM_INFO,
    CAPABILITY_SYSTEM_PING, CAPABILITY_WIREGUARD_INSPECT, CAPABILITY_WIREGUARD_KEY_ENSURE,
    CAPABILITY_WIREGUARD_RECONCILE, CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_LIFECYCLE,
};
use store::{CommandJournal, CommandLookup, CommandStart};
use sysinfo::{Disks, MemoryRefreshKind, RefreshKind, System};

pub(crate) const CONTAINER_RUNTIMES: [&str; 2] = ["podman", "docker"];

pub(crate) struct CommandExecution {
    pub(crate) accepted: bool,
    pub(crate) result: CommandResult,
}

pub(crate) struct CommandExecutor {
    sentinel_version: String,
    journal: CommandJournal,
    network_root: PathBuf,
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
        }
    }

    #[cfg(test)]
    pub(crate) fn with_network_root(mut self, root: &Path) -> Self {
        self.network_root = root.to_path_buf();
        self
    }

    pub(crate) fn execute(
        &mut self,
        command: Command,
        capability_accepted: bool,
    ) -> CommandExecution {
        let request = journal_request(&command);
        match self.journal.lookup(&command.command_id, &request) {
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
            (CAPABILITY_CORROSION_INSPECT, Some(Payload::CorrosionInspect(_))) => true,
            (CAPABILITY_CORROSION_RECONCILE, Some(Payload::CorrosionReconcile(request))) => {
                crate::network::render_corrosion(request).is_ok()
            }
            _ => false,
        };
        let accepted = !(command.command_id.is_empty()
            || !matches!(
                command.command_type.as_str(),
                CAPABILITY_SYSTEM_PING
                    | CAPABILITY_SYSTEM_INFO
                    | CAPABILITY_CONTAINER_LIST
                    | CAPABILITY_WORKLOAD_DEPLOY
                    | CAPABILITY_WORKLOAD_LIFECYCLE
                    | CAPABILITY_WIREGUARD_KEY_ENSURE
                    | CAPABILITY_WIREGUARD_INSPECT
                    | CAPABILITY_WIREGUARD_RECONCILE
                    | CAPABILITY_FIREWALL_INSPECT
                    | CAPABILITY_FIREWALL_RECONCILE
                    | CAPABILITY_CORROSION_INSPECT
                    | CAPABILITY_CORROSION_RECONCILE
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

        match self
            .journal
            .start(&command.command_id, &request, now_millis())
        {
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
                ))),
            }
        } else if let Some(Payload::ContainerList(_)) = command.payload {
            match container_list() {
                Ok(containers) => CommandResult {
                    event_id: format!("{}:result", command.command_id),
                    command_id: command.command_id.clone(),
                    status: CommandStatus::Succeeded.into(),
                    observed_at_unix_ms: now_millis(),
                    payload: Some(command_result::Payload::ContainerList(
                        ContainerListResult { containers },
                    )),
                },
                Err(message) => failed(&command.command_id, "container_list_failed", message),
            }
        } else if let Some(Payload::WorkloadDeploy(request)) = command.payload {
            match workload_deploy(&request) {
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
            match workload_lifecycle(&request) {
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
        } else {
            failed(
                &command.command_id,
                "invalid_payload",
                "Command payload is missing.",
            )
        };
        if let Err(error) =
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

fn workload_lifecycle(
    request: &WorkloadLifecycleRequest,
) -> Result<WorkloadLifecycleResult, String> {
    let output = std::process::Command::new("podman")
        .args(podman_lifecycle_args(request)?)
        .output()
        .map_err(|_| "Podman is unavailable.".to_string())?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if message.is_empty() {
            "Podman could not change the workload state.".into()
        } else {
            message.chars().take(2_000).collect()
        });
    }

    Ok(WorkloadLifecycleResult {
        name: request.name.clone(),
        action: request.action,
    })
}

pub(crate) fn podman_lifecycle_args(
    request: &WorkloadLifecycleRequest,
) -> Result<Vec<String>, String> {
    if request.name.is_empty()
        || request.name.len() > 128
        || !request
            .name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err("The container name is invalid.".into());
    }

    let name = request.name.clone();
    match WorkloadLifecycleAction::try_from(request.action).ok() {
        Some(WorkloadLifecycleAction::Start) => Ok(vec!["start".into(), name]),
        Some(WorkloadLifecycleAction::Stop) => {
            Ok(vec!["stop".into(), "--time".into(), "10".into(), name])
        }
        Some(WorkloadLifecycleAction::Restart) => {
            Ok(vec!["restart".into(), "--time".into(), "10".into(), name])
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

fn workload_deploy(request: &WorkloadDeployRequest) -> Result<WorkloadDeployResult, String> {
    let output = std::process::Command::new("podman")
        .args(podman_deploy_args(request)?)
        .output()
        .map_err(|_| "Podman is unavailable.".to_string())?;
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
    Ok(WorkloadDeployResult {
        runtime_id,
        name: request.name.clone(),
        image: request.image.clone(),
    })
}

pub(crate) fn podman_deploy_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    if request.name.is_empty()
        || request.name.len() > 128
        || !request
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        return Err("The container name is invalid.".into());
    }
    if request.image.is_empty()
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
    if request.command.len() > 64
        || request.environment.len() > 256
        || request.labels.len() > 128
        || request.ports.len() > 128
    {
        return Err("The workload configuration is too large.".into());
    }
    let mut args = vec![
        "run".into(),
        "--detach".into(),
        "--replace".into(),
        "--pull".into(),
        "missing".into(),
        "--name".into(),
        request.name.clone(),
        "--restart".into(),
        request.restart_policy.clone(),
    ];
    for variable in &request.environment {
        let key = &variable.key;
        let value = &variable.value;
        if key.is_empty()
            || key.len() > 255
            || value.len() > 4_096
            || value.contains('\0')
            || !key.chars().enumerate().all(|(i, c)| {
                c == '_' || c.is_ascii_alphanumeric() && (i > 0 || !c.is_ascii_digit())
            })
        {
            return Err("An environment variable is invalid.".into());
        }
        args.extend(["--env".into(), format!("{key}={value}")]);
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
    args.push(request.image.clone());
    args.extend(request.command.clone());
    Ok(args)
}

fn container_list() -> Result<Vec<ContainerObservation>, &'static str> {
    let output = std::process::Command::new("podman")
        .args(["ps", "--all", "--no-trunc", "--format", "json"])
        .output()
        .map_err(|_| "Podman is unavailable.")?;
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
                health_status: string_field(value, &["Health", "HealthStatus"]).map(str::to_string),
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

fn system_info(sentinel_version: &str) -> SystemInfoResult {
    let mut system = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
    );
    system.refresh_memory();
    let disks = Disks::new_with_refreshed_list();
    let root_disk = disks
        .list()
        .iter()
        .find(|disk| disk.mount_point() == std::path::Path::new("/"));
    let (container_runtime, container_runtime_version) = container_runtime();

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
    }
}

fn container_runtime() -> (Option<String>, Option<String>) {
    for runtime in CONTAINER_RUNTIMES {
        let output = std::process::Command::new(runtime)
            .args(["version", "--format", "{{.Server.Version}}"])
            .output();
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

fn boot_id() -> String {
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
