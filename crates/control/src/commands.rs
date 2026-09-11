use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use prost::Message;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    Command, CommandError, CommandResult, CommandStatus, SystemInfoResult, SystemPingResult,
};
use sentinel_protocol::{CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING};
use sysinfo::{Disks, MemoryRefreshKind, RefreshKind, System};

const MAX_CACHED_RESULTS: usize = 1_000;
const RESULT_TTL: Duration = Duration::from_secs(30 * 60);

struct CachedCommand {
    request: Vec<u8>,
    result: CommandResult,
    cached_at_unix_ms: i64,
}

pub(crate) struct CommandExecution {
    pub(crate) accepted: bool,
    pub(crate) result: CommandResult,
}

pub(crate) struct CommandExecutor {
    sentinel_version: String,
    results: HashMap<String, CachedCommand>,
    order: VecDeque<String>,
}

impl CommandExecutor {
    pub(crate) fn new(sentinel_version: &str) -> Self {
        Self {
            sentinel_version: sentinel_version.into(),
            results: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub(crate) fn execute(
        &mut self,
        command: Command,
        capability_accepted: bool,
    ) -> CommandExecution {
        self.prune();
        let request = command.encode_to_vec();
        if let Some(cached) = self.results.get(&command.command_id) {
            return if cached.request == request {
                CommandExecution {
                    accepted: true,
                    result: cached.result.clone(),
                }
            } else {
                CommandExecution {
                    accepted: false,
                    result: failed(
                        &command.command_id,
                        "command_id_conflict",
                        "Command ID was already used for another request.",
                    ),
                }
            };
        }
        let has_valid_payload = match (command.command_type.as_str(), command.payload.as_ref()) {
            (CAPABILITY_SYSTEM_PING, Some(Payload::SystemPing(ping))) => !ping.nonce.is_empty(),
            (CAPABILITY_SYSTEM_INFO, Some(Payload::SystemInfo(_))) => true,
            _ => false,
        };
        let accepted = !(command.command_id.is_empty()
            || !matches!(
                command.command_type.as_str(),
                CAPABILITY_SYSTEM_PING | CAPABILITY_SYSTEM_INFO
            )
            || command.payload_version != 1
            || command.expires_at_unix_ms <= now_millis()
            || !capability_accepted)
            && has_valid_payload;
        let result = if !accepted {
            failed(
                &command.command_id,
                "invalid_command",
                "Command is invalid or expired.",
            )
        } else if let Some(Payload::SystemPing(ping)) = command.payload {
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
        } else {
            failed(
                &command.command_id,
                "invalid_payload",
                "Ping payload is missing.",
            )
        };
        self.remember(command.command_id, request, result.clone());
        CommandExecution { accepted, result }
    }

    fn remember(&mut self, command_id: String, request: Vec<u8>, result: CommandResult) {
        if self.results.len() >= MAX_CACHED_RESULTS
            && let Some(oldest) = self.order.pop_front()
        {
            self.results.remove(&oldest);
        }
        self.order.push_back(command_id.clone());
        self.results.insert(
            command_id,
            CachedCommand {
                request,
                result,
                cached_at_unix_ms: now_millis(),
            },
        );
    }

    fn prune(&mut self) {
        let cutoff = now_millis() - RESULT_TTL.as_millis() as i64;
        while let Some(oldest) = self.order.front() {
            if self
                .results
                .get(oldest)
                .is_some_and(|cached| cached.cached_at_unix_ms >= cutoff)
            {
                break;
            }
            let oldest = self.order.pop_front().expect("front exists");
            self.results.remove(&oldest);
        }
    }
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
    for runtime in ["docker", "podman"] {
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
