use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use prost::Message;
use sentinel_protocol::CAPABILITY_SYSTEM_PING;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    Command, CommandError, CommandResult, CommandStatus, SystemPingResult,
};

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
        let has_valid_payload = matches!(
            command.payload.as_ref(),
            Some(Payload::SystemPing(ping)) if !ping.nonce.is_empty()
        );
        let accepted = !(command.command_id.is_empty()
            || command.command_type != CAPABILITY_SYSTEM_PING
            || command.payload_version != 1
            || command.expires_at_unix_ms <= now_millis()
            || !capability_accepted)
            && has_valid_payload;
        let result = if !accepted {
            failed(
                &command.command_id,
                "invalid_command",
                "Ping command is invalid or expired.",
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
