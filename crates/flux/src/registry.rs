use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sentinel_protocol::control::v1::{
    Command, CommandResult, ControlMessage, ShutdownHint, control_message,
};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub connection_id: String,
    pub protocol_version: u32,
    pub capabilities: Vec<String>,
    pub connected_at_unix_ms: i64,
    pub last_heartbeat_unix_ms: i64,
}

struct Connection {
    info: ConnectionInfo,
    sender: mpsc::Sender<ControlMessage>,
}

#[derive(Clone, Default)]
pub struct ConnectionRegistry {
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    pending: Arc<Mutex<HashMap<String, PendingCommand>>>,
}

struct PendingCommand {
    server_id: String,
    result: oneshot::Sender<CommandResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandDispatchError {
    #[error("server is not connected")]
    Offline,
    #[error("Sentinel does not support this command")]
    Unsupported,
    #[error("command could not be sent")]
    Send,
    #[error("connection command queue is full")]
    QueueFull,
    #[error("command timed out")]
    Timeout,
}

impl ConnectionRegistry {
    pub async fn insert(
        &self,
        server_id: &str,
        connection_id: &str,
        sender: mpsc::Sender<ControlMessage>,
        protocol_version: u32,
        capabilities: Vec<String>,
    ) {
        let now = now_millis();
        let connection = Connection {
            info: ConnectionInfo {
                connection_id: connection_id.into(),
                protocol_version,
                capabilities,
                connected_at_unix_ms: now,
                last_heartbeat_unix_ms: now,
            },
            sender,
        };
        let old = self
            .connections
            .write()
            .await
            .insert(server_id.into(), connection);
        if let Some(old) = old {
            let _ = old.sender.try_send(ControlMessage {
                message: Some(control_message::Message::ShutdownHint(ShutdownHint {
                    reason: "replaced".into(),
                    reconnect_after_seconds: 0,
                })),
            });
        }
    }

    pub async fn heartbeat(&self, server_id: &str, connection_id: &str, sent_at: i64) -> bool {
        let mut connections = self.connections.write().await;
        let Some(connection) = connections.get_mut(server_id) else {
            return false;
        };
        if connection.info.connection_id != connection_id {
            return false;
        }
        connection.info.last_heartbeat_unix_ms = sent_at.max(now_millis());
        true
    }

    pub async fn remove(&self, server_id: &str, connection_id: &str) {
        let mut connections = self.connections.write().await;
        if connections
            .get(server_id)
            .is_some_and(|connection| connection.info.connection_id == connection_id)
        {
            connections.remove(server_id);
        }
    }

    pub async fn get(&self, server_id: &str) -> Option<ConnectionInfo> {
        self.connections
            .read()
            .await
            .get(server_id)
            .map(|connection| connection.info.clone())
    }

    pub async fn dispatch(
        &self,
        server_id: &str,
        command: Command,
        timeout: std::time::Duration,
    ) -> Result<CommandResult, CommandDispatchError> {
        let command_id = command.command_id.clone();
        let (result_sender, result_receiver) = oneshot::channel();
        self.pending.lock().await.insert(
            command_id.clone(),
            PendingCommand {
                server_id: server_id.into(),
                result: result_sender,
            },
        );
        let send_result = {
            let connections = self.connections.read().await;
            let Some(connection) = connections.get(server_id) else {
                self.pending.lock().await.remove(&command_id);
                return Err(CommandDispatchError::Offline);
            };
            if !connection.info.capabilities.contains(&command.command_type) {
                self.pending.lock().await.remove(&command_id);
                return Err(CommandDispatchError::Unsupported);
            }
            connection.sender.try_send(ControlMessage {
                message: Some(control_message::Message::Command(command)),
            })
        };
        if let Err(error) = send_result {
            self.pending.lock().await.remove(&command_id);
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => CommandDispatchError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => CommandDispatchError::Send,
            });
        }
        match tokio::time::timeout(timeout, result_receiver).await {
            Ok(Ok(result)) => Ok(result),
            _ => {
                self.pending.lock().await.remove(&command_id);
                Err(CommandDispatchError::Timeout)
            }
        }
    }

    pub async fn complete(&self, server_id: &str, result: CommandResult) -> bool {
        let mut pending = self.pending.lock().await;
        let matches = pending
            .get(&result.command_id)
            .is_some_and(|command| command.server_id == server_id);
        if !matches {
            return false;
        }
        let Some(command) = pending.remove(&result.command_id) else {
            return false;
        };
        command.result.send(result).is_ok()
    }
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
