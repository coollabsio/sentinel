use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sentinel_protocol::control::v1::{ControlMessage, ShutdownHint, control_message};
use tokio::sync::{RwLock, mpsc};

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
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
