use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sentinel_protocol::control::v1::agent_message;
use sentinel_protocol::control::v1::control_message;
use sentinel_protocol::control::v1::{AgentMessage, CommandAccepted, Heartbeat, Hello};
use sentinel_protocol::{CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::{ClientTlsConfig, Endpoint};
use url::Url;

use crate::Assignment;
use crate::commands::CommandExecutor;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MESSAGE_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FluxTransport {
    Plaintext,
    Tls,
}

impl FluxTransport {
    pub fn from_url(url: &Url) -> Result<Self, FluxConnectionError> {
        match url.scheme() {
            "http" => Ok(Self::Plaintext),
            "https" => Ok(Self::Tls),
            _ => Err(FluxConnectionError::InvalidEndpoint),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FluxConnectionError {
    #[error("invalid Flux endpoint")]
    InvalidEndpoint,
    #[error("invalid Flux credential")]
    InvalidCredential,
    #[error("Flux connection failed")]
    Connection,
    #[error("Flux handshake failed")]
    Handshake,
}

pub async fn connect(
    assignment: &Assignment,
    sentinel_version: &str,
    mut shutdown: watch::Receiver<bool>,
    command_executor: Arc<tokio::sync::Mutex<CommandExecutor>>,
) -> Result<(), FluxConnectionError> {
    let transport = FluxTransport::from_url(assignment.flux_url())?;
    let mut endpoint = Endpoint::from_shared(assignment.flux_url().to_string())
        .map_err(|_| FluxConnectionError::InvalidEndpoint)?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(CONNECT_TIMEOUT);
    if transport == FluxTransport::Tls {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|_| FluxConnectionError::InvalidEndpoint)?;
    }
    let channel = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        result = endpoint.connect() => result.map_err(|_| FluxConnectionError::Connection)?,
    };
    let mut client = sentinel_protocol::control::v1::agent_client::AgentClient::new(channel)
        .max_decoding_message_size(MESSAGE_LIMIT)
        .max_encoding_message_size(MESSAGE_LIMIT);
    let (sender, receiver) = mpsc::channel(32);
    sender
        .send(AgentMessage {
            message: Some(agent_message::Message::Hello(Hello {
                server_id: assignment.server_id().into(),
                sentinel_version: sentinel_version.into(),
                protocol_min: assignment.protocol_min(),
                protocol_max: assignment.protocol_max(),
                capabilities: vec![CAPABILITY_SYSTEM_PING.into(), CAPABILITY_SYSTEM_INFO.into()],
                boot_id: boot_id(),
            })),
        })
        .await
        .map_err(|_| FluxConnectionError::Connection)?;
    let mut request = Request::new(ReceiverStream::new(receiver));
    let authorization = MetadataValue::try_from(format!("Bearer {}", assignment.credential()))
        .map_err(|_| FluxConnectionError::InvalidCredential)?;
    request
        .metadata_mut()
        .insert("authorization", authorization);
    let mut inbound = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        result = client.stream(request) => result.map_err(|_| FluxConnectionError::Handshake)?.into_inner(),
    };
    let welcome = tokio::select! {
        _ = shutdown.changed() => return Ok(()),
        result = tokio::time::timeout(CONNECT_TIMEOUT, inbound.message()) => result.map_err(|_| FluxConnectionError::Handshake)?.map_err(|_| FluxConnectionError::Handshake)?.ok_or(FluxConnectionError::Handshake)?,
    };
    let Some(control_message::Message::Welcome(welcome)) = welcome.message else {
        return Err(FluxConnectionError::Handshake);
    };
    if welcome.protocol_version < assignment.protocol_min()
        || welcome.protocol_version > assignment.protocol_max()
        || welcome.connection_id.is_empty()
    {
        return Err(FluxConnectionError::Handshake);
    }
    tracing::info!(connection_id = %welcome.connection_id, protocol_version = welcome.protocol_version, transport = ?transport, "Sentinel connected to Flux");
    let interval =
        Duration::from_secs(u64::from(welcome.heartbeat_interval_seconds).clamp(10, 120));
    let mut ticker = tokio::time::interval(interval);
    let refresh_after = std::time::Duration::try_from(
        assignment.credential_expires_at()
            - time::Duration::seconds(60)
            - time::OffsetDateTime::now_utc(),
    )
    .unwrap_or(Duration::from_secs(1))
    .max(Duration::from_secs(1));
    let refresh = tokio::time::sleep(refresh_after);
    tokio::pin!(refresh);
    let ping_accepted = welcome
        .accepted_capabilities
        .iter()
        .any(|capability| capability == CAPABILITY_SYSTEM_PING);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            _ = &mut refresh => {
                tracing::info!("Sentinel is refreshing its Flux credential");
                return Ok(());
            }
            _ = ticker.tick() => {
                sender.send(AgentMessage { message: Some(agent_message::Message::Heartbeat(Heartbeat { connection_id: welcome.connection_id.clone(), sent_at_unix_ms: now_millis() })) }).await.map_err(|_| FluxConnectionError::Connection)?;
            }
            message = inbound.message() => match message {
                Ok(Some(message)) => {
                    match message.message {
                        Some(control_message::Message::ShutdownHint(_)) => return Ok(()),
                        Some(control_message::Message::Command(command)) => {
                            let command_id = command.command_id.clone();
                            let execution = command_executor.lock().await.execute(command, ping_accepted);
                            if execution.accepted {
                                sender.send(AgentMessage {
                                    message: Some(agent_message::Message::CommandAccepted(CommandAccepted {
                                        command_id,
                                        accepted_at_unix_ms: now_millis(),
                                    })),
                                }).await.map_err(|_| FluxConnectionError::Connection)?;
                            }
                            sender.send(AgentMessage {
                                message: Some(agent_message::Message::CommandResult(execution.result)),
                            }).await.map_err(|_| FluxConnectionError::Connection)?;
                        }
                        _ => {}
                    }
                }
                _ => return Err(FluxConnectionError::Connection),
            }
        }
    }
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
