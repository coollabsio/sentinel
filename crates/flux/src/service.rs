use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::Stream;
use sentinel_protocol::control::v1::agent_message;
use sentinel_protocol::control::v1::agent_server::Agent;
use sentinel_protocol::control::v1::{AgentMessage, ControlMessage, Welcome, control_message};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{ConnectionRegistry, CredentialVerifier, EventReporter, negotiate, now_millis};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct AgentService {
    verifier: Arc<CredentialVerifier>,
    registry: ConnectionRegistry,
    reporter: EventReporter,
    transport: &'static str,
}

impl AgentService {
    pub fn new(
        verifier: CredentialVerifier,
        registry: ConnectionRegistry,
        reporter: EventReporter,
        transport: &'static str,
    ) -> Self {
        Self {
            verifier: Arc::new(verifier),
            registry,
            reporter,
            transport,
        }
    }

    pub fn into_server(self) -> sentinel_protocol::control::v1::agent_server::AgentServer<Self> {
        sentinel_protocol::control::v1::agent_server::AgentServer::new(self)
            .max_decoding_message_size(MAX_MESSAGE_BYTES)
            .max_encoding_message_size(MAX_MESSAGE_BYTES)
    }
}

#[tonic::async_trait]
impl Agent for AgentService {
    type StreamStream = Pin<Box<dyn Stream<Item = Result<ControlMessage, Status>> + Send>>;

    async fn stream(
        &self,
        request: Request<tonic::Streaming<AgentMessage>>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let credential = bearer_token(request.metadata())
            .ok_or_else(|| Status::unauthenticated("missing credential"))?;
        let claims = self
            .verifier
            .verify(credential)
            .map_err(|_| Status::unauthenticated("invalid credential"))?;
        let mut inbound = request.into_inner();
        let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("Hello timeout"))?
            .map_err(|_| Status::invalid_argument("invalid first message"))?
            .ok_or_else(|| Status::invalid_argument("Hello is required"))?;
        let Some(agent_message::Message::Hello(hello)) = first.message else {
            return Err(Status::invalid_argument("Hello must be the first message"));
        };
        let negotiated = negotiate(&claims, &hello).map_err(Status::failed_precondition)?;
        let connection_id = Uuid::new_v4().to_string();
        let heartbeat_interval = 30_u32;
        let (sender, receiver) = mpsc::channel(32);
        self.registry
            .insert(
                &hello.server_id,
                &connection_id,
                sender.clone(),
                negotiated.protocol_version,
                negotiated.capabilities.clone(),
            )
            .await;
        sender
            .send(ControlMessage {
                message: Some(control_message::Message::Welcome(Welcome {
                    connection_id: connection_id.clone(),
                    protocol_version: negotiated.protocol_version,
                    heartbeat_interval_seconds: heartbeat_interval,
                    accepted_capabilities: negotiated.capabilities.clone(),
                    server_time_unix_ms: now_millis(),
                })),
            })
            .await
            .map_err(|_| Status::unavailable("stream closed"))?;
        self.reporter
            .connected(
                &hello.server_id,
                &connection_id,
                &hello.sentinel_version,
                negotiated.protocol_version,
                hello.trust_bundle_version,
                self.transport,
            )
            .await;

        let registry = self.registry.clone();
        let reporter = self.reporter.clone();
        let server_id = hello.server_id;
        let task_connection_id = connection_id.clone();
        let credential_lifetime = Duration::from_secs(
            claims
                .expires_at
                .saturating_sub(now_millis() / 1_000)
                .max(0) as u64,
        );
        tokio::spawn(async move {
            let timeout = Duration::from_secs(u64::from(heartbeat_interval) * 3);
            let credential_expiry = tokio::time::sleep(credential_lifetime);
            tokio::pin!(credential_expiry);
            loop {
                let message = tokio::select! {
                    _ = &mut credential_expiry => break,
                    result = tokio::time::timeout(timeout, inbound.message()) => match result {
                        Ok(Ok(Some(message))) => message,
                        _ => break,
                    },
                };
                match message.message {
                    Some(agent_message::Message::Heartbeat(heartbeat))
                        if heartbeat.connection_id == task_connection_id =>
                    {
                        if !registry
                            .heartbeat(&server_id, &task_connection_id, heartbeat.sent_at_unix_ms)
                            .await
                        {
                            break;
                        }
                        reporter
                            .heartbeat(&server_id, &task_connection_id, heartbeat.sent_at_unix_ms)
                            .await;
                    }
                    Some(agent_message::Message::CommandAccepted(_)) => {}
                    Some(agent_message::Message::CommandResult(result)) => {
                        registry.complete(&server_id, result).await;
                    }
                    _ => break,
                }
            }
            registry.remove(&server_id, &task_connection_id).await;
            reporter.disconnected(&server_id, &task_connection_id).await;
        });

        Ok(Response::new(Box::pin(
            ReceiverStream::new(receiver).map(Ok),
        )))
    }
}

fn bearer_token(metadata: &tonic::metadata::MetadataMap) -> Option<&str> {
    metadata
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

use tokio_stream::StreamExt;
