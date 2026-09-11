use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sentinel_protocol::CAPABILITY_SYSTEM_PING;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{Command, CommandStatus, SystemPingRequest};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CommandDispatchError, ConnectionRegistry, now_millis};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct ApiState {
    registry: ConnectionRegistry,
    token: String,
}

#[derive(Deserialize)]
struct PingRequest {
    server_id: String,
}

#[derive(Serialize)]
pub struct PingResponse {
    command_id: String,
    nonce: String,
    sentinel_time_unix_ms: i64,
    sentinel_version: String,
    boot_id: String,
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    registry: ConnectionRegistry,
    token: String,
) -> Result<(), std::io::Error> {
    let router = Router::new()
        .route("/v1/commands/system.ping", post(ping))
        .with_state(ApiState { registry, token });
    let listen = listener.local_addr()?;
    tracing::info!(%listen, "Flux internal command API is listening");
    axum::serve(listener, router).await
}

async fn ping(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<PingRequest>,
) -> Result<Json<PingResponse>, (StatusCode, &'static str)> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    if authorization != Some(&format!("Bearer {}", state.token)) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if request.server_id.is_empty() || request.server_id.len() > 255 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid server ID"));
    }
    let command_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: command_id.clone(),
                command_type: CAPABILITY_SYSTEM_PING.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::SystemPing(SystemPingRequest {
                    nonce: nonce.clone(),
                })),
                expires_at_unix_ms: now + COMMAND_TIMEOUT.as_millis() as i64,
            },
            COMMAND_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    let Some(command_result::Payload::SystemPing(ping)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    if ping.nonce != nonce {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel nonce"));
    }

    Ok(Json(PingResponse {
        command_id,
        nonce,
        sentinel_time_unix_ms: ping.sentinel_time_unix_ms,
        sentinel_version: ping.sentinel_version,
        boot_id: ping.boot_id,
    }))
}

fn dispatch_error(error: CommandDispatchError) -> (StatusCode, &'static str) {
    match error {
        CommandDispatchError::Offline => (StatusCode::NOT_FOUND, "server is not connected"),
        CommandDispatchError::Unsupported => (StatusCode::CONFLICT, "command is not supported"),
        CommandDispatchError::Send => (StatusCode::SERVICE_UNAVAILABLE, "connection closed"),
        CommandDispatchError::QueueFull => (StatusCode::SERVICE_UNAVAILABLE, "connection is busy"),
        CommandDispatchError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "command timed out"),
    }
}
