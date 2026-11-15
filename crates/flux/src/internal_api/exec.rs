//! Commands and terminals in workload containers (decision 0018).
//!
//! `workload.exec` forwards one poll of a command; Sentinel runs it in the
//! background. A terminal is opened with `POST /v1/terminals` (internal
//! token), which returns a one-time ticket. The terminal server then attaches
//! a WebSocket at `GET /v1/terminals/{session_id}/attach` with the ticket as
//! the bearer token: binary messages are keyboard input, a text message
//! `{"resize":{"cols":C,"rows":R}}` resizes, binary messages back are the
//! output, and a last text message `{"exit_code":N|null,"reason":"..."}`
//! comes before the close.

use std::time::Duration;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    ControlMessage, TerminalInput, TerminalSize, WorkloadExecRequest, WorkloadTerminalRequest,
    control_message, terminal_input,
};
use sentinel_protocol::{CAPABILITY_WORKLOAD_EXEC, CAPABILITY_WORKLOAD_TERMINAL};
use serde::Deserialize;

use super::{ApiError, ApiState, dispatch_with_timeout};
use crate::terminal::TerminalEvent;

/// One poll; Sentinel answers at once, unless an earlier command of the
/// connection is still running.
const EXEC_POLL_TIMEOUT: Duration = Duration::from_secs(30);
const TERMINAL_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// A session whose terminal server does not attach in this time is closed.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const STDIN_FRAME_BYTES: usize = 16 * 1024;
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
pub(super) struct WorkloadExecApiRequest {
    server_id: String,
    command_id: String,
    exec_id: String,
    container: String,
    argv: Vec<String>,
    timeout_seconds: u32,
}

pub(super) async fn workload_exec(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WorkloadExecApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WORKLOAD_EXEC,
        Payload::WorkloadExec(WorkloadExecRequest {
            exec_id: request.exec_id,
            container: request.container,
            argv: request.argv,
            timeout_seconds: request.timeout_seconds,
        }),
        EXEC_POLL_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::WorkloadExec(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "state": value.state,
        "exit_code": value.exit_code,
        "output": String::from_utf8_lossy(&value.output),
        "truncated": value.truncated,
        "timed_out": value.timed_out,
        "error": value.error,
    })))
}

#[derive(Deserialize)]
pub(super) struct TerminalOpenApiRequest {
    server_id: String,
    command_id: String,
    container: String,
    cols: u32,
    rows: u32,
}

pub(super) async fn terminal_open(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<TerminalOpenApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    super::authorize(&state.token, &headers)?;
    let terminals = state.registry.terminals().clone();
    let Some(registered) = terminals.register(&request.server_id) else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "too many terminal sessions",
        )
            .into());
    };
    let opened = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WORKLOAD_TERMINAL,
        Payload::WorkloadTerminal(WorkloadTerminalRequest {
            session_id: registered.session_id.clone(),
            container: request.container,
            cols: request.cols,
            rows: request.rows,
        }),
        TERMINAL_OPEN_TIMEOUT,
    )
    .await;
    if let Err(error) = opened {
        terminals.remove(&registered.session_id);
        // A timed out open can still start on Sentinel.
        close(&state, &request.server_id, &registered.session_id).await;
        return Err(error);
    }
    let session_id = registered.session_id.clone();
    let server_id = request.server_id.clone();
    let deadline_state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(ATTACH_TIMEOUT).await;
        if !deadline_state.registry.terminals().is_attached(&session_id)
            && deadline_state
                .registry
                .terminals()
                .remove(&session_id)
                .is_some()
        {
            close(&deadline_state, &server_id, &session_id).await;
        }
    });
    Ok(Json(serde_json::json!({
        "session_id": registered.session_id,
        "ticket": registered.ticket,
    })))
}

pub(super) async fn terminal_attach(
    State(state): State<ApiState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let ticket = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let Some(attached) = state.registry.terminals().attach(&session_id, ticket) else {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized").into());
    };
    Ok(upgrade
        .max_message_size(MAX_WEBSOCKET_MESSAGE_BYTES)
        .on_upgrade(move |socket| relay(state, session_id, attached, socket)))
}

async fn relay(
    state: ApiState,
    session_id: String,
    attached: crate::terminal::Attached,
    mut socket: WebSocket,
) {
    let server_id = attached.server_id;
    let mut output = attached.output;
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.tick().await;
    let mut exited = false;
    loop {
        tokio::select! {
            event = output.recv() => match event {
                Some(TerminalEvent::Stdout(data)) => {
                    let bytes = data.len() as u32;
                    if socket.send(Message::Binary(data.into())).await.is_err() {
                        break;
                    }
                    send(&state, &server_id, &session_id, terminal_input::Frame::Ack(bytes)).await;
                }
                Some(TerminalEvent::Exit(exit)) => {
                    exited = true;
                    let status = serde_json::json!({ "exit_code": exit.exit_code, "reason": exit.reason });
                    let _ = socket.send(Message::Text(status.to_string().into())).await;
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                None => {
                    let status = serde_json::json!({ "exit_code": null, "reason": "the terminal output stopped" });
                    let _ = socket.send(Message::Text(status.to_string().into())).await;
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            },
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(data))) => {
                    for chunk in data.chunks(STDIN_FRAME_BYTES) {
                        send(&state, &server_id, &session_id, terminal_input::Frame::Stdin(chunk.to_vec())).await;
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Some(size) = resize(&text) {
                        send(&state, &server_id, &session_id, terminal_input::Frame::Resize(size)).await;
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
            },
            _ = keepalive.tick() => {
                send(&state, &server_id, &session_id, terminal_input::Frame::Keepalive(true)).await;
            }
        }
    }
    state.registry.terminals().remove(&session_id);
    if !exited {
        close(&state, &server_id, &session_id).await;
    }
}

fn resize(text: &str) -> Option<TerminalSize> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let size = value.get("resize")?;
    let dimension = |key: &str| {
        size.get(key)
            .and_then(serde_json::Value::as_u64)
            .filter(|value| (1..=1000).contains(value))
            .map(|value| value as u32)
    };
    Some(TerminalSize {
        cols: dimension("cols")?,
        rows: dimension("rows")?,
    })
}

async fn close(state: &ApiState, server_id: &str, session_id: &str) {
    send(
        state,
        server_id,
        session_id,
        terminal_input::Frame::Close(true),
    )
    .await;
}

async fn send(state: &ApiState, server_id: &str, session_id: &str, frame: terminal_input::Frame) {
    state
        .registry
        .send_message(
            server_id,
            CAPABILITY_WORKLOAD_TERMINAL,
            ControlMessage {
                message: Some(control_message::Message::TerminalInput(TerminalInput {
                    session_id: session_id.into(),
                    frame: Some(frame),
                })),
            },
        )
        .await;
}
