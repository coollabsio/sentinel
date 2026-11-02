//! Node volumes (decision 0007). Sentinel validates every field; these
//! handlers only map the JSON from Coolify.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    VolumeDeleteRequest, VolumeObservation, VolumeReceiveRequest, VolumeServeRequest,
    WorkloadVolumeMount,
};
use sentinel_protocol::{
    CAPABILITY_VOLUME_DELETE, CAPABILITY_VOLUME_RECEIVE, CAPABILITY_VOLUME_SERVE,
};
use serde::{Deserialize, Serialize};

use super::{ApiError, ApiState, LIFECYCLE_TIMEOUT, dispatch_with_timeout};

#[derive(Deserialize)]
pub(super) struct DeployMount {
    volume_name: String,
    container_path: String,
    #[serde(default)]
    read_only: bool,
}

impl DeployMount {
    pub(super) fn protocol(self) -> WorkloadVolumeMount {
        WorkloadVolumeMount {
            volume_name: self.volume_name,
            container_path: self.container_path,
            read_only: self.read_only,
        }
    }
}

#[derive(Serialize)]
pub(super) struct VolumeResponse {
    name: String,
    labels: std::collections::HashMap<String, String>,
    created_at_unix_ms: Option<i64>,
}

impl From<VolumeObservation> for VolumeResponse {
    fn from(volume: VolumeObservation) -> Self {
        Self {
            name: volume.name,
            labels: volume.labels,
            created_at_unix_ms: volume.created_at_unix_ms,
        }
    }
}

#[derive(Deserialize)]
pub(super) struct VolumeDeleteApiRequest {
    server_id: String,
    command_id: String,
    names: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct VolumeServeApiRequest {
    server_id: String,
    command_id: String,
    transfer_id: String,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    peer_ip: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    expires_at_unix_ms: i64,
    #[serde(default)]
    stop: bool,
}

#[derive(Deserialize)]
pub(super) struct VolumeReceiveApiRequest {
    server_id: String,
    command_id: String,
    transfer_id: String,
    pass: String,
    source_address: String,
    source_port: u32,
    secret: String,
    names: Vec<String>,
}

fn invalid_response() -> ApiError {
    (StatusCode::BAD_GATEWAY, "invalid Sentinel response").into()
}

pub(super) async fn volume_delete(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<VolumeDeleteApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_VOLUME_DELETE,
        Payload::VolumeDelete(VolumeDeleteRequest {
            names: request.names,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::VolumeDelete(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "deleted": value.deleted,
        "missing": value.missing,
    })))
}

/// Starts, repeats or stops the rsync daemon of a transfer on the source Node.
/// Measuring the used size walks every file, so it can take a while.
pub(super) async fn volume_serve(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<VolumeServeApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_VOLUME_SERVE,
        Payload::VolumeServe(VolumeServeRequest {
            transfer_id: request.transfer_id,
            names: request.names,
            peer_ip: request.peer_ip,
            secret: request.secret,
            expires_at_unix_ms: request.expires_at_unix_ms,
            stop: request.stop,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::VolumeServe(value)) = result.payload else {
        return Err(invalid_response());
    };
    let volumes = value
        .volumes
        .into_iter()
        .map(|volume| {
            serde_json::json!({
                "name": volume.name,
                "used_bytes": volume.used_bytes,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "address": value.address,
        "port": value.port,
        "volumes": volumes,
    })))
}

/// Starts a copy pass on the target Node, or reads its state. It never waits
/// for the copy.
pub(super) async fn volume_receive(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<VolumeReceiveApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_VOLUME_RECEIVE,
        Payload::VolumeReceive(VolumeReceiveRequest {
            transfer_id: request.transfer_id,
            pass: request.pass,
            source_address: request.source_address,
            source_port: request.source_port,
            secret: request.secret,
            names: request.names,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::VolumeReceive(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "state": value.state,
        "bytes_total": value.bytes_total,
        "bytes_done": value.bytes_done,
        "error": value.error,
    })))
}
