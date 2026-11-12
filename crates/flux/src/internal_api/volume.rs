//! Node volumes (decision 0007). Sentinel validates every field; these
//! handlers only map the JSON from Coolify.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    VolumeBackupPartUrl, VolumeBackupRequest, VolumeDeleteRequest, VolumeObservation,
    VolumeReceiveRequest, VolumeRestoreRequest, VolumeServeRequest, WorkloadVolumeMount,
};
use sentinel_protocol::{
    CAPABILITY_VOLUME_BACKUP, CAPABILITY_VOLUME_DELETE, CAPABILITY_VOLUME_RECEIVE,
    CAPABILITY_VOLUME_RESTORE, CAPABILITY_VOLUME_SERVE,
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

#[derive(Deserialize)]
pub(super) struct PartUrl {
    part_number: u32,
    url: String,
}

#[derive(Deserialize)]
pub(super) struct VolumeBackupApiRequest {
    server_id: String,
    command_id: String,
    backup_id: String,
    volume_name: String,
    #[serde(default)]
    stop_container: String,
    #[serde(default)]
    stop_timeout_seconds: u32,
    #[serde(default)]
    part_urls: Vec<PartUrl>,
    #[serde(default)]
    abort: bool,
}

#[derive(Deserialize)]
pub(super) struct VolumeRestoreApiRequest {
    server_id: String,
    command_id: String,
    restore_id: String,
    step: String,
    volume_name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    archive_bytes: u64,
    #[serde(default)]
    target_volume_name: String,
}

/// Starts a volume backup on the Node, adds part URLs, or reads its state
/// (decision 0009). It never waits for the backup.
pub(super) async fn volume_backup(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<VolumeBackupApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_VOLUME_BACKUP,
        Payload::VolumeBackup(VolumeBackupRequest {
            backup_id: request.backup_id,
            volume_name: request.volume_name,
            stop_container: request.stop_container,
            stop_timeout_seconds: request.stop_timeout_seconds,
            part_urls: request
                .part_urls
                .into_iter()
                .map(|part| VolumeBackupPartUrl {
                    part_number: part.part_number,
                    url: part.url,
                })
                .collect(),
            abort: request.abort,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::VolumeBackup(value)) = result.payload else {
        return Err(invalid_response());
    };
    let parts = value
        .parts
        .into_iter()
        .map(|part| {
            serde_json::json!({
                "part_number": part.part_number,
                "etag": part.etag,
                "size_bytes": part.size_bytes,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "state": value.state,
        "used_bytes": value.used_bytes,
        "part_size_bytes": value.part_size_bytes,
        "next_part_number": value.next_part_number,
        "parts": parts,
        "bytes_done": value.bytes_done,
        "archive_bytes": value.archive_bytes,
        "sha256": value.sha256,
        "error": value.error,
    })))
}

/// Starts or reads a restore download, or switches the data of two volumes
/// (decision 0009).
pub(super) async fn volume_restore(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<VolumeRestoreApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_VOLUME_RESTORE,
        Payload::VolumeRestore(VolumeRestoreRequest {
            restore_id: request.restore_id,
            step: request.step,
            volume_name: request.volume_name,
            url: request.url,
            sha256: request.sha256,
            archive_bytes: request.archive_bytes,
            target_volume_name: request.target_volume_name,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::VolumeRestore(value)) = result.payload else {
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
