//! The desired set of the workloads of one Node (decision 0026 of Coolify).
//! Flux only maps the JSON from Coolify and stores nothing. Sentinel
//! validates each deploy when it converges.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::CAPABILITY_WORKLOAD_RECONCILE;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    WorkloadDesiredState, WorkloadReconcileRequest, WorkloadSetEntry, WorkloadStatus,
};
use serde::Deserialize;

use super::{
    ApiError, ApiState, LIFECYCLE_TIMEOUT, WorkloadDeploySpec, deploy_request,
    dispatch_with_timeout,
};
use crate::CommandDispatchError;

/// A full set of a Node with many workloads stays below the gRPC message
/// limit of 16 MiB.
pub(super) const RECONCILE_BODY_LIMIT: usize = 15 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000;

#[derive(Deserialize)]
pub(super) struct WorkloadReconcileApiRequest {
    server_id: String,
    command_id: String,
    generation: u64,
    set_hash: String,
    #[serde(default)]
    full: bool,
    #[serde(default)]
    puts: Vec<SetEntryApiRequest>,
    #[serde(default)]
    removes: Vec<String>,
    #[serde(default)]
    releases: Vec<String>,
}

#[derive(Deserialize)]
struct SetEntryApiRequest {
    workload_id: String,
    revision_id: String,
    #[serde(default)]
    configuration_hash: String,
    desired_state: String,
    #[serde(default)]
    network_revision: u64,
    deploy: WorkloadDeploySpec,
    #[serde(default)]
    replaces: String,
    #[serde(default)]
    operation_id: String,
    stop_timeout_seconds: Option<u32>,
    entry_hash: String,
    #[serde(default)]
    redeploy: bool,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
}

/// Stores a change of the desired set on one Node. A Sentinel without
/// `workload.reconcile.v1` gets 409.
pub(super) async fn workload_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WorkloadReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    super::authorize(&state.token, &headers)?;
    if request.puts.len() + request.removes.len() + request.releases.len() > MAX_ENTRIES
        || request.set_hash.len() != 64
        || !request
            .removes
            .iter()
            .chain(&request.releases)
            .all(|id| valid_id(id))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid workload set").into());
    }
    let mut needed = Vec::new();
    let mut puts = Vec::with_capacity(request.puts.len());
    for put in request.puts {
        let desired_state = match put.desired_state.as_str() {
            "running" => WorkloadDesiredState::Running,
            "stopped" => WorkloadDesiredState::Stopped,
            _ => {
                return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid desired state").into());
            }
        };
        if !valid_id(&put.workload_id)
            || !valid_id(&put.revision_id)
            || (!put.operation_id.is_empty() && !valid_id(&put.operation_id))
            || put.entry_hash.is_empty()
            || put.entry_hash.len() > 128
            || put.configuration_hash.len() > 128
        {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid workload set entry",
            )
                .into());
        }
        let (deploy, deploy_needs) = deploy_request(put.deploy)?;
        needed.extend(deploy_needs);
        puts.push(WorkloadSetEntry {
            workload_id: put.workload_id,
            revision_id: put.revision_id,
            configuration_hash: put.configuration_hash,
            desired_state: desired_state as i32,
            network_revision: put.network_revision,
            deploy: Some(deploy),
            replaces: put.replaces,
            operation_id: put.operation_id,
            stop_timeout_seconds: put.stop_timeout_seconds,
            entry_hash: put.entry_hash,
            redeploy: put.redeploy,
        });
    }
    // An older Sentinel ignores unknown deploy fields, as for workload.deploy.
    if !needed.is_empty() {
        let Some(connection) = state.registry.get(&request.server_id).await else {
            return Err(super::dispatch_error(CommandDispatchError::Offline).into());
        };
        if needed
            .iter()
            .any(|capability| !connection.capabilities.iter().any(|c| c == capability))
        {
            return Err(super::dispatch_error(CommandDispatchError::Unsupported).into());
        }
    }
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WORKLOAD_RECONCILE,
        Payload::WorkloadReconcile(WorkloadReconcileRequest {
            generation: request.generation,
            set_hash: request.set_hash,
            full: request.full,
            puts,
            removes: request.removes,
            releases: request.releases,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::WorkloadReconcile(value)) = result.payload else {
        return Err(super::volume::invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "generation": value.generation,
        "set_hash": value.set_hash,
        "accepted": value.accepted,
        "statuses": value.statuses.iter().map(status_json).collect::<Vec<_>>(),
    })))
}

fn status_json(status: &WorkloadStatus) -> serde_json::Value {
    serde_json::json!({
        "workload_id": status.workload_id,
        "revision_id": status.revision_id,
        "operation_id": status.operation_id,
        "status": crate::reporter::workload_status_name(status.status),
        "reason": status.reason,
        "generation": status.generation,
        "container_name": status.container_name,
        "runtime_id": status.runtime_id,
        "observed_at_unix_ms": status.observed_at_unix_ms,
    })
}
