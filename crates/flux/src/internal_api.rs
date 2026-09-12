use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    Command, CommandStatus, ContainerListRequest, ContainerPort, SystemInfoRequest,
    SystemPingRequest, WorkloadDeployRequest, WorkloadEnvironmentVariable, WorkloadLabel,
};
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING,
    CAPABILITY_WORKLOAD_DEPLOY,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CommandDispatchError, ConnectionRegistry, now_millis};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct ApiState {
    registry: ConnectionRegistry,
    token: String,
}

#[derive(Deserialize)]
struct PingRequest {
    server_id: String,
}

#[derive(Deserialize)]
struct SystemInfoApiRequest {
    server_id: String,
}

#[derive(Deserialize)]
struct ContainerListApiRequest {
    server_id: String,
}

#[derive(Deserialize)]
struct WorkloadDeployApiRequest {
    server_id: String,
    command_id: String,
    name: String,
    image: String,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    environment: std::collections::HashMap<String, String>,
    #[serde(default)]
    ports: Vec<DeployPort>,
    #[serde(default)]
    labels: std::collections::HashMap<String, String>,
    restart_policy: String,
}

#[derive(Deserialize)]
struct DeployPort {
    host_ip: Option<String>,
    host_port: Option<u32>,
    container_port: u32,
    protocol: String,
}

#[derive(Serialize)]
pub struct PingResponse {
    command_id: String,
    nonce: String,
    sentinel_time_unix_ms: i64,
    sentinel_version: String,
    boot_id: String,
}

#[derive(Serialize)]
pub struct SystemInfoResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    hostname: Option<String>,
    operating_system: Option<String>,
    operating_system_version: Option<String>,
    kernel_version: Option<String>,
    architecture: Option<String>,
    cpu_count: Option<u32>,
    memory_bytes: Option<u64>,
    disk_total_bytes: Option<u64>,
    disk_available_bytes: Option<u64>,
    sentinel_version: String,
    boot_id: Option<String>,
    uptime_seconds: Option<u64>,
    container_runtime: Option<String>,
    container_runtime_version: Option<String>,
}

#[derive(Serialize)]
pub struct ContainerListResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    containers: Vec<ContainerResponse>,
}

#[derive(Serialize)]
pub struct WorkloadDeployResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    runtime_id: String,
    name: String,
    image: String,
}

#[derive(Serialize)]
struct ContainerResponse {
    runtime_id: String,
    name: String,
    image: String,
    state: String,
    health_status: Option<String>,
    restart_count: Option<u32>,
    ports: Vec<ContainerPortResponse>,
    labels: std::collections::HashMap<String, String>,
    created_at_unix_ms: Option<i64>,
    started_at_unix_ms: Option<i64>,
}

#[derive(Serialize)]
struct ContainerPortResponse {
    host_ip: Option<String>,
    host_port: Option<u32>,
    container_port: u32,
    protocol: String,
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    registry: ConnectionRegistry,
    token: String,
) -> Result<(), std::io::Error> {
    let router = Router::new()
        .route("/v1/commands/system.ping", post(ping))
        .route("/v1/commands/system.info", post(system_info))
        .route("/v1/commands/container.list", post(container_list))
        .route("/v1/commands/workload.deploy", post(workload_deploy))
        .with_state(ApiState { registry, token });
    let listen = listener.local_addr()?;
    tracing::info!(%listen, "Flux internal command API is listening");
    axum::serve(listener, router).await
}

async fn workload_deploy(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WorkloadDeployApiRequest>,
) -> Result<Json<WorkloadDeployResponse>, (StatusCode, &'static str)> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    if authorization != Some(&format!("Bearer {}", state.token)) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if request.server_id.is_empty()
        || request.server_id.len() > 255
        || request.command_id.is_empty()
        || request.command_id.len() > 128
        || !request
            .command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request"));
    }
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: request.command_id.clone(),
                command_type: CAPABILITY_WORKLOAD_DEPLOY.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::WorkloadDeploy(WorkloadDeployRequest {
                    name: request.name,
                    image: request.image,
                    command: request.command,
                    environment: sorted_pairs(request.environment)
                        .into_iter()
                        .map(|(key, value)| WorkloadEnvironmentVariable { key, value })
                        .collect(),
                    ports: request
                        .ports
                        .into_iter()
                        .map(|port| ContainerPort {
                            host_ip: port.host_ip,
                            host_port: port.host_port,
                            container_port: port.container_port,
                            protocol: port.protocol,
                        })
                        .collect(),
                    labels: sorted_pairs(request.labels)
                        .into_iter()
                        .map(|(key, value)| WorkloadLabel { key, value })
                        .collect(),
                    restart_policy: request.restart_policy,
                })),
                expires_at_unix_ms: now + DEPLOY_TIMEOUT.as_millis() as i64,
            },
            DEPLOY_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::WorkloadDeploy(deployed)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    Ok(Json(WorkloadDeployResponse {
        command_id: request.command_id,
        observed_at_unix_ms,
        runtime_id: deployed.runtime_id,
        name: deployed.name,
        image: deployed.image,
    }))
}

fn sorted_pairs(values: std::collections::HashMap<String, String>) -> Vec<(String, String)> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_by(|left, right| left.0.cmp(&right.0));
    values
}

async fn container_list(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ContainerListApiRequest>,
) -> Result<Json<ContainerListResponse>, (StatusCode, &'static str)> {
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
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: command_id.clone(),
                command_type: CAPABILITY_CONTAINER_LIST.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::ContainerList(ContainerListRequest {})),
                expires_at_unix_ms: now + COMMAND_TIMEOUT.as_millis() as i64,
            },
            COMMAND_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::ContainerList(list)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    let containers = list
        .containers
        .into_iter()
        .map(|container| ContainerResponse {
            runtime_id: container.runtime_id,
            name: container.name,
            image: container.image,
            state: container.state,
            health_status: container.health_status,
            restart_count: container.restart_count,
            ports: container
                .ports
                .into_iter()
                .map(|port| ContainerPortResponse {
                    host_ip: port.host_ip,
                    host_port: port.host_port,
                    container_port: port.container_port,
                    protocol: port.protocol,
                })
                .collect(),
            labels: container.labels,
            created_at_unix_ms: container.created_at_unix_ms,
            started_at_unix_ms: container.started_at_unix_ms,
        })
        .collect();

    Ok(Json(ContainerListResponse {
        command_id,
        observed_at_unix_ms,
        containers,
    }))
}

async fn system_info(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<SystemInfoApiRequest>,
) -> Result<Json<SystemInfoResponse>, (StatusCode, &'static str)> {
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
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: command_id.clone(),
                command_type: CAPABILITY_SYSTEM_INFO.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::SystemInfo(SystemInfoRequest {})),
                expires_at_unix_ms: now + COMMAND_TIMEOUT.as_millis() as i64,
            },
            COMMAND_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::SystemInfo(info)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };

    Ok(Json(SystemInfoResponse {
        command_id,
        observed_at_unix_ms,
        hostname: info.hostname,
        operating_system: info.operating_system,
        operating_system_version: info.operating_system_version,
        kernel_version: info.kernel_version,
        architecture: info.architecture,
        cpu_count: info.cpu_count,
        memory_bytes: info.memory_bytes,
        disk_total_bytes: info.disk_total_bytes,
        disk_available_bytes: info.disk_available_bytes,
        sentinel_version: info.sentinel_version,
        boot_id: info.boot_id,
        uptime_seconds: info.uptime_seconds,
        container_runtime: info.container_runtime,
        container_runtime_version: info.container_runtime_version,
    }))
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
