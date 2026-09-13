use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    Command, CommandStatus, ContainerListRequest, ContainerPort, CorrosionInspectRequest,
    CorrosionReconcileRequest, FirewallInspectRequest, FirewallReconcileRequest, FirewallRule,
    SystemInfoRequest, SystemPingRequest, WireguardInspectRequest, WireguardKeyEnsureRequest,
    WireguardPeer, WireguardReconcileRequest, WorkloadDeployRequest, WorkloadEnvironmentVariable,
    WorkloadLabel, WorkloadLifecycleAction, WorkloadLifecycleRequest,
};
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_CORROSION_INSPECT, CAPABILITY_CORROSION_RECONCILE,
    CAPABILITY_FIREWALL_INSPECT, CAPABILITY_FIREWALL_RECONCILE, CAPABILITY_SYSTEM_INFO,
    CAPABILITY_SYSTEM_PING, CAPABILITY_WIREGUARD_INSPECT, CAPABILITY_WIREGUARD_KEY_ENSURE,
    CAPABILITY_WIREGUARD_RECONCILE, CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_LIFECYCLE,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CommandDispatchError, ConnectionRegistry, now_millis};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

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
struct WorkloadLifecycleApiRequest {
    server_id: String,
    command_id: String,
    name: String,
    action: WorkloadLifecycleApiAction,
}

#[derive(Deserialize)]
struct WireguardKeyApiRequest {
    server_id: String,
    command_id: String,
    interface: String,
}
#[derive(Deserialize)]
struct WireguardInspectApiRequest {
    server_id: String,
    command_id: String,
    interface: String,
    #[serde(default)]
    expected_revision: u64,
    #[serde(default)]
    expected_hash: String,
}
#[derive(Deserialize)]
struct WireguardPeerApiRequest {
    public_key: String,
    endpoint: String,
    allowed_ip: String,
    #[serde(default = "default_keepalive")]
    persistent_keepalive_seconds: u32,
}
fn default_keepalive() -> u32 {
    25
}
#[derive(Deserialize)]
struct WireguardReconcileApiRequest {
    server_id: String,
    command_id: String,
    interface: String,
    address: String,
    listen_port: u32,
    revision: u64,
    peers: Vec<WireguardPeerApiRequest>,
    #[serde(default)]
    flux_probe_host: String,
}
#[derive(Deserialize)]
struct FirewallInspectApiRequest {
    server_id: String,
    command_id: String,
    #[serde(default)]
    expected_revision: u64,
    #[serde(default)]
    expected_hash: String,
}
#[derive(Deserialize)]
struct FirewallRuleApiRequest {
    chain: String,
    expression: String,
}
#[derive(Deserialize)]
struct FirewallReconcileApiRequest {
    server_id: String,
    command_id: String,
    revision: u64,
    wireguard_port: u32,
    cluster_cidr: String,
    wireguard_interface: String,
    #[serde(default)]
    rules: Vec<FirewallRuleApiRequest>,
}
#[derive(Deserialize)]
struct CorrosionInspectApiRequest {
    server_id: String,
    command_id: String,
}
#[derive(Deserialize)]
struct CorrosionReconcileApiRequest {
    server_id: String,
    command_id: String,
    version: String,
    cluster_id: String,
    bind_address: String,
    #[serde(default)]
    peers: Vec<String>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkloadLifecycleApiAction {
    Start,
    Stop,
    Restart,
    Remove,
}

impl WorkloadLifecycleApiAction {
    fn protocol(self) -> WorkloadLifecycleAction {
        match self {
            Self::Start => WorkloadLifecycleAction::Start,
            Self::Stop => WorkloadLifecycleAction::Stop,
            Self::Restart => WorkloadLifecycleAction::Restart,
            Self::Remove => WorkloadLifecycleAction::Remove,
        }
    }
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
pub struct WorkloadLifecycleResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    name: String,
    action: WorkloadLifecycleApiAction,
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
        .route("/v1/commands/workload.lifecycle", post(workload_lifecycle))
        .route(
            "/v1/commands/network.wireguard.key.ensure",
            post(wireguard_key_ensure),
        )
        .route(
            "/v1/commands/network.wireguard.inspect",
            post(wireguard_inspect),
        )
        .route(
            "/v1/commands/network.wireguard.reconcile",
            post(wireguard_reconcile),
        )
        .route(
            "/v1/commands/network.firewall.inspect",
            post(firewall_inspect),
        )
        .route(
            "/v1/commands/network.firewall.reconcile",
            post(firewall_reconcile),
        )
        .route(
            "/v1/commands/discovery.corrosion.inspect",
            post(corrosion_inspect),
        )
        .route(
            "/v1/commands/discovery.corrosion.reconcile",
            post(corrosion_reconcile),
        )
        .with_state(ApiState { registry, token });
    let listen = listener.local_addr()?;
    tracing::info!(%listen, "Flux internal command API is listening");
    axum::serve(listener, router).await
}

async fn dispatch_network(
    state: &ApiState,
    headers: &HeaderMap,
    server_id: &str,
    command_id: &str,
    command_type: &str,
    payload: Payload,
) -> Result<sentinel_protocol::control::v1::CommandResult, (StatusCode, &'static str)> {
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    if authorization != Some(&format!("Bearer {}", state.token)) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if server_id.is_empty()
        || server_id.len() > 255
        || command_id.is_empty()
        || command_id.len() > 128
        || !command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request"));
    }
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            server_id,
            Command {
                command_id: command_id.into(),
                command_type: command_type.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(payload),
                expires_at_unix_ms: now + LIFECYCLE_TIMEOUT.as_millis() as i64,
            },
            LIFECYCLE_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    Ok(result)
}

async fn wireguard_key_ensure(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WireguardKeyApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WIREGUARD_KEY_ENSURE,
        Payload::WireguardKeyEnsure(WireguardKeyEnsureRequest {
            interface: request.interface,
        }),
    )
    .await?;
    let Some(command_result::Payload::WireguardKeyEnsure(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "public_key": value.public_key}),
    ))
}

async fn wireguard_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WireguardInspectApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WIREGUARD_INSPECT,
        Payload::WireguardInspect(WireguardInspectRequest {
            interface: request.interface,
            expected_revision: request.expected_revision,
            expected_hash: request.expected_hash,
        }),
    )
    .await?;
    let Some(command_result::Payload::WireguardInspect(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    let peers = value.peers.into_iter().map(|peer| serde_json::json!({"public_key": peer.public_key, "endpoint": peer.endpoint, "allowed_ips": peer.allowed_ips, "latest_handshake_unix_seconds": peer.latest_handshake_unix_seconds})).collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "interface": value.interface, "public_key": value.public_key, "listen_port": value.listen_port, "applied_revision": value.applied_revision, "configuration_hash": value.configuration_hash, "drifted": value.drifted, "peers": peers}),
    ))
}

async fn wireguard_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WireguardReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let peers = request
        .peers
        .into_iter()
        .map(|peer| WireguardPeer {
            public_key: peer.public_key,
            endpoint: peer.endpoint,
            allowed_ip: peer.allowed_ip,
            persistent_keepalive_seconds: peer.persistent_keepalive_seconds,
        })
        .collect();
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_WIREGUARD_RECONCILE,
        Payload::WireguardReconcile(WireguardReconcileRequest {
            interface: request.interface,
            address: request.address,
            listen_port: request.listen_port,
            revision: request.revision,
            peers,
            flux_probe_host: request.flux_probe_host,
        }),
    )
    .await?;
    let Some(command_result::Payload::WireguardReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    let network = value
        .state
        .ok_or((StatusCode::BAD_GATEWAY, "invalid Sentinel response"))?;
    let peers = network.peers.into_iter().map(|peer| serde_json::json!({"public_key": peer.public_key, "endpoint": peer.endpoint, "allowed_ips": peer.allowed_ips, "latest_handshake_unix_seconds": peer.latest_handshake_unix_seconds})).collect::<Vec<_>>();
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "changed": value.changed, "rollback_cancelled": value.rollback_cancelled, "public_key": network.public_key, "listen_port": network.listen_port, "applied_revision": network.applied_revision, "configuration_hash": network.configuration_hash, "drifted": network.drifted, "peers": peers}),
    ))
}

async fn firewall_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<FirewallInspectApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_FIREWALL_INSPECT,
        Payload::FirewallInspect(FirewallInspectRequest {
            expected_revision: request.expected_revision,
            expected_hash: request.expected_hash,
        }),
    )
    .await?;
    let Some(command_result::Payload::FirewallInspect(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "applied_revision": value.applied_revision, "configuration_hash": value.configuration_hash, "drifted": value.drifted, "table": value.table}),
    ))
}

async fn firewall_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<FirewallReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let rules = request
        .rules
        .into_iter()
        .map(|rule| FirewallRule {
            chain: rule.chain,
            expression: rule.expression,
        })
        .collect();
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_FIREWALL_RECONCILE,
        Payload::FirewallReconcile(FirewallReconcileRequest {
            revision: request.revision,
            wireguard_port: request.wireguard_port,
            cluster_cidr: request.cluster_cidr,
            rules,
            wireguard_interface: request.wireguard_interface,
        }),
    )
    .await?;
    let Some(command_result::Payload::FirewallReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    let network = value
        .state
        .ok_or((StatusCode::BAD_GATEWAY, "invalid Sentinel response"))?;
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "changed": value.changed, "rollback_cancelled": value.rollback_cancelled, "applied_revision": network.applied_revision, "configuration_hash": network.configuration_hash, "drifted": network.drifted, "table": network.table}),
    ))
}

async fn corrosion_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CorrosionInspectApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_CORROSION_INSPECT,
        Payload::CorrosionInspect(CorrosionInspectRequest {}),
    )
    .await?;
    let Some(command_result::Payload::CorrosionInspect(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "version": value.version, "member_state": value.member_state, "endpoint_count": value.endpoint_count, "last_convergence_unix_seconds": value.last_convergence_unix_seconds}),
    ))
}

async fn corrosion_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CorrosionReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_CORROSION_RECONCILE,
        Payload::CorrosionReconcile(CorrosionReconcileRequest {
            version: request.version,
            cluster_id: request.cluster_id,
            bind_address: request.bind_address,
            peers: request.peers,
        }),
    )
    .await?;
    let Some(command_result::Payload::CorrosionReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    let discovery = value
        .state
        .ok_or((StatusCode::BAD_GATEWAY, "invalid Sentinel response"))?;
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "changed": value.changed, "version": discovery.version, "member_state": discovery.member_state, "endpoint_count": discovery.endpoint_count, "last_convergence_unix_seconds": discovery.last_convergence_unix_seconds}),
    ))
}

async fn workload_lifecycle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WorkloadLifecycleApiRequest>,
) -> Result<Json<WorkloadLifecycleResponse>, (StatusCode, &'static str)> {
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
    let action = request.action;
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: request.command_id.clone(),
                command_type: CAPABILITY_WORKLOAD_LIFECYCLE.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::WorkloadLifecycle(WorkloadLifecycleRequest {
                    name: request.name,
                    action: action.protocol().into(),
                })),
                expires_at_unix_ms: now + LIFECYCLE_TIMEOUT.as_millis() as i64,
            },
            LIFECYCLE_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err((StatusCode::BAD_GATEWAY, "Sentinel command failed"));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::WorkloadLifecycle(changed)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    };
    if changed.action != action.protocol() as i32 {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response"));
    }
    Ok(Json(WorkloadLifecycleResponse {
        command_id: request.command_id,
        observed_at_unix_ms,
        name: changed.name,
        action,
    }))
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
