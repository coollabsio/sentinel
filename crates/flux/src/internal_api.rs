use base64::Engine;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    ClusterLeaveRequest, Command, CommandResult, CommandStatus, ContainerListRequest,
    ContainerLogsRequest, ContainerPort, CorrosionInspectRequest, CorrosionReconcileRequest,
    FirewallIngressRule, FirewallInspectRequest, FirewallPublishedPort, FirewallReconcileRequest,
    FirewallRule, FirewallStackRule, IngressHeader, IngressReconcileRequest, IngressRoute,
    LogSource, LogsReadRequest, SystemInfoRequest, SystemPingRequest, TrustBundleUpdateRequest,
    WireguardInspectRequest, WireguardKeyEnsureRequest, WireguardPeer, WireguardReconcileRequest,
    WorkloadDeployRequest, WorkloadEnvironmentVariable, WorkloadFile, WorkloadHealthCheck,
    WorkloadHost, WorkloadLabel, WorkloadLifecycleAction, WorkloadLifecycleRequest, WorkloadName,
    WorkloadSecret, WorkloadSysctl, WorkloadTmpfs, WorkloadUlimit,
};
use sentinel_protocol::{
    CAPABILITY_CLUSTER_LEAVE, CAPABILITY_CONTAINER_LIST, CAPABILITY_CONTAINER_LOGS,
    CAPABILITY_CORROSION_INSPECT, CAPABILITY_CORROSION_RECONCILE, CAPABILITY_FIREWALL_INSPECT,
    CAPABILITY_FIREWALL_RECONCILE, CAPABILITY_INGRESS_RECONCILE, CAPABILITY_INGRESS_ROUTE_OPTIONS,
    CAPABILITY_LOGS_READ, CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING,
    CAPABILITY_TRUST_BUNDLE_UPDATE, CAPABILITY_WIREGUARD_INSPECT, CAPABILITY_WIREGUARD_KEY_ENSURE,
    CAPABILITY_WIREGUARD_RECONCILE, CAPABILITY_WORKLOAD_CONTAINER_SOCKET,
    CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_DNS_SEARCH, CAPABILITY_WORKLOAD_FILES,
    CAPABILITY_WORKLOAD_GPU, CAPABILITY_WORKLOAD_LIFECYCLE, CAPABILITY_WORKLOAD_RUNTIME_OPTIONS,
    CAPABILITY_WORKLOAD_RUNTIME_OPTIONS_V2, CAPABILITY_WORKLOAD_SECRETS_OWNER,
    CAPABILITY_WORKLOAD_USER,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CommandDispatchError, ConnectionRegistry, now_millis};

mod build;
mod database;
mod exec;
mod reconcile;
mod volume;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// Sentinel stops reading container logs after 20 seconds.
const CONTAINER_LOGS_TIMEOUT: Duration = Duration::from_secs(30);
/// Matches Sentinel's `container.logs.v1` limit.
const CONTAINER_LOGS_MAX_LINES: u32 = 10_000;
/// Matches Sentinel's limit. A CA certificate is about 1 KiB.
const MAX_TRUST_BUNDLE_BYTES: usize = 64 * 1024;

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
struct TrustBundleUpdateApiRequest {
    server_id: String,
    command_id: String,
    version: u64,
    bundle_pem: String,
}

#[derive(Deserialize)]
struct LogsReadApiRequest {
    server_id: String,
    source: LogsReadApiSource,
    limit: u32,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum LogsReadApiSource {
    Sentinel,
    Corrosion,
    DiscoveryDns,
}

impl LogsReadApiSource {
    fn protocol(self) -> LogSource {
        match self {
            Self::Sentinel => LogSource::Sentinel,
            Self::Corrosion => LogSource::Corrosion,
            Self::DiscoveryDns => LogSource::DiscoveryDns,
        }
    }
}

#[derive(Deserialize)]
struct ContainerLogsApiRequest {
    server_id: String,
    command_id: String,
    name: String,
    lines: u32,
    #[serde(default)]
    since_unix_seconds: Option<i64>,
}

#[derive(Deserialize)]
struct ContainerListApiRequest {
    server_id: String,
}

#[derive(Deserialize)]
struct ClusterLeaveApiRequest {
    server_id: String,
    command_id: String,
    interface: String,
    owner_node_ip: String,
    #[serde(default)]
    workload_cidrs: Vec<String>,
}

#[derive(Deserialize)]
struct WorkloadDeployApiRequest {
    server_id: String,
    command_id: String,
    #[serde(flatten)]
    spec: WorkloadDeploySpec,
}

/// The container of a deploy, also the `deploy` of a desired set entry.
#[derive(Deserialize)]
pub(crate) struct WorkloadDeploySpec {
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
    #[serde(default)]
    network_name: String,
    #[serde(default)]
    network_subnet: String,
    #[serde(default)]
    container_ip: String,
    #[serde(default)]
    dns_server: String,
    cpu_limit: Option<f64>,
    cpu_reservation: Option<f64>,
    memory_limit_bytes: Option<u64>,
    memory_reservation_bytes: Option<u64>,
    #[serde(default)]
    pull_policy: String,
    #[serde(default)]
    mounts: Vec<volume::DeployMount>,
    #[serde(default)]
    health_check: Option<DeployHealthCheck>,
    #[serde(default)]
    secrets: std::collections::HashMap<String, DeploySecret>,
    #[serde(default)]
    registry_username: String,
    #[serde(default)]
    registry_password: String,
    #[serde(default)]
    dns_search: Vec<String>,
    #[serde(default)]
    files: Vec<DeployFile>,
    /// Paths of `workload.container_socket.v1`. Sentinel validates them. The
    /// socket gives the container root on the Node.
    #[serde(default)]
    container_socket_paths: Vec<String>,
    /// The `user` of `workload.user.v1`. Sentinel validates it.
    #[serde(default)]
    user: String,
    /// The runtime options of `workload.runtime_options.v1` (decision 0028).
    /// Sentinel validates them.
    #[serde(default)]
    shm_size_bytes: Option<u64>,
    #[serde(default)]
    ulimits: Vec<DeployUlimit>,
    #[serde(default)]
    tmpfs: Vec<DeployTmpfs>,
    #[serde(default)]
    stop_timeout_seconds: Option<u32>,
    #[serde(default)]
    tty: bool,
    #[serde(default)]
    stdin_open: bool,
    /// CDI names of `workload.gpu.v1` (decision 0032). Sentinel checks them
    /// against its CDI inventory.
    #[serde(default)]
    cdi_devices: Vec<String>,
    /// The options of `workload.runtime_options.v2` (decision 0032). Sentinel
    /// validates them.
    #[serde(default)]
    user_labels: Vec<DeployUserLabel>,
    #[serde(default)]
    init: bool,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    pids_limit: Option<i64>,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    entrypoint: Vec<String>,
    #[serde(default)]
    extra_hosts: Vec<DeployHost>,
    #[serde(default)]
    cap_add: Vec<String>,
    #[serde(default)]
    cap_drop: Vec<String>,
    #[serde(default)]
    no_new_privileges: bool,
    #[serde(default)]
    sysctls: Vec<DeploySysctl>,
}

/// A user label of `workload.runtime_options.v2`, in the given order.
#[derive(Deserialize)]
struct DeployUserLabel {
    key: String,
    #[serde(default)]
    value: String,
}

/// An extra host of `workload.runtime_options.v2`.
#[derive(Deserialize)]
struct DeployHost {
    name: String,
    ip: String,
}

/// A sysctl of `workload.runtime_options.v2`.
#[derive(Deserialize)]
struct DeploySysctl {
    name: String,
    value: String,
}

/// A ulimit of `workload.runtime_options.v1`; -1 is unlimited.
#[derive(Deserialize)]
struct DeployUlimit {
    name: String,
    soft: i64,
    hard: i64,
}

/// A tmpfs mount of `workload.runtime_options.v1`; a size of 0 keeps the Podman default.
#[derive(Deserialize)]
struct DeployTmpfs {
    path: String,
    #[serde(default)]
    size_bytes: u64,
}

/// A file of `workload.files.v1`. Sentinel validates the path, mode, and sizes.
#[derive(Deserialize)]
struct DeployFile {
    path: String,
    #[serde(default)]
    content_base64: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    directory: bool,
}

/// Decodes the files of a deploy. A file is at most 1 MiB, so a longer
/// encoding is refused before it is decoded.
fn deploy_files(files: Vec<DeployFile>) -> Result<Vec<WorkloadFile>, (StatusCode, &'static str)> {
    const MAX_FILES: usize = 64;
    const MAX_ENCODED_BYTES: usize = (1024 * 1024usize).div_ceil(3) * 4;
    if files.len() > MAX_FILES {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "too many files"));
    }
    files
        .into_iter()
        .map(|file| {
            if file.content_base64.len() > MAX_ENCODED_BYTES {
                return Err((StatusCode::UNPROCESSABLE_ENTITY, "a file is too large"));
            }
            let content = base64::engine::general_purpose::STANDARD
                .decode(file.content_base64.as_bytes())
                .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid file content"))?;
            Ok(WorkloadFile {
                path: file.path,
                content,
                mode: file.mode,
                directory: file.directory,
            })
        })
        .collect()
}

/// The files of one deploy are at most 4 MiB, about 5.4 MiB as base64.
const WORKLOAD_DEPLOY_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// The value of a secret file, or the value with the owner and the mode of
/// the file (`workload.secrets.owner.v1`). An unset field keeps the Podman
/// default.
#[derive(Deserialize)]
#[serde(untagged)]
enum DeploySecret {
    Value(String),
    File {
        value: String,
        uid: Option<u32>,
        gid: Option<u32>,
        mode: Option<u32>,
    },
}

impl DeploySecret {
    fn protocol(self, key: String) -> WorkloadSecret {
        match self {
            Self::Value(value) => WorkloadSecret {
                key,
                value,
                ..Default::default()
            },
            Self::File {
                value,
                uid,
                gid,
                mode,
            } => WorkloadSecret {
                key,
                value,
                uid,
                gid,
                mode,
            },
        }
    }
}

#[derive(Deserialize)]
struct DeployHealthCheck {
    command: String,
    interval_seconds: u32,
    timeout_seconds: u32,
    retries: u32,
    start_period_seconds: u32,
}

/// Validates a workload image pull policy. The default (`missing`) is
/// canonicalized to an empty string so default deploy commands encode exactly
/// as they did before the field existed, keeping command journal replay stable.
pub(crate) fn workload_pull_policy(value: &str) -> Result<String, (StatusCode, &'static str)> {
    match value {
        "" | "missing" => Ok(String::new()),
        "newer" | "always" => Ok(value.into()),
        _ => Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid pull policy")),
    }
}

#[derive(Deserialize)]
struct WorkloadLifecycleApiRequest {
    server_id: String,
    command_id: String,
    name: String,
    action: WorkloadLifecycleApiAction,
    #[serde(default)]
    stop_timeout_seconds: Option<u32>,
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
    allowed_ips: Vec<String>,
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
    source_ip: String,
    destination_ip: String,
    protocol: String,
    port: u32,
}
#[derive(Deserialize)]
struct FirewallIngressRuleApiRequest {
    destination_ip: String,
    protocol: String,
    port: u32,
}
#[derive(Deserialize)]
struct FirewallReconcileApiRequest {
    server_id: String,
    command_id: String,
    revision: u64,
    wireguard_port: u32,
    cluster_cidr: String,
    local_node_ip: String,
    wireguard_interface: String,
    #[serde(default)]
    rules: Vec<FirewallRuleApiRequest>,
    #[serde(default)]
    flux_probe_host: String,
    #[serde(default)]
    workload_cidrs: Vec<String>,
    #[serde(default)]
    ingress_rules: Vec<FirewallIngressRuleApiRequest>,
    #[serde(default)]
    stack_rules: Vec<FirewallStackRuleApiRequest>,
    #[serde(default)]
    published_ports: Vec<FirewallPublishedPortApiRequest>,
}
#[derive(Deserialize)]
struct FirewallStackRuleApiRequest {
    source_ip: String,
    destination_ip: String,
}
#[derive(Deserialize)]
struct FirewallPublishedPortApiRequest {
    protocol: String,
    host_port: u32,
    destination_ip: String,
    container_port: u32,
    #[serde(default)]
    source_cidrs: Vec<String>,
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
    node_dns_name: String,
}

#[derive(Deserialize)]
struct IngressReconcileApiRequest {
    server_id: String,
    command_id: String,
    enabled: bool,
    #[serde(default)]
    caddy_version: String,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    routes: Vec<IngressRouteApiRequest>,
    #[serde(default)]
    names: Vec<WorkloadNameApiRequest>,
    #[serde(default)]
    tls_enabled: bool,
    /// Base64 of the 32-byte cluster TLS key; empty without HTTPS.
    #[serde(default)]
    tls_key: String,
    #[serde(default)]
    tls_issuer: bool,
    #[serde(default)]
    acme_directory_url: String,
    #[serde(default)]
    ingress_public_ips: Vec<String>,
    #[serde(default)]
    acme_ca_pem: String,
}
#[derive(Deserialize)]
struct WorkloadNameApiRequest {
    name: String,
    workload_id: String,
    namespace: String,
}
#[derive(Deserialize)]
struct IngressRouteApiRequest {
    host: String,
    #[serde(default)]
    workload_id: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    path: String,
    #[serde(default)]
    redirect_host: String,
    #[serde(default)]
    http_only: bool,
    #[serde(default)]
    allow_http: bool,
    #[serde(default)]
    temporary_redirect: bool,
    #[serde(default)]
    noindex: bool,
    #[serde(default)]
    strip_path: bool,
    #[serde(default)]
    basic_auth_username: String,
    #[serde(default)]
    basic_auth_password_hash: String,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    request_headers: Vec<IngressHeaderApiRequest>,
    #[serde(default)]
    response_headers: Vec<IngressHeaderApiRequest>,
    #[serde(default)]
    compress: bool,
}

#[derive(Deserialize)]
struct IngressHeaderApiRequest {
    name: String,
    value: String,
}

impl IngressHeaderApiRequest {
    fn protocol(self) -> IngressHeader {
        IngressHeader {
            name: self.name,
            value: self.value,
        }
    }
}

impl IngressRouteApiRequest {
    fn has_options(&self) -> bool {
        !self.basic_auth_username.is_empty()
            || !self.basic_auth_password_hash.is_empty()
            || !self.allowed_ips.is_empty()
            || !self.request_headers.is_empty()
            || !self.response_headers.is_empty()
            || self.compress
    }
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
    cpu_usage_percent: Option<f64>,
    memory_used_bytes: Option<u64>,
    memory_available_bytes: Option<u64>,
    load_average_one: Option<f64>,
    load_average_five: Option<f64>,
    load_average_fifteen: Option<f64>,
    ingress_certificates: Vec<IngressCertificateStatusResponse>,
    gpu_cdi_devices: Vec<String>,
    gpu_cdi_check: String,
}

#[derive(Serialize)]
pub struct IngressCertificateStatusResponse {
    host: String,
    status: String,
    not_after: i64,
    error: String,
    next_attempt_at: i64,
}

#[derive(Serialize)]
pub struct LogsReadResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    source: LogsReadApiSource,
    truncated: bool,
    events: Vec<LogEventResponse>,
}

#[derive(Serialize)]
struct LogEventResponse {
    timestamp_unix_ms: i64,
    level: String,
    component: String,
    message: String,
    fields: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct ContainerLogsResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    name: String,
    logs: String,
    truncated: bool,
}

#[derive(Serialize)]
pub struct ContainerListResponse {
    command_id: String,
    observed_at_unix_ms: i64,
    containers: Vec<ContainerResponse>,
    volumes: Vec<volume::VolumeResponse>,
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
    exit_code: Option<i32>,
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
        .route("/v1/commands/logs.read", post(logs_read))
        .route("/v1/commands/container.logs", post(container_logs))
        .route(
            "/v1/commands/trust.bundle.update",
            post(trust_bundle_update),
        )
        .route("/v1/commands/network.cluster.leave", post(cluster_leave))
        .route(
            "/v1/commands/workload.deploy",
            post(workload_deploy).layer(axum::extract::DefaultBodyLimit::max(
                WORKLOAD_DEPLOY_BODY_LIMIT,
            )),
        )
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
        .route("/v1/commands/ingress.reconcile", post(ingress_reconcile))
        .route("/v1/commands/image.build", post(build::image_build))
        .route("/v1/commands/image.load", post(build::image_load))
        .route("/v1/commands/image.serve", post(build::image_serve))
        .route("/v1/commands/image.fetch", post(build::image_fetch))
        .route("/v1/commands/image.prune", post(build::image_prune))
        .route(
            "/v1/commands/workload.reconcile",
            post(reconcile::workload_reconcile).layer(axum::extract::DefaultBodyLimit::max(
                reconcile::RECONCILE_BODY_LIMIT,
            )),
        )
        .route(
            "/v1/commands/builder.reconcile",
            post(build::builder_reconcile),
        )
        .route("/v1/commands/volume.delete", post(volume::volume_delete))
        .route("/v1/commands/volume.serve", post(volume::volume_serve))
        .route("/v1/commands/volume.receive", post(volume::volume_receive))
        .route("/v1/commands/volume.backup", post(volume::volume_backup))
        .route("/v1/commands/volume.restore", post(volume::volume_restore))
        .route("/v1/commands/database.dump", post(database::database_dump))
        .route(
            "/v1/commands/database.restore",
            post(database::database_restore),
        )
        .route("/v1/commands/workload.exec", post(exec::workload_exec))
        .route("/v1/terminals", post(exec::terminal_open))
        .route(
            "/v1/terminals/{session_id}/attach",
            axum::routing::get(exec::terminal_attach),
        )
        .with_state(ApiState { registry, token });
    let listen = listener.local_addr()?;
    tracing::info!(%listen, "Flux internal command API is listening");
    axum::serve(listener, router).await
}

async fn cluster_leave(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ClusterLeaveApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_CLUSTER_LEAVE,
        Payload::ClusterLeave(ClusterLeaveRequest {
            interface: request.interface,
            owner_node_ip: request.owner_node_ip,
            workload_cidrs: request.workload_cidrs,
        }),
    )
    .await?;
    let Some(command_result::Payload::ClusterLeave(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "wireguard_removed": value.wireguard_removed,
        "firewall_removed": value.firewall_removed,
        "discovery_removed": value.discovery_removed,
        "resolver_reverted": value.resolver_reverted,
    })))
}

/// Forwards a Flux CA trust bundle to Sentinel. The bundle holds public CA
/// certificates only; Sentinel validates it before installing.
async fn trust_bundle_update(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<TrustBundleUpdateApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.version == 0
        || request.bundle_pem.trim().is_empty()
        || request.bundle_pem.len() > MAX_TRUST_BUNDLE_BYTES
    {
        authorize(&state.token, &headers)?;
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid trust bundle").into());
    }
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_TRUST_BUNDLE_UPDATE,
        Payload::TrustBundleUpdate(TrustBundleUpdateRequest {
            version: request.version,
            bundle_pem: request.bundle_pem,
        }),
    )
    .await?;
    let Some(command_result::Payload::TrustBundleUpdate(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    if value.installed_version != request.version {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    }
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "installed_version": value.installed_version,
        "changed": value.changed,
    })))
}

async fn dispatch_network(
    state: &ApiState,
    headers: &HeaderMap,
    server_id: &str,
    command_id: &str,
    command_type: &str,
    payload: Payload,
) -> Result<sentinel_protocol::control::v1::CommandResult, ApiError> {
    dispatch_with_timeout(
        state,
        headers,
        server_id,
        command_id,
        command_type,
        payload,
        LIFECYCLE_TIMEOUT,
    )
    .await
}

async fn dispatch_with_timeout(
    state: &ApiState,
    headers: &HeaderMap,
    server_id: &str,
    command_id: &str,
    command_type: &str,
    payload: Payload,
    timeout: Duration,
) -> Result<sentinel_protocol::control::v1::CommandResult, ApiError> {
    authorize(&state.token, headers)?;
    if server_id.is_empty()
        || server_id.len() > 255
        || command_id.is_empty()
        || command_id.len() > 128
        || !command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request").into());
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
                expires_at_unix_ms: now + timeout.as_millis() as i64,
            },
            timeout,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err(command_failed(result));
    }
    Ok(result)
}

async fn wireguard_key_ensure(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WireguardKeyApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "public_key": value.public_key}),
    ))
}

async fn wireguard_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WireguardInspectApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
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
) -> Result<Json<serde_json::Value>, ApiError> {
    let peers = request
        .peers
        .into_iter()
        .map(|peer| WireguardPeer {
            public_key: peer.public_key,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
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
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
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
) -> Result<Json<serde_json::Value>, ApiError> {
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
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "applied_revision": value.applied_revision, "configuration_hash": value.configuration_hash, "drifted": value.drifted, "table": value.table, "ingress_enforced": value.ingress_enforced}),
    ))
}

async fn firewall_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<FirewallReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = request
        .rules
        .into_iter()
        .map(|rule| FirewallRule {
            source_ip: rule.source_ip,
            destination_ip: rule.destination_ip,
            protocol: rule.protocol,
            port: rule.port,
        })
        .collect();
    let ingress_rules = request
        .ingress_rules
        .into_iter()
        .map(|rule| FirewallIngressRule {
            destination_ip: rule.destination_ip,
            protocol: rule.protocol,
            port: rule.port,
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
            local_node_ip: request.local_node_ip,
            rules,
            wireguard_interface: request.wireguard_interface,
            flux_probe_host: request.flux_probe_host,
            workload_cidrs: request.workload_cidrs,
            ingress_rules,
            stack_rules: request
                .stack_rules
                .into_iter()
                .map(|rule| FirewallStackRule {
                    source_ip: rule.source_ip,
                    destination_ip: rule.destination_ip,
                })
                .collect(),
            published_ports: request
                .published_ports
                .into_iter()
                .map(|port| FirewallPublishedPort {
                    protocol: port.protocol,
                    host_port: port.host_port,
                    destination_ip: port.destination_ip,
                    container_port: port.container_port,
                    source_cidrs: port.source_cidrs,
                })
                .collect(),
        }),
    )
    .await?;
    let Some(command_result::Payload::FirewallReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    let network = value
        .state
        .ok_or((StatusCode::BAD_GATEWAY, "invalid Sentinel response"))?;
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "changed": value.changed, "rollback_cancelled": value.rollback_cancelled, "applied_revision": network.applied_revision, "configuration_hash": network.configuration_hash, "drifted": network.drifted, "table": network.table, "ingress_enforced": network.ingress_enforced}),
    ))
}

async fn corrosion_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CorrosionInspectApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "version": value.version, "member_state": value.member_state, "endpoint_count": value.endpoint_count, "last_convergence_unix_seconds": value.last_convergence_unix_seconds, "alive_member_count": value.alive_member_count}),
    ))
}

async fn corrosion_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<CorrosionReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
            node_dns_name: request.node_dns_name,
        }),
    )
    .await?;
    let Some(command_result::Payload::CorrosionReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    let discovery = value
        .state
        .ok_or((StatusCode::BAD_GATEWAY, "invalid Sentinel response"))?;
    Ok(Json(
        serde_json::json!({"command_id": request.command_id, "observed_at_unix_ms": result.observed_at_unix_ms, "changed": value.changed, "version": discovery.version, "member_state": discovery.member_state, "endpoint_count": discovery.endpoint_count, "last_convergence_unix_seconds": discovery.last_convergence_unix_seconds, "alive_member_count": discovery.alive_member_count}),
    ))
}

/// Forwards the HTTP ingress state, route table and internal names to one
/// Node. Sentinel validates them and the pinned Caddy version.
async fn ingress_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<IngressReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authorize(&state.token, &headers)?;
    let tls_key = base64::engine::general_purpose::STANDARD
        .decode(&request.tls_key)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "invalid TLS key"))?;
    // An older Sentinel ignores the options and would serve the route without
    // its basic auth or IP allow list.
    if request
        .routes
        .iter()
        .any(IngressRouteApiRequest::has_options)
    {
        let Some(connection) = state.registry.get(&request.server_id).await else {
            return Err(dispatch_error(CommandDispatchError::Offline).into());
        };
        if !connection
            .capabilities
            .iter()
            .any(|capability| capability == CAPABILITY_INGRESS_ROUTE_OPTIONS)
        {
            return Err(dispatch_error(CommandDispatchError::Unsupported).into());
        }
    }
    let result = dispatch_network(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_INGRESS_RECONCILE,
        Payload::IngressReconcile(IngressReconcileRequest {
            enabled: request.enabled,
            caddy_version: request.caddy_version,
            revision: request.revision,
            routes: request
                .routes
                .into_iter()
                .map(|route| IngressRoute {
                    host: route.host,
                    workload_id: route.workload_id,
                    namespace: route.namespace,
                    port: route.port,
                    path: route.path,
                    redirect_host: route.redirect_host,
                    http_only: route.http_only,
                    allow_http: route.allow_http,
                    temporary_redirect: route.temporary_redirect,
                    noindex: route.noindex,
                    strip_path: route.strip_path,
                    basic_auth_username: route.basic_auth_username,
                    basic_auth_password_hash: route.basic_auth_password_hash,
                    allowed_ips: route.allowed_ips,
                    request_headers: route
                        .request_headers
                        .into_iter()
                        .map(IngressHeaderApiRequest::protocol)
                        .collect(),
                    response_headers: route
                        .response_headers
                        .into_iter()
                        .map(IngressHeaderApiRequest::protocol)
                        .collect(),
                    compress: route.compress,
                })
                .collect(),
            names: request
                .names
                .into_iter()
                .map(|name| WorkloadName {
                    name: name.name,
                    workload_id: name.workload_id,
                    namespace: name.namespace,
                })
                .collect(),
            tls_enabled: request.tls_enabled,
            tls_key,
            tls_issuer: request.tls_issuer,
            acme_directory_url: request.acme_directory_url,
            ingress_public_ips: request.ingress_public_ips,
            acme_ca_pem: request.acme_ca_pem,
        }),
    )
    .await?;
    let Some(command_result::Payload::IngressReconcile(value)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "enabled": value.enabled,
        "caddy_version": value.caddy_version,
        "active": value.active,
        "revision": value.revision,
        "route_count": value.route_count,
        "name_count": value.name_count,
        "tls_enabled": value.tls_enabled,
    })))
}

async fn workload_lifecycle(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<WorkloadLifecycleApiRequest>,
) -> Result<Json<WorkloadLifecycleResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty()
        || request.server_id.len() > 255
        || request.command_id.is_empty()
        || request.command_id.len() > 128
        || !request
            .command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request").into());
    }
    if request
        .stop_timeout_seconds
        .is_some_and(|seconds| !(1..=600).contains(&seconds))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid stop timeout").into());
    }
    let now = now_millis();
    let action = request.action;
    // The command waits for the stop timeout, so the wait for its result grows with it.
    let timeout = LIFECYCLE_TIMEOUT.max(Duration::from_secs(
        u64::from(request.stop_timeout_seconds.unwrap_or(0)) + 60,
    ));
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
                    stop_timeout_seconds: request.stop_timeout_seconds,
                })),
                expires_at_unix_ms: now + timeout.as_millis() as i64,
            },
            timeout,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::WorkloadLifecycle(changed)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    if changed.action != action.protocol() as i32 {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
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
) -> Result<Json<WorkloadDeployResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty()
        || request.server_id.len() > 255
        || request.command_id.is_empty()
        || request.command_id.len() > 128
        || !request
            .command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request").into());
    }
    let (deploy, needed) = deploy_request(request.spec)?;
    // An older Sentinel ignores the fields and would start the container
    // without its files, search domains, secret file owners, or socket.
    if !needed.is_empty() {
        let Some(connection) = state.registry.get(&request.server_id).await else {
            return Err(dispatch_error(CommandDispatchError::Offline).into());
        };
        if needed
            .iter()
            .any(|capability| !connection.capabilities.iter().any(|c| c == capability))
        {
            return Err(dispatch_error(CommandDispatchError::Unsupported).into());
        }
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
                payload: Some(Payload::WorkloadDeploy(deploy)),
                expires_at_unix_ms: now + DEPLOY_TIMEOUT.as_millis() as i64,
            },
            DEPLOY_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::WorkloadDeploy(deployed)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    Ok(Json(WorkloadDeployResponse {
        command_id: request.command_id,
        observed_at_unix_ms,
        runtime_id: deployed.runtime_id,
        name: deployed.name,
        image: deployed.image,
    }))
}

/// Converts the container of a deploy to the protocol, with the capabilities
/// that its fields need on top of `workload.deploy.v1`.
pub(crate) fn deploy_request(
    spec: WorkloadDeploySpec,
) -> Result<(WorkloadDeployRequest, Vec<&'static str>), ApiError> {
    let pull_policy = workload_pull_policy(&spec.pull_policy)?;
    let files = deploy_files(spec.files)?;
    let mut secrets: Vec<_> = spec
        .secrets
        .into_iter()
        .map(|(key, secret)| secret.protocol(key))
        .collect();
    secrets.sort_by(|left, right| left.key.cmp(&right.key));
    let needed = [
        (!spec.dns_search.is_empty()).then_some(CAPABILITY_WORKLOAD_DNS_SEARCH),
        (!files.is_empty()).then_some(CAPABILITY_WORKLOAD_FILES),
        (!spec.container_socket_paths.is_empty()).then_some(CAPABILITY_WORKLOAD_CONTAINER_SOCKET),
        (!spec.user.is_empty()).then_some(CAPABILITY_WORKLOAD_USER),
        (spec.shm_size_bytes.is_some()
            || !spec.ulimits.is_empty()
            || !spec.tmpfs.is_empty()
            || spec.stop_timeout_seconds.is_some()
            || spec.tty
            || spec.stdin_open)
            .then_some(CAPABILITY_WORKLOAD_RUNTIME_OPTIONS),
        (!spec.user_labels.is_empty()
            || spec.init
            || spec.read_only
            || spec.pids_limit.is_some()
            || !spec.hostname.is_empty()
            || !spec.entrypoint.is_empty()
            || !spec.extra_hosts.is_empty()
            || !spec.cap_add.is_empty()
            || !spec.cap_drop.is_empty()
            || spec.no_new_privileges
            || !spec.sysctls.is_empty())
        .then_some(CAPABILITY_WORKLOAD_RUNTIME_OPTIONS_V2),
        (!spec.cdi_devices.is_empty()).then_some(CAPABILITY_WORKLOAD_GPU),
        secrets
            .iter()
            .any(|secret| secret.uid.is_some() || secret.gid.is_some() || secret.mode.is_some())
            .then_some(CAPABILITY_WORKLOAD_SECRETS_OWNER),
    ]
    .into_iter()
    .flatten()
    .collect();
    let deploy = WorkloadDeployRequest {
        name: spec.name,
        image: spec.image,
        command: spec.command,
        environment: sorted_pairs(spec.environment)
            .into_iter()
            .map(|(key, value)| WorkloadEnvironmentVariable { key, value })
            .collect(),
        ports: spec
            .ports
            .into_iter()
            .map(|port| ContainerPort {
                host_ip: port.host_ip,
                host_port: port.host_port,
                container_port: port.container_port,
                protocol: port.protocol,
            })
            .collect(),
        labels: sorted_pairs(spec.labels)
            .into_iter()
            .map(|(key, value)| WorkloadLabel { key, value })
            .collect(),
        restart_policy: spec.restart_policy,
        network_name: spec.network_name,
        network_subnet: spec.network_subnet,
        container_ip: spec.container_ip,
        dns_server: spec.dns_server,
        cpu_limit: spec.cpu_limit,
        cpu_reservation: spec.cpu_reservation,
        memory_limit_bytes: spec.memory_limit_bytes,
        memory_reservation_bytes: spec.memory_reservation_bytes,
        pull_policy,
        mounts: spec
            .mounts
            .into_iter()
            .map(volume::DeployMount::protocol)
            .collect(),
        health_check: spec.health_check.map(|check| WorkloadHealthCheck {
            command: check.command,
            interval_seconds: check.interval_seconds,
            timeout_seconds: check.timeout_seconds,
            retries: check.retries,
            start_period_seconds: check.start_period_seconds,
        }),
        secrets,
        registry_username: spec.registry_username,
        registry_password: spec.registry_password,
        dns_search: spec.dns_search,
        files,
        container_socket_paths: spec.container_socket_paths,
        user: spec.user,
        shm_size_bytes: spec.shm_size_bytes,
        ulimits: spec
            .ulimits
            .into_iter()
            .map(|ulimit| WorkloadUlimit {
                name: ulimit.name,
                soft: ulimit.soft,
                hard: ulimit.hard,
            })
            .collect(),
        tmpfs: spec
            .tmpfs
            .into_iter()
            .map(|tmpfs| WorkloadTmpfs {
                path: tmpfs.path,
                size_bytes: tmpfs.size_bytes,
            })
            .collect(),
        stop_timeout_seconds: spec.stop_timeout_seconds,
        tty: spec.tty,
        stdin_open: spec.stdin_open,
        cdi_devices: spec.cdi_devices,
        user_labels: spec
            .user_labels
            .into_iter()
            .map(|label| WorkloadLabel {
                key: label.key,
                value: label.value,
            })
            .collect(),
        init: spec.init,
        read_only: spec.read_only,
        pids_limit: spec.pids_limit,
        hostname: spec.hostname,
        entrypoint: spec.entrypoint,
        extra_hosts: spec
            .extra_hosts
            .into_iter()
            .map(|host| WorkloadHost {
                name: host.name,
                ip: host.ip,
            })
            .collect(),
        cap_add: spec.cap_add,
        cap_drop: spec.cap_drop,
        no_new_privileges: spec.no_new_privileges,
        sysctls: spec
            .sysctls
            .into_iter()
            .map(|sysctl| WorkloadSysctl {
                name: sysctl.name,
                value: sysctl.value,
            })
            .collect(),
    };
    Ok((deploy, needed))
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
) -> Result<Json<ContainerListResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty() || request.server_id.len() > 255 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid server ID").into());
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
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::ContainerList(list)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
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
            exit_code: container.exit_code,
        })
        .collect();

    Ok(Json(ContainerListResponse {
        command_id,
        observed_at_unix_ms,
        containers,
        volumes: list
            .volumes
            .into_iter()
            .map(volume::VolumeResponse::from)
            .collect(),
    }))
}

async fn system_info(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<SystemInfoApiRequest>,
) -> Result<Json<SystemInfoResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty() || request.server_id.len() > 255 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid server ID").into());
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
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::SystemInfo(info)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
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
        cpu_usage_percent: info.cpu_usage_percent,
        memory_used_bytes: info.memory_used_bytes,
        memory_available_bytes: info.memory_available_bytes,
        load_average_one: info.load_average_one,
        load_average_five: info.load_average_five,
        load_average_fifteen: info.load_average_fifteen,
        ingress_certificates: info
            .ingress_certificates
            .into_iter()
            .map(|certificate| IngressCertificateStatusResponse {
                host: certificate.host,
                status: certificate.status,
                not_after: certificate.not_after,
                error: certificate.error,
                next_attempt_at: certificate.next_attempt_at,
            })
            .collect(),
        gpu_cdi_devices: info.gpu_cdi_devices,
        gpu_cdi_check: info.gpu_cdi_check,
    }))
}

async fn logs_read(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<LogsReadApiRequest>,
) -> Result<Json<LogsReadResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty() || request.server_id.len() > 255 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid server ID").into());
    }
    if !(1..=500).contains(&request.limit) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid limit").into());
    }
    let command_id = Uuid::new_v4().to_string();
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: command_id.clone(),
                command_type: CAPABILITY_LOGS_READ.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::LogsRead(LogsReadRequest {
                    source: request.source.protocol().into(),
                    limit: request.limit,
                })),
                expires_at_unix_ms: now + COMMAND_TIMEOUT.as_millis() as i64,
            },
            COMMAND_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::LogsRead(logs)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    if logs.source != i32::from(request.source.protocol()) {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    }

    Ok(Json(LogsReadResponse {
        command_id,
        observed_at_unix_ms,
        source: request.source,
        truncated: logs.truncated,
        events: logs
            .events
            .into_iter()
            .map(|event| LogEventResponse {
                timestamp_unix_ms: event.timestamp_unix_ms,
                level: event.level,
                component: event.component,
                message: event.message,
                fields: event.fields.into_iter().collect(),
            })
            .collect(),
    }))
}

/// Reads the newest output of one Coolify-managed container. Sentinel checks
/// the `coolify.managed` label; Flux validates the request shape. Like
/// `logs.read`, the command is not journaled, so a repeated ID reads again.
async fn container_logs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ContainerLogsApiRequest>,
) -> Result<Json<ContainerLogsResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty()
        || request.server_id.len() > 255
        || request.command_id.is_empty()
        || request.command_id.len() > 128
        || !request
            .command_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid command request").into());
    }
    if !sentinel_protocol::valid_container_name(&request.name) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid container name").into());
    }
    if !(1..=CONTAINER_LOGS_MAX_LINES).contains(&request.lines) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid lines").into());
    }
    if request.since_unix_seconds.is_some_and(|since| since <= 0) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid since").into());
    }
    let now = now_millis();
    let result = state
        .registry
        .dispatch(
            &request.server_id,
            Command {
                command_id: request.command_id.clone(),
                command_type: CAPABILITY_CONTAINER_LOGS.into(),
                payload_version: 1,
                created_at_unix_ms: now,
                payload: Some(Payload::ContainerLogs(ContainerLogsRequest {
                    name: request.name.clone(),
                    lines: request.lines,
                    since_unix_seconds: request.since_unix_seconds,
                })),
                expires_at_unix_ms: now + CONTAINER_LOGS_TIMEOUT.as_millis() as i64,
            },
            CONTAINER_LOGS_TIMEOUT,
        )
        .await
        .map_err(dispatch_error)?;
    if result.status != CommandStatus::Succeeded as i32 {
        return Err(command_failed(result));
    }
    let observed_at_unix_ms = result.observed_at_unix_ms;
    let Some(command_result::Payload::ContainerLogs(logs)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    if logs.name != request.name {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    }

    Ok(Json(ContainerLogsResponse {
        command_id: request.command_id,
        observed_at_unix_ms,
        name: logs.name,
        logs: logs.logs,
        truncated: logs.truncated,
    }))
}

async fn ping(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<PingRequest>,
) -> Result<Json<PingResponse>, ApiError> {
    authorize(&state.token, &headers)?;
    if request.server_id.is_empty() || request.server_id.len() > 255 {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "invalid server ID").into());
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
        return Err(command_failed(result));
    }
    let Some(command_result::Payload::SystemPing(ping)) = result.payload else {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel response").into());
    };
    if ping.nonce != nonce {
        return Err((StatusCode::BAD_GATEWAY, "invalid Sentinel nonce").into());
    }

    Ok(Json(PingResponse {
        command_id,
        nonce,
        sentinel_time_unix_ms: ping.sentinel_time_unix_ms,
        sentinel_version: ping.sentinel_version,
        boot_id: ping.boot_id,
    }))
}

/// Checks the internal API bearer token in constant time.
fn authorize(token: &str, headers: &HeaderMap) -> Result<(), ApiError> {
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .as_bytes();
    let expected = token.as_bytes();
    let difference = presented.iter().zip(expected).fold(
        presented.len() ^ expected.len(),
        |difference, (left, right)| difference | usize::from(left ^ right),
    );
    if difference != 0 || expected.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized").into());
    }
    Ok(())
}

/// An internal API error. A failed Sentinel command keeps the message that Sentinel reported.
pub(crate) struct ApiError(StatusCode, String);

impl From<(StatusCode, &'static str)> for ApiError {
    fn from((status, message): (StatusCode, &'static str)) -> Self {
        Self(status, message.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

fn command_failed(result: CommandResult) -> ApiError {
    match result.payload {
        Some(command_result::Payload::Error(error)) if !error.message.trim().is_empty() => {
            ApiError(StatusCode::BAD_GATEWAY, error.message)
        }
        _ => (StatusCode::BAD_GATEWAY, "Sentinel command failed").into(),
    }
}

fn dispatch_error(error: CommandDispatchError) -> (StatusCode, &'static str) {
    match error {
        CommandDispatchError::Offline => (StatusCode::NOT_FOUND, "server is not connected"),
        CommandDispatchError::Unsupported => (StatusCode::CONFLICT, "command is not supported"),
        CommandDispatchError::Send => (StatusCode::SERVICE_UNAVAILABLE, "connection closed"),
        CommandDispatchError::QueueFull => (StatusCode::SERVICE_UNAVAILABLE, "connection is busy"),
        CommandDispatchError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "command timed out"),
        CommandDispatchError::Duplicate => (StatusCode::CONFLICT, "command is already running"),
    }
}
