//! Image builds and the cluster registry (decision 0006). Sentinel validates
//! every field; these handlers only map the JSON from Coolify.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    BuilderReconcileRequest, ImageBuildRequest, RegistryReconcileRequest, RegistryServer,
};
use sentinel_protocol::{
    CAPABILITY_BUILDER_RECONCILE, CAPABILITY_IMAGE_BUILD, CAPABILITY_REGISTRY_RECONCILE,
};
use serde::Deserialize;

use super::{ApiError, ApiState, DEPLOY_TIMEOUT, dispatch_with_timeout};

#[derive(Deserialize)]
pub(super) struct ImageBuildApiRequest {
    server_id: String,
    command_id: String,
    build_id: String,
    builder_image: String,
    repository_url: String,
    commit_sha: String,
    source_type: String,
    #[serde(default)]
    base_directory: String,
    #[serde(default)]
    dockerfile_path: String,
    image: String,
}

#[derive(Deserialize)]
pub(super) struct BuilderReconcileApiRequest {
    server_id: String,
    command_id: String,
    enabled: bool,
    #[serde(default)]
    max_used_space_bytes: u64,
    #[serde(default)]
    push_username: String,
    #[serde(default)]
    push_password: String,
}

#[derive(Deserialize)]
pub(super) struct RegistryReconcileApiRequest {
    server_id: String,
    command_id: String,
    ca_pem: String,
    pull_username: String,
    pull_password: String,
    #[serde(default)]
    server: Option<RegistryServerApiRequest>,
}

#[derive(Deserialize)]
pub(super) struct RegistryServerApiRequest {
    certificate_pem: String,
    private_key_pem: String,
    htpasswd: String,
    push_username: String,
    keep_tags: u32,
}

fn invalid_response() -> ApiError {
    (StatusCode::BAD_GATEWAY, "invalid Sentinel response").into()
}

/// Starts a build container. It answers when the container runs, not when the
/// build ends; pulling the builder image can take minutes.
pub(super) async fn image_build(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ImageBuildApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_IMAGE_BUILD,
        Payload::ImageBuild(ImageBuildRequest {
            build_id: request.build_id,
            builder_image: request.builder_image,
            repository_url: request.repository_url,
            commit_sha: request.commit_sha,
            source_type: request.source_type,
            base_directory: request.base_directory,
            dockerfile_path: request.dockerfile_path,
            image: request.image,
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::ImageBuild(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "runtime_id": value.runtime_id,
        "name": value.name,
    })))
}

pub(super) async fn builder_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<BuilderReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_BUILDER_RECONCILE,
        Payload::BuilderReconcile(BuilderReconcileRequest {
            enabled: request.enabled,
            max_used_space_bytes: request.max_used_space_bytes,
            push_username: request.push_username,
            push_password: request.push_password,
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::BuilderReconcile(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "enabled": value.enabled,
        "running": value.running,
        "apparmor_profile": value.apparmor_profile,
    })))
}

pub(super) async fn registry_reconcile(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<RegistryReconcileApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_REGISTRY_RECONCILE,
        Payload::RegistryReconcile(RegistryReconcileRequest {
            ca_pem: request.ca_pem,
            pull_username: request.pull_username,
            pull_password: request.pull_password,
            server: request.server.map(|server| RegistryServer {
                certificate_pem: server.certificate_pem,
                private_key_pem: server.private_key_pem,
                htpasswd: server.htpasswd,
                push_username: server.push_username,
                keep_tags: server.keep_tags,
            }),
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::RegistryReconcile(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "trust_installed": value.trust_installed,
        "server_running": value.server_running,
        "registry_host": value.registry_host,
    })))
}
