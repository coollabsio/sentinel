//! Image builds and the cluster registry (decision 0006). Sentinel validates
//! every field; these handlers only map the JSON from Coolify.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    BuilderReconcileRequest, ImageBuildRequest, ImageLoadRequest, RegistryInspectRequest,
    RegistryReconcileRequest, RegistryServer,
};
use sentinel_protocol::{
    CAPABILITY_BUILDER_RECONCILE, CAPABILITY_IMAGE_BUILD, CAPABILITY_IMAGE_LOAD,
    CAPABILITY_REGISTRY_INSPECT, CAPABILITY_REGISTRY_RECONCILE,
};
use serde::Deserialize;

use super::{ApiError, ApiState, DEPLOY_TIMEOUT, LIFECYCLE_TIMEOUT, dispatch_with_timeout};

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
    #[serde(default)]
    git_https_token: String,
    #[serde(default)]
    git_ssh_private_key: String,
    #[serde(default)]
    push_image: String,
    #[serde(default)]
    push_username: String,
    #[serde(default)]
    push_password: String,
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
            git_https_token: request.git_https_token,
            git_ssh_private_key: request.git_ssh_private_key,
            push_image: request.push_image,
            push_username: request.push_username,
            push_password: request.push_password,
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

#[derive(Deserialize)]
pub(super) struct RegistryInspectApiRequest {
    server_id: String,
    command_id: String,
}

/// A read-only report of the registry and build cache on one Node.
pub(super) async fn registry_inspect(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<RegistryInspectApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_REGISTRY_INSPECT,
        Payload::RegistryInspect(RegistryInspectRequest {}),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::RegistryInspect(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "registry_running": value.registry_running,
        "healthy": value.healthy,
        "error": value.error,
        "repositories": value.repositories.iter().map(|repository| serde_json::json!({
            "name": repository.name,
            "tags": repository.tags.iter().map(|tag| serde_json::json!({
                "tag": tag.tag,
                "digest": tag.digest,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "repositories_truncated": value.repositories_truncated,
        "registry_bytes": value.registry_bytes,
        "build_cache_bytes": value.build_cache_bytes,
        "builder_running": value.builder_running,
    })))
}

#[derive(Deserialize)]
pub(super) struct ImageLoadApiRequest {
    server_id: String,
    command_id: String,
    build_id: String,
    image: String,
    keep_tags: u32,
}

/// Loads a finished local build into the Podman store of its Node.
pub(super) async fn image_load(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ImageLoadApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_IMAGE_LOAD,
        Payload::ImageLoad(ImageLoadRequest {
            build_id: request.build_id,
            image: request.image,
            keep_tags: request.keep_tags,
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::ImageLoad(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "image": value.image,
        "image_id": value.image_id,
    })))
}
