//! Image builds (decision 0006) and local image transfers between Nodes
//! (decision 0030). Sentinel validates every field; these handlers only map
//! the JSON from Coolify.

use std::collections::HashMap;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{
    BuilderReconcileRequest, ImageBuildRequest, ImageFetchRequest, ImageLoadRequest,
    ImagePruneRequest, ImageServeRequest,
};
use sentinel_protocol::{
    CAPABILITY_BUILDER_RECONCILE, CAPABILITY_IMAGE_BUILD, CAPABILITY_IMAGE_BUILD_UNTRUSTED_SOURCE,
    CAPABILITY_IMAGE_FETCH, CAPABILITY_IMAGE_LOAD, CAPABILITY_IMAGE_PRUNE, CAPABILITY_IMAGE_SERVE,
};
use serde::Deserialize;

use super::{
    ApiError, ApiState, DEPLOY_TIMEOUT, LIFECYCLE_TIMEOUT, dispatch_error, dispatch_with_timeout,
};
use crate::CommandDispatchError;

#[derive(Deserialize)]
pub(super) struct ImageBuildApiRequest {
    server_id: String,
    command_id: String,
    build_id: String,
    builder_image: String,
    /// Empty for an inline Dockerfile; Sentinel checks the combination.
    #[serde(default)]
    repository_url: String,
    #[serde(default)]
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
    #[serde(default)]
    build_args: HashMap<String, String>,
    #[serde(default)]
    build_secrets: HashMap<String, String>,
    #[serde(default)]
    dockerfile_content: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    static_root: String,
    #[serde(default)]
    image_username: String,
    #[serde(default)]
    image_password: String,
    #[serde(default)]
    untrusted_source: bool,
    #[serde(default)]
    max_concurrent_builds: u32,
}

#[derive(Deserialize)]
pub(super) struct BuilderReconcileApiRequest {
    server_id: String,
    command_id: String,
    enabled: bool,
    #[serde(default)]
    max_used_space_bytes: u64,
    #[serde(default)]
    memory_limit_bytes: u64,
    #[serde(default)]
    cpu_limit_millis: u32,
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
    // An older Sentinel ignores `untrusted_source` and would give the Git
    // credential to the submodules of the source.
    if request.untrusted_source {
        super::authorize(&state.token, &headers)?;
        let Some(connection) = state.registry.get(&request.server_id).await else {
            return Err(dispatch_error(CommandDispatchError::Offline).into());
        };
        if !connection
            .capabilities
            .iter()
            .any(|capability| capability == CAPABILITY_IMAGE_BUILD_UNTRUSTED_SOURCE)
        {
            return Err(dispatch_error(CommandDispatchError::Unsupported).into());
        }
    }
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
            build_args: request.build_args,
            build_secrets: request.build_secrets,
            dockerfile_content: request.dockerfile_content,
            target: request.target,
            static_root: request.static_root,
            image_username: request.image_username,
            image_password: request.image_password,
            untrusted_source: request.untrusted_source,
            max_concurrent_builds: request.max_concurrent_builds,
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
            memory_limit_bytes: request.memory_limit_bytes,
            cpu_limit_millis: request.cpu_limit_millis,
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
        "replace_pending": value.replace_pending,
        "memory_limit_bytes": value.memory_limit_bytes,
    })))
}

#[derive(Deserialize)]
pub(super) struct ImagePruneApiRequest {
    server_id: String,
    command_id: String,
    #[serde(default)]
    keep: Vec<String>,
    #[serde(default)]
    running_build_containers: Vec<String>,
}

/// Removes unused images and ended build containers on one Node, except the
/// keep list. A Sentinel without `image.prune.v1` gets 409.
pub(super) async fn image_prune(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ImagePruneApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_IMAGE_PRUNE,
        Payload::ImagePrune(ImagePruneRequest {
            keep: request.keep,
            running_build_containers: request.running_build_containers,
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::ImagePrune(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "freed_bytes": value.freed_bytes,
        "removed_images": value.removed_images,
        "removed_containers": value.removed_containers,
        "kept_images": value.kept_images,
        "skipped": value.skipped,
        "disk_available_bytes": value.disk_available_bytes,
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

#[derive(Deserialize)]
pub(super) struct ImageServeApiRequest {
    server_id: String,
    command_id: String,
    transfer_id: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    peer_ip: String,
    #[serde(default)]
    secret: String,
    #[serde(default)]
    expires_at_unix_ms: i64,
    #[serde(default)]
    stop: bool,
}

/// Exports a local image and serves it to one peer Node, repeats a running
/// serve, or stops it. The export can take a few minutes for a large image.
pub(super) async fn image_serve(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ImageServeApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_IMAGE_SERVE,
        Payload::ImageServe(ImageServeRequest {
            transfer_id: request.transfer_id,
            image: request.image,
            peer_ip: request.peer_ip,
            secret: request.secret,
            expires_at_unix_ms: request.expires_at_unix_ms,
            stop: request.stop,
        }),
        DEPLOY_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::ImageServe(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "address": value.address,
        "port": value.port,
        "repository": value.repository,
        "digest": value.digest,
        "image_id": value.image_id,
        "size_bytes": value.size_bytes,
        "bytes_sent": value.bytes_sent,
    })))
}

#[derive(Deserialize)]
pub(super) struct ImageFetchApiRequest {
    server_id: String,
    command_id: String,
    transfer_id: String,
    source_address: String,
    source_port: u32,
    secret: String,
    repository: String,
    digest: String,
    image: String,
    image_id: String,
}

/// Starts the pull of a served image on the target Node, or reads its state.
/// It never waits for the pull.
pub(super) async fn image_fetch(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ImageFetchApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_IMAGE_FETCH,
        Payload::ImageFetch(ImageFetchRequest {
            transfer_id: request.transfer_id,
            source_address: request.source_address,
            source_port: request.source_port,
            secret: request.secret,
            repository: request.repository,
            digest: request.digest,
            image: request.image,
            image_id: request.image_id,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::ImageFetch(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(serde_json::json!({
        "command_id": request.command_id,
        "observed_at_unix_ms": result.observed_at_unix_ms,
        "state": value.state,
        "bytes_done": value.bytes_done,
        "error": value.error,
        "image_id": value.image_id,
    })))
}
