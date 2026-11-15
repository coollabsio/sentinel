//! Database dumps and restores (decision 0010). Sentinel validates every
//! field and chooses the commands; these handlers only map the JSON from
//! Coolify.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use sentinel_protocol::control::v1::command::Payload;
use sentinel_protocol::control::v1::command_result;
use sentinel_protocol::control::v1::{DatabaseDumpRequest, DatabaseRestoreRequest};
use sentinel_protocol::{CAPABILITY_DATABASE_DUMP, CAPABILITY_DATABASE_RESTORE};
use serde::Deserialize;

use super::volume::{PartUrl, backup_json, invalid_response, restore_json};
use super::{ApiError, ApiState, LIFECYCLE_TIMEOUT, dispatch_with_timeout};

#[derive(Deserialize)]
pub(super) struct DatabaseDumpApiRequest {
    server_id: String,
    command_id: String,
    dump_id: String,
    container_name: String,
    engine: String,
    #[serde(default)]
    database: String,
    #[serde(default)]
    part_urls: Vec<PartUrl>,
    #[serde(default)]
    abort: bool,
}

#[derive(Deserialize)]
pub(super) struct DatabaseRestoreApiRequest {
    server_id: String,
    command_id: String,
    restore_id: String,
    container_name: String,
    engine: String,
    #[serde(default)]
    database: String,
    url: String,
    sha256: String,
    #[serde(default)]
    archive_bytes: u64,
}

/// Starts a dump on the Node, adds part URLs, or reads its state. It never
/// waits for the dump.
pub(super) async fn database_dump(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<DatabaseDumpApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_DATABASE_DUMP,
        Payload::DatabaseDump(DatabaseDumpRequest {
            dump_id: request.dump_id,
            container_name: request.container_name,
            engine: request.engine,
            database: request.database,
            part_urls: request
                .part_urls
                .into_iter()
                .map(PartUrl::protocol)
                .collect(),
            abort: request.abort,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::DatabaseDump(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(backup_json(
        &request.command_id,
        result.observed_at_unix_ms,
        value,
    )))
}

/// Starts a restore on the Node or reads its state.
pub(super) async fn database_restore(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<DatabaseRestoreApiRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = dispatch_with_timeout(
        &state,
        &headers,
        &request.server_id,
        &request.command_id,
        CAPABILITY_DATABASE_RESTORE,
        Payload::DatabaseRestore(DatabaseRestoreRequest {
            restore_id: request.restore_id,
            container_name: request.container_name,
            engine: request.engine,
            database: request.database,
            url: request.url,
            sha256: request.sha256,
            archive_bytes: request.archive_bytes,
        }),
        LIFECYCLE_TIMEOUT,
    )
    .await?;
    let Some(command_result::Payload::DatabaseRestore(value)) = result.payload else {
        return Err(invalid_response());
    };
    Ok(Json(restore_json(
        &request.command_id,
        result.observed_at_unix_ms,
        value,
    )))
}
