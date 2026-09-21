use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::{
    BadRequestError, ContainerDiskUsage, CpuUsage, InternalServerError, MemUsage,
    UnauthorizedError,
};

/// Container history defaults `from` one second later than the host endpoints.
/// This asymmetry exists in the Go implementation and is preserved.
const DEFAULT_FROM: &str = "1970-01-01T00:00:01Z";

pub fn routes() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        // axum 0.8 requires braced params; "/:containerId" panics at build time.
        .routes(routes!(cpu_history))
        .routes(routes!(memory_history))
        .routes(routes!(disk_current))
        .routes(routes!(disk_history))
}

#[utoipa::path(
    get,
    path = "/api/container/{containerId}/cpu/history",
    tag = "Container Metrics",
    summary = "Get container CPU usage history",
    description = "Retrieve CPU usage history for a specific Docker container",
    params(
        ("containerId" = String, Path, description = "Exact container display name recorded by Sentinel"),
        HistoryQuery
    ),
    responses(
        (status = 200, description = "Container CPU usage history", body = Vec<CpuUsage>),
        (status = 400, response = BadRequestError),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn cpu_history(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let id = container_id;
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result =
        tokio::task::spawn_blocking(move || store.container_cpu_history(&id, from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<CpuUsage> = rows
        .into_iter()
        .map(|r| CpuUsage {
            time: r.time.to_string(),
            percent: format!("{:.2}", r.percent),
            human_friendly_time: debug.then(|| format_millis(r.time)),
        })
        .collect();
    Json(out).into_response()
}

#[utoipa::path(
    get,
    path = "/api/container/{containerId}/memory/history",
    tag = "Container Metrics",
    summary = "Get container memory usage history",
    description = "Retrieve memory usage history for a specific Docker container",
    params(
        ("containerId" = String, Path, description = "Exact container display name recorded by Sentinel"),
        HistoryQuery
    ),
    responses(
        (status = 200, description = "Container memory usage history", body = Vec<MemUsage>),
        (status = 400, response = BadRequestError),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn memory_history(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let id = container_id;
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result =
        tokio::task::spawn_blocking(move || store.container_memory_history(&id, from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<MemUsage> = rows
        .into_iter()
        .map(|r| MemUsage {
            time: r.time.to_string(),
            total: r.total,
            available: r.available,
            used: r.used,
            used_percent: r.used_percent,
            free: r.free,
            human_friendly_time: debug.then(|| format_millis(r.time)),
        })
        .collect();
    Json(out).into_response()
}

// Latest stored storage row for one container (`null` when none recorded yet).
#[utoipa::path(
    get,
    path = "/api/container/{containerId}/disk/current",
    tag = "Container Metrics",
    summary = "Get current container storage",
    description = "Latest stored writable-layer and volume size for a specific container (null if none recorded) Returns `null` when no storage row has been recorded for the container.",
    params(
        ("containerId" = String, Path, description = "Exact container display name recorded by Sentinel")
    ),
    responses(
        (status = 200, description = "Current container storage (or null)", body = Option<ContainerDiskUsage>),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn disk_current(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result =
        tokio::task::spawn_blocking(move || store.container_disk_latest_one(&container_id)).await;
    drop(permit);
    let row = match result {
        Ok(Ok(row)) => row,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    Json(row.map(|r| to_container_disk(r, debug))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/container/{containerId}/disk/history",
    tag = "Container Metrics",
    summary = "Get container storage history",
    description = "Historical writable-layer and volume sizes for a specific container",
    params(
        ("containerId" = String, Path, description = "Exact container display name recorded by Sentinel"),
        HistoryQuery
    ),
    responses(
        (status = 200, description = "Container storage history", body = Vec<ContainerDiskUsage>),
        (status = 400, response = BadRequestError),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn disk_history(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let id = container_id;
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result =
        tokio::task::spawn_blocking(move || store.container_disk_history(&id, from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<ContainerDiskUsage> = rows
        .into_iter()
        .map(|r| to_container_disk(r, debug))
        .collect();
    Json(out).into_response()
}

fn to_container_disk(r: store::ContainerDiskRow, debug: bool) -> ContainerDiskUsage {
    ContainerDiskUsage {
        time: r.time.to_string(),
        writable_layer: r.writable_layer,
        volumes_total: r.volumes_total,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}
