use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::{BadRequestError, InternalServerError, LoadAverage, UnauthorizedError};

pub fn routes() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(current))
        .routes(routes!(history))
}

#[utoipa::path(
    get,
    path = "/api/load/current",
    tag = "System Metrics",
    summary = "Get current load average",
    description = "Latest host load average (1 / 5 / 15 minute), or null when nothing has been recorded yet",
    responses(
        (status = 200, description = "Current load average", body = Option<LoadAverage>),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn current(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.load_latest()).await;
    drop(permit);
    let row = match result {
        Ok(Ok(row)) => row,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    Json(row.map(|r| to_load(r, debug))).into_response()
}

#[utoipa::path(
    get,
    path = "/api/load/history",
    tag = "System Metrics",
    summary = "Get load average history",
    description = "Historical host load average with optional date range filtering",
    params(HistoryQuery),
    responses(
        (status = 200, description = "Load average history", body = Vec<LoadAverage>),
        (status = 400, response = BadRequestError),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn history(State(state): State<Arc<AppState>>, Query(q): Query<HistoryQuery>) -> Response {
    let (from, to) = match resolve_range(&q, "1970-01-01T00:00:00Z") {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.load_history(from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<LoadAverage> = rows.into_iter().map(|r| to_load(r, debug)).collect();
    Json(out).into_response()
}

pub(crate) fn to_load(r: store::LoadRow, debug: bool) -> LoadAverage {
    LoadAverage {
        time: r.time.to_string(),
        load1: r.load1,
        load5: r.load5,
        load15: r.load15,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}
