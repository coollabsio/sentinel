use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::LoadAverage;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/load/current", get(current))
        .route("/api/load/history", get(history))
}

/// Latest host load average (`null` when nothing recorded yet).
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

fn to_load(r: store::LoadRow, debug: bool) -> LoadAverage {
    LoadAverage {
        time: r.time.to_string(),
        load1: r.load1,
        load5: r.load5,
        load15: r.load15,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}
