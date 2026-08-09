use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::DiskUsage;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/disk/current", get(current))
        .route("/api/disk/history", get(history))
}

/// Latest stored snapshot: one row per mountpoint from the most recent cycle.
async fn current(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.disk_latest()).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<DiskUsage> = rows.into_iter().map(|r| to_disk_usage(r, debug)).collect();
    Json(out).into_response()
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
    let result = tokio::task::spawn_blocking(move || store.disk_history(from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<DiskUsage> = rows.into_iter().map(|r| to_disk_usage(r, debug)).collect();
    Json(out).into_response()
}

fn to_disk_usage(r: store::DiskRow, debug: bool) -> DiskUsage {
    DiskUsage {
        time: r.time.to_string(),
        mount: r.mount,
        total: r.total,
        used: r.used,
        available: r.available,
        used_percent: r.used_percent,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}
