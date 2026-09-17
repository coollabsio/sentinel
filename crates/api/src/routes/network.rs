use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::NetworkUsage;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/network/current", get(current))
        .route("/api/network/history", get(history))
}

/// Latest host network rate (`null` when nothing recorded yet).
async fn current(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.network_latest()).await;
    drop(permit);
    let row = match result {
        Ok(Ok(row)) => row,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    Json(row.map(|r| to_network_usage(r, debug))).into_response()
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
    let result = tokio::task::spawn_blocking(move || store.network_history(from, to)).await;
    drop(permit);
    let rows = match result {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let debug = state.config.debug;
    let out: Vec<NetworkUsage> = rows
        .into_iter()
        .map(|r| to_network_usage(r, debug))
        .collect();
    Json(out).into_response()
}

pub(crate) fn to_network_usage(r: store::NetworkRow, debug: bool) -> NetworkUsage {
    NetworkUsage {
        time: r.time.to_string(),
        rx_bytes_per_sec: r.rx_bytes_per_sec,
        tx_bytes_per_sec: r.tx_bytes_per_sec,
        human_friendly_time: debug.then(|| format_millis(r.time)),
    }
}
