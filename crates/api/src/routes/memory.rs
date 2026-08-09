use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::MemUsage;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/memory/current", get(current))
        .route("/api/memory/history", get(history))
}

async fn current(State(state): State<Arc<AppState>>) -> Response {
    let time = collector::now_millis();
    let mut row = state.memory.get();
    row.time = time;

    Json(MemUsage {
        time: row.time.to_string(),
        total: row.total,
        available: row.available,
        used: row.used,
        used_percent: row.used_percent,
        free: row.free,
        human_friendly_time: None,
    })
    .into_response()
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
    let result = tokio::task::spawn_blocking(move || store.memory_history(from, to)).await;
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
