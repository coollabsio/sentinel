use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::AppState;
use crate::time::{format_millis, now_layout, parse_bound};
use crate::types::{CpuUsage, ErrorBody};

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}

/// Resolves `from`/`to` into a millisecond range, applying the Go defaults.
/// The Response error type is necessary here for axum's flexibility in returning
/// different response types (bad_request or other errors).
///
/// `?from=&to=` deserializes to `Some("")`, not `None` — axum's `Query`
/// extractor only produces `None` when the key is absent entirely, not when
/// its value is empty (verified directly against `serde_urlencoded`). Go's
/// `ctx.Query("from")` returns `""` for both cases and its `if from != ""`
/// guard applied the default either way. Without the `.filter`, a caller
/// that builds a query string from an optional value (`?from=${from ?? ''}`)
/// gets a 400 on an endpoint that used to return full history.
#[allow(clippy::result_large_err)]
pub fn resolve_range(q: &HistoryQuery, default_from: &str) -> Result<(i64, i64), Response> {
    let from = q
        .from
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_from.to_string());
    let to =
        q.to.clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(now_layout);

    let from_ms = parse_bound(&from).map_err(|_| bad_request("from"))?;
    let to_ms = parse_bound(&to).map_err(|_| bad_request("to"))?;
    Ok((from_ms, to_ms))
}

fn bad_request(field: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: format!("Invalid '{field}' date format. Use YYYY-MM-DDTHH:MM:SSZ"),
        }),
    )
        .into_response()
}

pub fn internal_error(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "API request failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "Internal server error".to_string(),
        }),
    )
        .into_response()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/cpu/current", get(current))
        .route("/api/cpu/history", get(history))
}

async fn current(State(state): State<Arc<AppState>>) -> Response {
    let time = collector::now_millis().to_string();
    let percent = {
        let mut sampler = state.sampler.lock().await;
        sampler.sample_cpu()
    };
    // NOTE: `percent` is a NUMBER here, unlike /api/cpu/history. Frozen.
    Json(serde_json::json!({ "time": time, "percent": percent })).into_response()
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
    let result = tokio::task::spawn_blocking(move || store.cpu_history(from, to)).await;
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
