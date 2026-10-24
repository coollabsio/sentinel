use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;
use crate::time::{format_millis, now_layout, parse_bound};
use crate::types::{
    BadRequestError, CpuCurrent, CpuUsage, ErrorBody, InternalServerError, UnauthorizedError,
};

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// Start date in ISO 8601 format (UTC). Defaults to the Unix epoch
    /// (all recorded history) when omitted.
    pub from: Option<String>,
    /// End date in ISO 8601 format (UTC). Defaults to now when omitted.
    pub to: Option<String>,
}

/// [`HistoryQuery`] plus an optional averaging window, for the metric history
/// endpoints. A separate struct so the traffic endpoints that reuse
/// `HistoryQuery` do not document a param they ignore.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MetricsHistoryQuery {
    /// Start date in ISO 8601 format (UTC). Defaults to the Unix epoch
    /// (all recorded history) when omitted.
    pub from: Option<String>,
    /// End date in ISO 8601 format (UTC). Defaults to now when omitted.
    pub to: Option<String>,
    /// Window width in milliseconds. Rows are averaged per epoch-aligned
    /// window and `time` is the window start. Omit for raw rows.
    // A `String` so `?bucket_ms=` (empty) means raw rows, like `from`/`to`.
    #[param(value_type = Option<i64>, minimum = 1)]
    pub bucket_ms: Option<String>,
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

/// [`resolve_range`] plus the optional `bucket_ms` window width.
#[allow(clippy::result_large_err)]
pub fn resolve_history(
    q: &MetricsHistoryQuery,
    default_from: &str,
) -> Result<(i64, i64, Option<i64>), Response> {
    let range = HistoryQuery {
        from: q.from.clone(),
        to: q.to.clone(),
    };
    let (from, to) = resolve_range(&range, default_from)?;
    let bucket_ms = match q.bucket_ms.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(raw) => match raw.parse::<i64>() {
            Ok(b) if b > 0 => Some(b),
            _ => {
                return Err(error_response(
                    "Invalid 'bucket_ms'. Use a positive integer",
                ));
            }
        },
    };
    Ok((from, to, bucket_ms))
}

fn bad_request(field: &str) -> Response {
    error_response(&format!(
        "Invalid '{field}' date format. Use YYYY-MM-DDTHH:MM:SSZ"
    ))
}

fn error_response(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: error.to_string(),
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

pub fn routes() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new()
        .routes(routes!(current))
        .routes(routes!(history))
}

#[utoipa::path(
    get,
    path = "/api/cpu/current",
    tag = "System Metrics",
    summary = "Get current CPU usage",
    description = "Retrieve the current CPU usage percentage",
    responses(
        (status = 200, description = "Current CPU usage", body = CpuCurrent),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn current(State(state): State<Arc<AppState>>) -> Response {
    let time = collector::now_millis().to_string();
    let percent = {
        let mut sampler = state.sampler.lock().await;
        sampler.sample_cpu()
    };
    // NOTE: `percent` is a NUMBER here, unlike /api/cpu/history. Frozen.
    Json(serde_json::json!({ "time": time, "percent": percent })).into_response()
}

#[utoipa::path(
    get,
    path = "/api/cpu/history",
    tag = "System Metrics",
    summary = "Get CPU usage history",
    description = "Retrieve historical CPU usage data with optional date range filtering",
    params(MetricsHistoryQuery),
    responses(
        (status = 200, description = "Historical CPU usage data", body = Vec<CpuUsage>),
        (status = 400, response = BadRequestError),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn history(
    State(state): State<Arc<AppState>>,
    Query(q): Query<MetricsHistoryQuery>,
) -> Response {
    let (from, to, bucket_ms) = match resolve_history(&q, "1970-01-01T00:00:00Z") {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.cpu_history(from, to, bucket_ms)).await;
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
