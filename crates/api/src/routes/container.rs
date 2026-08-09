use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::{HistoryQuery, internal_error, resolve_range};
use crate::time::format_millis;
use crate::types::{CpuUsage, MemUsage};

/// Container history defaults `from` one second later than the host endpoints.
/// This asymmetry exists in the Go implementation and is preserved.
const DEFAULT_FROM: &str = "1970-01-01T00:00:01Z";

/// Shared with the collector's write path via `store::sanitize_container_id`,
/// so the queried key always matches the stored key.
use store::sanitize_container_id as sanitize_id;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // axum 0.8 requires braced params; "/:containerId" panics at build time.
        .route("/api/container/{containerId}/cpu/history", get(cpu_history))
        .route(
            "/api/container/{containerId}/memory/history",
            get(memory_history),
        )
}

async fn cpu_history(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let id = sanitize_id(&container_id);
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let store = state.store.clone();
    let rows = match tokio::task::spawn_blocking(move || store.container_cpu_history(&id, from, to))
        .await
    {
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

async fn memory_history(
    Path(container_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Response {
    let id = sanitize_id(&container_id);
    let (from, to) = match resolve_range(&q, DEFAULT_FROM) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let store = state.store.clone();
    let rows =
        match tokio::task::spawn_blocking(move || store.container_memory_history(&id, from, to))
            .await
        {
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

#[cfg(test)]
mod tests {
    use super::sanitize_id;

    #[test]
    fn strips_slashes_and_punctuation() {
        assert_eq!(sanitize_id("we/b-!"), "web");
        assert_eq!(sanitize_id("/my-app_1"), "myapp1");
        assert_eq!(sanitize_id("abc123"), "abc123");
        assert_eq!(sanitize_id("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_id(""), "");
    }
}
