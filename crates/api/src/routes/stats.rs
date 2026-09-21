use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;
use crate::routes::cpu::internal_error;
use crate::types::{
    InternalServerError, StatsMemoryUsage, StatsResponse, StatsTableSize, UnauthorizedError,
};

pub fn routes() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(stats))
}

#[utoipa::path(
    get,
    path = "/api/stats",
    tag = "Debug",
    summary = "Get database statistics",
    description = "Retrieve database storage statistics and estimated logical table sizes.\nOnly available when DEBUG environment variable is set to true. Only available when DEBUG=true.",
    responses(
        (status = 200, description = "Database statistics", body = StatsResponse),
        (status = 401, response = UnauthorizedError),
        (status = 500, response = InternalServerError),
    ),
    security(("bearerAuth" = []))
)]
async fn stats(State(state): State<Arc<AppState>>) -> Response {
    let permit = match state.history_queries.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(e) => return internal_error(e),
    };
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || store.db_stats()).await;
    drop(permit);
    let db = match result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e),
    };

    let memory = state.memory.get();

    let tables: Vec<_> = db
        .tables
        .iter()
        .map(|t| StatsTableSize {
            table_name: t.table_name.clone(),
            row_count: t.row_count,
            size_mb: format!("{:.2}", t.size_bytes as f64 / (1024.0 * 1024.0)),
            size_kb: format!("{:.2}", t.size_bytes as f64 / 1024.0),
        })
        .collect();

    Json(StatsResponse {
        row_count: db.row_count,
        storage_usage_kb: format!("{:.2}", db.storage_bytes as f64 / 1024.0),
        storage_usage_mb: format!("{:.2}", db.storage_bytes as f64 / (1024.0 * 1024.0)),
        memory_usage: StatsMemoryUsage {
            total: memory.total,
            available: memory.available,
            used: memory.used,
            used_percent: memory.used_percent,
            free: memory.free,
        },
        table_sizes: tables,
    })
    .into_response()
}
