use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::AppState;
use crate::routes::cpu::internal_error;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/stats", get(stats))
}

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
        .map(|t| {
            serde_json::json!({
                "table_name": t.table_name,
                "row_count": t.row_count,
                "size_mb": format!("{:.2}", t.size_bytes as f64 / (1024.0 * 1024.0)),
                "size_kb": format!("{:.2}", t.size_bytes as f64 / 1024.0),
            })
        })
        .collect();

    Json(serde_json::json!({
        "row_count": db.row_count,
        "storage_usage_kb": format!("{:.2}", db.storage_bytes as f64 / 1024.0),
        "storage_usage_mb": format!("{:.2}", db.storage_bytes as f64 / (1024.0 * 1024.0)),
        "memory_usage": {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "usedPercent": memory.used_percent,
            "free": memory.free,
        },
        "table_sizes": tables,
    }))
    .into_response()
}
