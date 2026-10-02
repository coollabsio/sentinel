use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::{AppState, types::ErrorBody};

/// Endpoints exempt from authentication, matching the Go implementation.
const PUBLIC_PATHS: [&str; 2] = ["/api/health", "/api/version"];

pub async fn require_token(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if PUBLIC_PATHS.contains(&path) {
        return next.run(request).await;
    }

    let expected = &state.auth_header;
    let provided = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "Unauthorized".into(),
            }),
        )
            .into_response();
    }
    next.run(request).await
}

/// Length-independent comparison, mirroring Go's subtle.ConstantTimeCompare
/// (which returns 0 for unequal lengths without leaking content).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests;
