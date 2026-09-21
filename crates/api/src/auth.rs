use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use crate::{AppState, types::ErrorBody};

/// Endpoints exempt from authentication, matching the Go implementation,
/// plus the generated OpenAPI document (it exposes the schema, not data).
const PUBLIC_PATHS: [&str; 3] = ["/api/health", "/api/version", "/api-docs/openapi.json"];

/// Interactive documentation UIs (and their static assets) are public like
/// the spec they render. Prefix matching covers `/scalar`, `/scalar/...`,
/// `/swagger-ui`, `/swagger-ui/...`.
const PUBLIC_PREFIXES: [&str; 2] = ["/scalar", "/swagger-ui"];

fn is_public(path: &str) -> bool {
    PUBLIC_PATHS.contains(&path)
        || PUBLIC_PREFIXES
            .iter()
            .any(|prefix| path == *prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with('/')))
}

pub async fn require_token(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_public(path) {
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
