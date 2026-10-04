use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::AppState;
use crate::types::{PushStatusBody, UnauthorizedError};

pub fn routes() -> OpenApiRouter<Arc<AppState>> {
    OpenApiRouter::new().routes(routes!(push_status))
}

#[utoipa::path(
    get,
    path = "/api/push-status",
    tag = "Core",
    summary = "Get push status",
    description = "Outcome of the most recent pushes to Coolify: when the last attempt and the last success happened, the last error (DNS, TLS, connection, non-2xx response, ...) and how many attempts failed in a row. All fields are null / 0 when push is disabled or no push was attempted yet.",
    responses(
        (status = 200, description = "Push status", body = PushStatusBody),
        (status = 401, response = UnauthorizedError),
    ),
    security(("bearerAuth" = []))
)]
async fn push_status(State(state): State<Arc<AppState>>) -> Json<PushStatusBody> {
    let status = state
        .push_status
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Json(PushStatusBody {
        last_attempt_at: status.last_attempt_at.map(format_rfc3339),
        last_success_at: status.last_success_at.map(format_rfc3339),
        last_error: status.last_error,
        last_status: status.last_status,
        consecutive_failures: status.consecutive_failures,
    })
}

/// Whole seconds, UTC (`2026-10-04T12:00:00Z`): sub-second precision adds
/// nothing at push cadence and nanosecond fractions trip some parsers.
fn format_rfc3339(at: OffsetDateTime) -> String {
    let at = at
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(at);
    at.format(&Rfc3339).unwrap_or_default()
}
