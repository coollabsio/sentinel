#![forbid(unsafe_code)]

pub mod auth;
pub mod routes;
pub mod time;
pub mod types;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use collector::HostSampler;
use config::Config;
use store::Store;
use tokio::sync::Mutex;

pub struct AppState {
    pub config: Arc<Config>,
    pub store: Store,
    /// Shared with the collector's sampling cadence: sysinfo CPU readings are
    /// differential, so /api/cpu/current must read through a warm instance.
    pub sampler: Arc<Mutex<HostSampler>>,
}

pub fn router(state: Arc<AppState>) -> Router {
    let debug = state.config.debug;

    let mut app = Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route(
            "/api/version",
            get({
                let v = state.config.version.clone();
                move || async move { v }
            }),
        )
        .merge(routes::cpu::routes())
        .merge(routes::memory::routes())
        .merge(routes::container::routes());

    if debug {
        app = app.merge(routes::stats::routes());
    }

    app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::require_token,
    ))
    .with_state(state)
}
