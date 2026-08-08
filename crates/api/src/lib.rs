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
    /// Shared between the API's own `/api/cpu/current`, `/api/memory/current`
    /// and `/api/stats` handlers — *not* with the collector, which constructs
    /// its own independent `HostSampler` so its fixed-cadence loop never
    /// contends on this lock with inbound requests. sysinfo CPU readings are
    /// differential, so those three handlers must read through one warm,
    /// consistently-refreshed instance rather than a fresh one per request.
    ///
    /// Consequence: `/api/cpu/current` reports usage *since the last call to
    /// any of those three routes* (whichever last refreshed this sampler),
    /// not usage over a fixed 5-second window the way the collector's own
    /// independently sampled history rows are.
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
