#![forbid(unsafe_code)]

pub mod auth;
pub mod docs;
pub mod routes;
pub mod time;
pub mod types;

use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::State;
use collector::HostSampler;
use config::Config;
use store::{MemRow, Store};
use tokio::sync::{Mutex, Semaphore};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::{Scalar, Servable};
use utoipa_swagger_ui::SwaggerUi;

pub const MAX_CONCURRENT_HISTORY_QUERIES: usize = 8;
pub const MAX_CONCURRENT_ANALYTICS_QUERIES: usize = 8;

pub struct CachedMemory(RwLock<MemRow>);

impl CachedMemory {
    pub fn new(row: MemRow) -> Self {
        Self(RwLock::new(row))
    }

    pub fn get(&self) -> MemRow {
        *self.0.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn set(&self, row: MemRow) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = row;
    }
}

pub struct AppState {
    pub config: Arc<Config>,
    /// Precomputed `"Bearer <token>"` so auth doesn't reallocate it per request.
    pub auth_header: String,
    pub store: Store,
    /// Shared by `/api/cpu/current` and the fixed-cadence memory refresher —
    /// *not* with the collector, which constructs its own `HostSampler`.
    /// sysinfo CPU readings are differential, so the API must use one warm,
    /// consistently-refreshed instance rather than a fresh one per request.
    ///
    /// Consequence: `/api/cpu/current` reports usage *since the last call to
    /// `/api/cpu/current` reports usage since its previous refresh (or the
    /// memory ticker's refresh, which does not refresh CPU), not usage over a
    /// fixed 5-second window like the collector's independent history rows.
    pub sampler: Arc<Mutex<HostSampler>>,
    /// Refreshed at a fixed cadence, so HTTP requests never read /proc/meminfo.
    pub memory: Arc<CachedMemory>,
    /// Bounds admission to SQLite's blocking history path. The store has one
    /// reader, so more blocking tasks only consume threads while waiting.
    pub history_queries: Arc<Semaphore>,
    /// Bounds admission to the analytics SQLite blocking path. Separate from
    /// `history_queries` because traffic hits an independent database
    /// (`analytics.sqlite`) with far heavier queries (million-row scans,
    /// t-digest/HLL decode+merge); sharing one semaphore let heavy analytics
    /// scans starve unrelated metric-history responses.
    ///
    /// This bounds *admission*, not parallelism: the store exposes a single
    /// read-only connection, so admitted analytics queries still serialize on
    /// its `Mutex`. The cap therefore limits how many analytics requests can be
    /// in flight (and thus how many blocking-pool threads they can tie up)
    /// rather than running that many scans at once. Real read concurrency would
    /// need a pool of reader connections, which this feature deliberately does
    /// not open (see `store::traffic::AnalyticsStore`).
    pub analytics_queries: Arc<Semaphore>,
    /// Traffic-analytics database, when the subsystem is both compiled in
    /// (the binary's `traffic` feature) and enabled (`TRAFFIC_ENABLED`) and
    /// its database opened successfully. `None` in every other case,
    /// including a build without the feature.
    ///
    /// Deliberately *not* `#[cfg]`-gated: `store::traffic` is always
    /// compiled (`store` is a required dependency here), so gating the field
    /// would only fracture this struct's shape across builds for no saving.
    /// `main.rs` owns the decision of what to put in it.
    pub analytics: Option<store::traffic::AnalyticsStore>,
    /// Attribution string for whichever GeoIP source is actually active
    /// (design spec §6; required by MaxMind's and DB-IP's licenses), filled
    /// in once `traffic::geoip::GeoIp::bootstrap` resolves — which happens
    /// well after the router is built, since the API must not wait on a
    /// network download to start answering requests. Deliberately typed as
    /// a plain `Arc<RwLock<Option<String>>>` rather than holding the
    /// `GeoIp` itself, so it needs no `#[cfg]` gating (see `analytics` above).
    ///
    /// Re-writable, not write-once: `GeoIp::refresh` can swap which source
    /// is active (the mirror can fail at boot and succeed on a later
    /// refresh, or vice versa), and each swap must be republished here so
    /// this stays in sync with `GeoIp`'s own `meta.source_url` rather than
    /// freezing whatever was true at startup.
    ///
    /// Empty (`.read()` yields `None`) whenever traffic analytics or GeoIP
    /// is disabled, the build lacks the `traffic` feature, bootstrap hasn't
    /// completed yet, or the resolved source has no attribution obligation —
    /// all of which the `/api/traffic/attribution` endpoint reports the same
    /// way: `{"attribution": null}`.
    pub geoip_attribution: Arc<std::sync::RwLock<Option<String>>>,
}

/// Everything except the debug-gated `/api/stats` *route*. Its documentation
/// is merged into the spec separately (see [`openapi_document`]) so the spec
/// always documents all endpoints regardless of the DEBUG flag.
fn core_openapi_router() -> OpenApiRouter<Arc<AppState>> {
    let open = OpenApiRouter::with_openapi(docs::base_openapi())
        .routes(routes!(health))
        .routes(routes!(version))
        .merge(routes::cpu::routes())
        .merge(routes::memory::routes())
        .merge(routes::disk::routes())
        .merge(routes::container::routes());

    // Compile-time gate only. Whether the routes have anything to serve is a
    // runtime question (`AppState::analytics`), which each handler answers
    // with a 404 when the subsystem is compiled in but disabled.
    #[cfg(feature = "traffic")]
    let open = open.merge(routes::traffic::routes());

    open
}

/// The complete OpenAPI document for this build. `/api/stats` is included
/// unconditionally — the route is DEBUG-gated at runtime, and the operation
/// description says so. Traffic paths are present when compiled with the
/// `traffic` feature (release builds always are).
fn openapi_document() -> utoipa::openapi::OpenApi {
    let (_, mut api) = core_openapi_router().split_for_parts();
    let (_, stats_api) = routes::stats::routes().split_for_parts();
    api.merge(stats_api);
    api
}

pub fn router(state: Arc<AppState>) -> Router {
    let debug = state.config.debug;

    let (mut app, _) = core_openapi_router().split_for_parts();
    let api = openapi_document();

    if debug {
        app = app.merge(routes::stats::routes());
    }

    // Interactive docs and the spec JSON are public, like /api/health and
    // /api/version (see auth::PUBLIC_PATHS / PUBLIC_PREFIXES).
    let app = app
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", api.clone()))
        .merge(Router::from(Scalar::with_url("/scalar", api)));

    app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::require_token,
    ))
    .with_state(state)
}

#[utoipa::path(
    get,
    path = "/api/health",
    tag = "Core",
    summary = "Health check",
    description = "Check if the service is running",
    responses(
        (status = 200, description = "Service is healthy", body = String, content_type = "text/plain", example = json!("ok"))
    ),
    security(())
)]
async fn health() -> &'static str {
    "ok"
}

#[utoipa::path(
    get,
    path = "/api/version",
    tag = "Core",
    summary = "Get version",
    description = "Get the current version of Sentinel",
    responses(
        // No version literal in the example — that would reintroduce a manual
        // bump location; the info block's version comes from config::VERSION.
        (status = 200, description = "Current version", body = String, content_type = "text/plain")
    ),
    security(())
)]
async fn version(State(state): State<Arc<AppState>>) -> String {
    state.config.version.clone()
}

#[cfg(test)]
mod tests;
