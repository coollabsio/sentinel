#![forbid(unsafe_code)]

pub mod auth;
pub mod routes;
pub mod time;
pub mod types;

use std::sync::{Arc, RwLock};

use axum::Router;
use axum::routing::get;
use collector::HostSampler;
use config::Config;
use store::{MemRow, Store};
use tokio::sync::{Mutex, Semaphore};

pub const MAX_CONCURRENT_HISTORY_QUERIES: usize = 8;

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
    /// `GeoIp` itself, so this field doesn't need `#[cfg(feature =
    /// "traffic")]` gating — that would fracture `AppState`'s shape across
    /// builds, same as `analytics` above.
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
        .merge(routes::disk::routes())
        .merge(routes::container::routes());

    // Compile-time gate only. Whether the routes have anything to serve is a
    // runtime question (`AppState::analytics`), which each handler answers
    // with a 404 when the subsystem is compiled in but disabled.
    #[cfg(feature = "traffic")]
    {
        app = app.merge(routes::traffic::routes());
    }

    if debug {
        app = app.merge(routes::stats::routes());
    }

    app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::require_token,
    ))
    .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::CachedMemory;
    use store::MemRow;

    fn memory(used: u64) -> MemRow {
        MemRow {
            time: 0,
            total: 100,
            available: 100 - used,
            used,
            used_percent: used as f64,
            free: 100 - used,
        }
    }

    #[test]
    fn cached_memory_returns_the_latest_snapshot() {
        let cache = CachedMemory::new(memory(10));
        assert_eq!(cache.get().used, 10);

        cache.set(memory(25));

        assert_eq!(cache.get().used, 25);
    }
}
