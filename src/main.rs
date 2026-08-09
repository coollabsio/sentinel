#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore, watch};

const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

fn unexpected_service_exit(
    result: Option<Result<Result<(), String>, tokio::task::JoinError>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Some(Ok(Ok(()))) => Err("required service stopped unexpectedly".into()),
        Some(Ok(Err(error))) => Err(error.into()),
        Some(Err(error)) => Err(format!("required service task failed: {error}").into()),
        None => Err("all required services stopped unexpectedly".into()),
    }
}

/// Bind the API listener. `addr` is the dual-stack `[::]` address from config;
/// on hosts where IPv6 is disabled that bind fails (EAFNOSUPPORT /
/// EADDRNOTAVAIL), so fall back to the equivalent IPv4 `0.0.0.0` address. This
/// mirrors Go's `net.Listen("tcp", ":PORT")`, which is dual-stack when IPv6 is
/// available and IPv4-only when it isn't.
async fn bind_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => Ok(listener),
        Err(e) if addr.is_ipv6() => {
            let v4 = SocketAddr::from(([0, 0, 0, 0], addr.port()));
            tracing::warn!(error = %e, %v4, "IPv6 bind failed, falling back to IPv4");
            tokio::net::TcpListener::bind(v4).await
        }
        Err(e) => Err(e),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sentinel: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Mirrors the Go implementation's Execute(): load a ".env" file from the
    // exact current working directory if present. Uses dotenvy::from_path
    // rather than dotenvy::dotenv() deliberately — the latter walks up
    // parent directories looking for ".env", which Go's plain
    // os.Stat(".env") + godotenv.Load() never did. tracing isn't initialized
    // yet at this point (config.debug, read a few lines below, decides the
    // log level), so this uses eprintln!/println! directly, matching Go's
    // use of the always-available standard `log` package here.
    if std::path::Path::new(".env").exists() {
        if let Err(e) = dotenvy::from_path(".env") {
            eprintln!("sentinel: error loading .env file: {e}");
        }
    } else {
        println!("sentinel: no .env file found, skipping load");
    }

    // Mirrors the Go implementation's `gin.Mode() == gin.DebugMode` check,
    // which is a RUNTIME env-var signal (GIN_MODE, defaulting to DebugMode
    // unless explicitly set to "release" — the Dockerfile does exactly
    // that). Deriving this from cfg!(debug_assertions) instead would tie it
    // to the BUILD PROFILE, not runtime intent: a `cargo test` binary is
    // always a debug build, so any integration test spawning the compiled
    // binary would silently get the development PUSH_ENDPOINT fallback and
    // could never exercise the "PUSH_ENDPOINT required" failure path.
    // SENTINEL_DEVELOPMENT lets that be forced explicitly either way; it
    // still defaults to the build profile when unset, so plain `cargo run`/
    // `cargo build --release` behave the same as before.
    let development = match std::env::var("SENTINEL_DEVELOPMENT") {
        Ok(v) => v != "0" && !v.eq_ignore_ascii_case("false"),
        Err(_) => cfg!(debug_assertions),
    };
    let config = Arc::new(config::Config::load(development)?);

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if config.debug {
                    "debug".into()
                } else {
                    "info".into()
                }
            }),
        )
        .init();

    tracing::info!(version = %config.version, "Sentinel is starting");

    // Store + sampler are required by the API. Docker is only needed by the
    // collector and pusher, so it is opened *after* the listener binds —
    // keeping the path to `/api/health` as short as possible.
    let store = store::Store::open(&config.metrics_file)?;

    // Traffic analytics database. Opened here, next to the metrics store and
    // ahead of the listener, for the same reason that one is: `AppState`
    // carries it, so it has to exist before the router is built. This is only
    // a local SQLite open — everything actually expensive about the traffic
    // subsystem (the GeoIP download, the access-log tail) is deferred to the
    // bottom of this function, well after the API is answering.
    //
    // A failure here degrades traffic analytics to "off" rather than taking
    // the agent down. `AnalyticsStore::open` already moves an unreadable
    // database aside and starts fresh, so reaching this arm means something
    // like a permissions or disk problem — which CPU/memory collection has no
    // stake in and must not be killed by.
    #[cfg(feature = "traffic")]
    let analytics: Option<store::traffic::AnalyticsStore> = if config.traffic.enabled {
        match store::traffic::AnalyticsStore::open(&config.traffic.analytics_file) {
            Ok(analytics) => Some(analytics),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    path = %config.traffic.analytics_file.display(),
                    "failed to open analytics database, traffic analytics disabled"
                );
                None
            }
        }
    } else {
        tracing::info!("traffic analytics disabled");
        None
    };

    let mut host_sampler = collector::HostSampler::new();
    let memory = Arc::new(api::CachedMemory::new(host_sampler.sample_memory()));
    let sampler = Arc::new(Mutex::new(host_sampler));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut services = tokio::task::JoinSet::new();

    // HTTP API
    //
    // Bind eagerly, before spawning: Go's implementation ran ListenAndServe
    // in a goroutine and propagated a bind failure through errgroup, tearing
    // down every other service and exiting the process non-zero. Binding
    // here, in run()'s own body, gets the same outcome more directly — a
    // bind failure surfaces via `?` immediately, before any other service is
    // even started, rather than needing extra coordination to cascade a
    // failure out of a spawned task after the fact.
    //
    // Also bind before DockerClient::new and before any collector/push work
    // so orchestration healthchecks (Coolify, Docker HEALTHCHECK) succeed as
    // soon as the process can answer /api/health.
    {
        let listener = bind_listener(config.bind_addr).await?;
        let addr = listener.local_addr().unwrap_or(config.bind_addr);
        tracing::info!(%addr, "api listening");

        let state = Arc::new(api::AppState {
            auth_header: format!("Bearer {}", config.token),
            config: config.clone(),
            store: store.clone(),
            sampler: sampler.clone(),
            memory: memory.clone(),
            history_queries: Arc::new(Semaphore::new(api::MAX_CONCURRENT_HISTORY_QUERIES)),
            #[cfg(feature = "traffic")]
            analytics: analytics.clone(),
            #[cfg(not(feature = "traffic"))]
            analytics: None,
        });
        let app = api::router(state);
        let mut rx = shutdown_rx.clone();
        services.spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await
                .map_err(|error| format!("API service failed: {error}"))
        });
    }

    // Refresh the in-memory host snapshot independently of request volume.
    // /proc/meminfo can be a comparatively expensive FUSE read inside LXC,
    // so current-memory requests only copy this cached value.
    {
        let sampler = sampler.clone();
        let memory = memory.clone();
        let mut rx = shutdown_rx.clone();
        services.spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                tokio::select! {
                    _ = rx.changed() => return Ok::<(), String>(()),
                    _ = ticker.tick() => {
                        let row = sampler.lock().await.sample_memory();
                        memory.set(row);
                    }
                }
            }
        });
    }

    let docker = docker::DockerClient::new()?;

    // Collector
    if config.collector_enabled {
        let c = collector::Collector::new(config.clone(), store.clone(), docker.clone());
        let rx = shutdown_rx.clone();
        services.spawn(async move {
            c.run(rx).await;
            Ok::<(), String>(())
        });
    } else {
        tracing::info!("collector disabled");
    }

    // Storage collector (disk usage + per-container storage)
    if config.storage_enabled {
        let c = collector::StorageCollector::new(config.clone(), store.clone(), docker.clone());
        let rx = shutdown_rx.clone();
        services.spawn(async move {
            c.run(rx).await;
            Ok::<(), String>(())
        });
    } else {
        tracing::info!("storage collector disabled");
    }

    // Pusher
    {
        let pusher = push::Pusher::new(config.clone(), docker.clone(), store.clone())?;
        let rx = shutdown_rx.clone();
        services.spawn(async move {
            pusher.run(rx).await;
            Ok::<(), String>(())
        });
    }

    // Retention: cleanup + downsample, daily, with one pass at startup.
    {
        let store = store.clone();
        let days = config.collector_retention_period_days;
        let mut rx = shutdown_rx.clone();
        services.spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            loop {
                tokio::select! {
                    _ = rx.changed() => return Ok::<(), String>(()),
                    _ = ticker.tick() => {
                        let s = store.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            let now = collector::now_millis();
                            let deleted = s.cleanup(days, now)?;
                            let collapsed = s.downsample(now)?;
                            Ok::<_, store::StoreError>((deleted, collapsed))
                        })
                        .await;
                        match result {
                            Ok(Ok((deleted, collapsed))) => tracing::info!(
                                deleted, collapsed, retention_days = days, "retention pass complete"
                            ),
                            Ok(Err(e)) => tracing::warn!(error = %e, "retention pass failed"),
                            Err(e) => tracing::warn!(error = %e, "retention task panicked"),
                        }
                    }
                }
            }
        });
    }

    // Traffic analytics: access-log ingest, tier compaction, retention, and
    // periodic GeoIP refresh. `analytics` is `Some` only when the subsystem is
    // both enabled and its database opened, so this one binding gates the whole
    // section.
    //
    // Deliberately last in the startup sequence: `GeoIp::bootstrap` downloads a
    // database, and nothing above — API, collectors, pusher — should wait on
    // that. (A signal arriving during the download still terminates the process
    // at its default disposition, exactly as one arriving during any other part
    // of startup does; `wait_for_signal` has not installed a handler yet.)
    #[cfg(feature = "traffic")]
    if let Some(analytics) = analytics {
        // GeoIP databases live next to analytics.sqlite (spec §6). `parent()`
        // is `Some("")` for a bare filename and `None` only for a root path;
        // neither is a directory to write into, so both degrade to the current
        // directory rather than panicking.
        let db_dir = config
            .traffic
            .analytics_file
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        // Country enrichment is optional: if every candidate source is
        // unreachable the country breakdown is simply empty, which is not a
        // reason to run without traffic analytics altogether.
        let geoip = if config.traffic.geoip_enabled {
            match traffic::geoip::GeoIp::bootstrap(&config.traffic, &db_dir).await {
                Ok(geoip) => Some(geoip),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "geoip bootstrap failed, continuing without country enrichment"
                    );
                    None
                }
            }
        } else {
            tracing::info!("geoip disabled");
            None
        };
        let lookup: Arc<dyn traffic::enrich::CountryLookup> = match &geoip {
            Some(geoip) => geoip.clone(),
            None => Arc::new(traffic::enrich::NoGeo),
        };

        // Ingest. A build failure here is nearly always "the access log isn't
        // there": the proxy's log directory isn't mounted into this container,
        // or the proxy hasn't been switched to JSON access logging yet. That is
        // a real misconfiguration worth surfacing loudly, but not a crash — and
        // not a reason to stop maintaining a database that may already hold
        // history, so the tasks below are spawned either way.
        match traffic::service::TrafficService::build(&config, analytics.clone(), lookup).await {
            Ok(service) => {
                let rx = shutdown_rx.clone();
                services.spawn(async move {
                    service.run(rx).await;
                    Ok::<(), String>(())
                });
            }
            Err(e) => tracing::error!(
                error = %e,
                path = %config.traffic.access_log_path.display(),
                "traffic ingest unavailable; compaction and retention still run"
            ),
        }

        // 1m -> 1h compaction, hourly, with one pass at startup. Compaction
        // only ever touches *closed* coarse buckets, so an off-boundary cadence
        // (and this immediate first pass) is safe by construction.
        {
            let analytics = analytics.clone();
            let topn = config.traffic.topn as usize;
            let mut rx = shutdown_rx.clone();
            services.spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
                loop {
                    tokio::select! {
                        _ = rx.changed() => return Ok::<(), String>(()),
                        _ = ticker.tick() => {
                            let s = analytics.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                traffic::compaction::compact_1m_to_1h(&s, collector::now_millis(), topn)
                            })
                            .await;
                            match result {
                                Ok(Ok(written)) => tracing::info!(
                                    written, "traffic 1m->1h compaction complete"
                                ),
                                Ok(Err(e)) => tracing::warn!(error = %e, "traffic 1m->1h compaction failed"),
                                Err(e) => tracing::warn!(error = %e, "traffic compaction task panicked"),
                            }
                        }
                    }
                }
            });
        }

        // 1h -> 1d compaction plus per-tier retention, daily, with one pass at
        // startup. Both are cheap SQLite work on the same connection, so they
        // share one blocking task rather than racing for the writer mutex.
        {
            let analytics = analytics.clone();
            let topn = config.traffic.topn as usize;
            let m1_hours = config.traffic.retention_1m_hours;
            let h1_days = config.traffic.retention_1h_days;
            let d1_days = config.traffic.retention_1d_days;
            let mut rx = shutdown_rx.clone();
            services.spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
                loop {
                    tokio::select! {
                        _ = rx.changed() => return Ok::<(), String>(()),
                        _ = ticker.tick() => {
                            let s = analytics.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                let now = collector::now_millis();
                                let written = traffic::compaction::compact_1h_to_1d(&s, now, topn)?;
                                let deleted = s.retention(now, m1_hours, h1_days, d1_days)?;
                                Ok::<_, traffic::TrafficError>((written, deleted))
                            })
                            .await;
                            match result {
                                Ok(Ok((written, deleted))) => tracing::info!(
                                    written, deleted, "traffic 1h->1d compaction and retention complete"
                                ),
                                Ok(Err(e)) => tracing::warn!(error = %e, "traffic daily compaction/retention failed"),
                                Err(e) => tracing::warn!(error = %e, "traffic daily task panicked"),
                            }
                        }
                    }
                }
            });
        }

        // GeoIP refresh, every GEOIP_REFRESH_DAYS. Unlike the tickers above,
        // the interval's immediate first tick is consumed rather than acted on:
        // `bootstrap` fetched a fresh database moments ago, so refreshing now
        // would be a redundant round-trip.
        if let Some(geoip) = geoip {
            let settings = config.traffic.clone();
            let period = std::time::Duration::from_secs(
                config.traffic.geoip_refresh_days as u64 * 24 * 60 * 60,
            );
            let mut rx = shutdown_rx.clone();
            services.spawn(async move {
                let mut ticker = tokio::time::interval(period);
                ticker.tick().await;
                loop {
                    tokio::select! {
                        _ = rx.changed() => return Ok::<(), String>(()),
                        _ = ticker.tick() => {
                            // `Err` means every candidate source failed, which
                            // `refresh` documents as leaving the currently
                            // mapped database untouched and still serving
                            // lookups. Log it and wait for the next tick —
                            // returning would trip `unexpected_service_exit`
                            // and take the whole agent down over a failed
                            // background download.
                            match geoip.refresh(&settings, &db_dir).await {
                                Ok(true) => tracing::info!("geoip database refreshed"),
                                Ok(false) => tracing::debug!("geoip database already current"),
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "geoip refresh failed, keeping the current database"
                                ),
                            }
                        }
                    }
                }
            });
        }
    }

    tokio::select! {
        _ = wait_for_signal() => {}
        result = services.join_next() => return unexpected_service_exit(result),
    }
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    match tokio::time::timeout(SHUTDOWN_GRACE, async {
        while services.join_next().await.is_some() {}
    })
    .await
    {
        Ok(()) => tracing::info!("all services stopped"),
        Err(_) => tracing::warn!("shutdown grace period elapsed, exiting anyway"),
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGTERM handler");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received interrupt"),
        _ = term.recv() => tracing::info!("received SIGTERM"),
    }
}

#[cfg(test)]
mod tests {
    use super::unexpected_service_exit;

    #[test]
    fn a_clean_service_exit_is_still_unexpected_before_shutdown() {
        let result = unexpected_service_exit(Some(Ok(Ok(()))));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("stopped unexpectedly")
        );
    }

    #[test]
    fn a_service_error_is_propagated() {
        let result = unexpected_service_exit(Some(Ok(Err("api failed".into()))));
        assert_eq!(result.unwrap_err().to_string(), "api failed");
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
