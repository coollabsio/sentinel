#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{Mutex, watch};

const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

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
    let sampler = Arc::new(Mutex::new(collector::HostSampler::new()));

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
        });
        let app = api::router(state);
        let mut rx = shutdown_rx.clone();
        services.spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await;
        });
    }

    let docker = docker::DockerClient::new()?;

    // Collector
    if config.collector_enabled {
        let c = collector::Collector::new(config.clone(), store.clone(), docker.clone());
        services.spawn(c.run(shutdown_rx.clone()));
    } else {
        tracing::info!("collector disabled");
    }

    // Pusher
    {
        let pusher = push::Pusher::new(config.clone(), docker.clone())?;
        services.spawn(pusher.run(shutdown_rx.clone()));
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
                    _ = rx.changed() => return,
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

    wait_for_signal().await;
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

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
