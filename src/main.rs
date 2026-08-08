#![forbid(unsafe_code)]

use std::sync::Arc;

use tokio::sync::{Mutex, watch};

const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

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

    let store = store::Store::open(&config.metrics_file)?;
    let docker = docker::DockerClient::new()?;
    let sampler = Arc::new(Mutex::new(collector::HostSampler::new()));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut services = tokio::task::JoinSet::new();

    // HTTP API
    {
        let state = Arc::new(api::AppState {
            config: config.clone(),
            store: store.clone(),
            sampler: sampler.clone(),
        });
        let app = api::router(state);
        let addr = config.bind_addr;
        let mut rx = shutdown_rx.clone();
        services.spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, %addr, "failed to bind");
                    return;
                }
            };
            tracing::info!(%addr, "api listening");
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.changed().await;
                })
                .await;
        });
    }

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
