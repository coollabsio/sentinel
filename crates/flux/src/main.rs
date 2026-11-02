#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use flux::{
    AgentService, ConnectionRegistry, CredentialVerifier, EventReporter, TlsConfigurationError,
    load_server_tls, serve_internal_api,
};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let listen: SocketAddr = std::env::var("FLUX_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7443".into())
        .parse()?;
    let tls_config = load_server_tls(
        std::env::var_os("FLUX_TLS_CERT_PATH").map(PathBuf::from),
        std::env::var_os("FLUX_TLS_KEY_PATH").map(PathBuf::from),
        std::env::var("FLUX_DEVELOPMENT_ALLOW_PLAINTEXT").is_ok_and(|value| value == "true"),
    )?;
    let key_id = required("FLUX_SIGNING_KEY_ID")?;
    let public_key = decode_key(&required("FLUX_SIGNING_PUBLIC_KEY")?)?;
    let issuer = required("FLUX_ISSUER")?;
    let mut verifier =
        CredentialVerifier::new(key_id, public_key, issuer, Duration::from_secs(15 * 60));
    // Optional second key for a signing key rotation: set it to the old key
    // until every credential signed with it has expired (15 minutes).
    match (
        optional("FLUX_PREVIOUS_SIGNING_KEY_ID"),
        optional("FLUX_PREVIOUS_SIGNING_PUBLIC_KEY"),
    ) {
        (Some(key_id), Some(public_key)) => {
            verifier = verifier.with_additional_key(key_id, decode_key(&public_key)?);
        }
        (None, None) => {}
        _ => {
            return Err("FLUX_PREVIOUS_SIGNING_KEY_ID and FLUX_PREVIOUS_SIGNING_PUBLIC_KEY must be set together".into());
        }
    }
    let reporter = EventReporter::new(
        std::env::var("FLUX_INTERNAL_EVENTS_URL").ok(),
        std::env::var("FLUX_INTERNAL_TOKEN").ok(),
    );
    let registry = ConnectionRegistry::default();
    let transport = if tls_config.is_some() {
        "tls"
    } else {
        "plaintext"
    };
    let service = AgentService::new(verifier, registry.clone(), reporter, transport);
    let internal_listen: SocketAddr = std::env::var("FLUX_INTERNAL_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7080".into())
        .parse()?;
    let internal_token = required("FLUX_INTERNAL_TOKEN")?;
    let internal_listener = tokio::net::TcpListener::bind(internal_listen).await?;
    let internal_api = serve_internal_api(internal_listener, registry.clone(), internal_token);
    let (_health_reporter, health_service) = tonic_health::server::health_reporter();
    let mut server = Server::builder()
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)));
    if let Some(tls_config) = tls_config {
        server = server
            .tls_config(tls_config)
            .map_err(|_| TlsConfigurationError::InvalidCertificate)?;
        tracing::info!(%listen, "Flux is listening with TLS");
    } else {
        tracing::warn!(%listen, "Flux is listening without TLS");
    }
    let (stopping_sender, mut stopping) = tokio::sync::watch::channel(false);
    let grpc = server
        .add_service(health_service)
        .add_service(service.into_server())
        .serve_with_shutdown(listen, async move {
            shutdown().await;
            registry
                .shutdown_all(SHUTDOWN_RECONNECT_AFTER_SECONDS)
                .await;
            let _ = stopping_sender.send(true);
        });
    // A failed listener exits non-zero so the supervisor restarts Flux.
    tokio::select! {
        result = grpc => result?,
        result = internal_api => {
            result?;
            return Err("Flux internal command API stopped".into());
        }
        () = async {
            let _ = stopping.changed().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => tracing::warn!("Flux shutdown grace period elapsed, exiting anyway"),
    }
    Ok(())
}

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const SHUTDOWN_RECONNECT_AFTER_SECONDS: u32 = 5;

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} is empty").into());
    }
    Ok(value)
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn decode_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))?;
    bytes
        .try_into()
        .map_err(|_| "a Flux signing public key must contain 32 bytes".into())
}

/// Waits for Ctrl-C or SIGTERM, so `docker stop` shuts Flux down gracefully.
#[cfg(unix)]
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(error) => {
            tracing::error!(%error, "failed to install SIGTERM handler");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received interrupt"),
        _ = term.recv() => tracing::info!("received SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
