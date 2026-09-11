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
    let verifier =
        CredentialVerifier::new(key_id, public_key, issuer, Duration::from_secs(15 * 60));
    let reporter = EventReporter::new(
        std::env::var("FLUX_INTERNAL_EVENTS_URL").ok(),
        std::env::var("FLUX_INTERNAL_TOKEN").ok(),
    );
    let registry = ConnectionRegistry::default();
    let service = AgentService::new(verifier, registry.clone(), reporter);
    let internal_listen: SocketAddr = std::env::var("FLUX_INTERNAL_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7080".into())
        .parse()?;
    let internal_token = required("FLUX_INTERNAL_TOKEN")?;
    let internal_listener = tokio::net::TcpListener::bind(internal_listen).await?;
    tokio::spawn(async move {
        if let Err(error) = serve_internal_api(internal_listener, registry, internal_token).await {
            tracing::error!(%error, "Flux internal command API stopped");
        }
    });
    let (_health_reporter, health_service) = tonic_health::server::health_reporter();
    let mut server = Server::builder();
    if let Some(tls_config) = tls_config {
        server = server
            .tls_config(tls_config)
            .map_err(|_| TlsConfigurationError::InvalidCertificate)?;
        tracing::info!(%listen, "Flux is listening with TLS");
    } else {
        tracing::warn!(%listen, "Flux is listening without TLS");
    }
    server
        .add_service(health_service)
        .add_service(service.into_server())
        .serve_with_shutdown(listen, shutdown())
        .await?;
    Ok(())
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::env::var(name)?;
    if value.is_empty() {
        return Err(format!("{name} is empty").into());
    }
    Ok(value)
}

fn decode_key(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = STANDARD
        .decode(value)
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))?;
    bytes
        .try_into()
        .map_err(|_| "FLUX_SIGNING_PUBLIC_KEY must contain 32 bytes".into())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
