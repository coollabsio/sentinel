use std::io::BufReader;
use std::path::PathBuf;
use std::sync::OnceLock;

use tonic::transport::{Identity, ServerTlsConfig};

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigurationError {
    #[error("FLUX_TLS_CERT_PATH and FLUX_TLS_KEY_PATH must both be set")]
    IncompleteConfiguration,
    #[error("Flux TLS is required unless FLUX_DEVELOPMENT_ALLOW_PLAINTEXT=true")]
    PlaintextNotAllowed,
    #[error("cannot read Flux TLS certificate")]
    CertificateRead,
    #[error("cannot read Flux TLS private key")]
    PrivateKeyRead,
    #[error("Flux TLS certificate is invalid")]
    InvalidCertificate,
    #[error("Flux TLS private key is invalid")]
    InvalidPrivateKey,
    #[error("Flux TLS certificate is not currently valid")]
    CertificateNotCurrentlyValid,
    #[error("Flux TLS certificate and private key do not match")]
    CertificateKeyMismatch,
}

pub fn load_server_tls(
    certificate_path: Option<PathBuf>,
    private_key_path: Option<PathBuf>,
    development_allow_plaintext: bool,
) -> Result<Option<ServerTlsConfig>, TlsConfigurationError> {
    let (certificate_path, private_key_path) = match (certificate_path, private_key_path) {
        (Some(certificate_path), Some(private_key_path)) => (certificate_path, private_key_path),
        (None, None) if development_allow_plaintext => return Ok(None),
        (None, None) => return Err(TlsConfigurationError::PlaintextNotAllowed),
        _ => return Err(TlsConfigurationError::IncompleteConfiguration),
    };
    let certificate =
        std::fs::read(certificate_path).map_err(|_| TlsConfigurationError::CertificateRead)?;
    let private_key_pem =
        std::fs::read(private_key_path).map_err(|_| TlsConfigurationError::PrivateKeyRead)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsConfigurationError::InvalidCertificate)?;
    let leaf = certificates
        .first()
        .ok_or(TlsConfigurationError::InvalidCertificate)?;
    let (remaining, leaf) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| TlsConfigurationError::InvalidCertificate)?;
    if !remaining.is_empty() {
        return Err(TlsConfigurationError::InvalidCertificate);
    }
    if !leaf.validity().is_valid() {
        return Err(TlsConfigurationError::CertificateNotCurrentlyValid);
    }
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(private_key_pem.as_slice()))
        .map_err(|_| TlsConfigurationError::InvalidPrivateKey)?
        .ok_or(TlsConfigurationError::InvalidPrivateKey)?;
    install_crypto_provider();
    let certificate_key = rustls::sign::CertifiedKey::from_der(
        certificates,
        private_key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|error| match error {
        rustls::Error::InconsistentKeys(_) => TlsConfigurationError::CertificateKeyMismatch,
        _ => TlsConfigurationError::InvalidPrivateKey,
    })?;
    certificate_key
        .keys_match()
        .map_err(|_| TlsConfigurationError::CertificateKeyMismatch)?;

    Ok(Some(ServerTlsConfig::new().identity(Identity::from_pem(
        certificate,
        private_key_pem,
    ))))
}

fn install_crypto_provider() {
    static CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

    CRYPTO_PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
