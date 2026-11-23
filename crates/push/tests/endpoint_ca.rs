//! PUSH_ENDPOINT_CA_PATH: a Coolify instance with a certificate from a private CA.

use std::sync::Arc;

use push::{PushError, load_endpoint_ca};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct PrivateCa {
    ca_pem: String,
    server_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

fn private_ca() -> PrivateCa {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&server_key, &ca)
        .unwrap();
    PrivateCa {
        ca_pem: ca.pem(),
        server_der: server.der().to_vec(),
        server_key_der: server_key.serialize_der(),
    }
}

/// An HTTPS server that answers every request with 200, with a certificate
/// for `localhost` from the private CA.
async fn start_https_server(ca: &PrivateCa) -> String {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![ca.server_der.clone().into()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(ca.server_key_der.clone().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 4096];
                let _ = tls.read(&mut buffer).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    format!("https://localhost:{port}/")
}

fn write_file(content: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, content.as_bytes()).unwrap();
    file
}

#[tokio::test]
async fn trusts_a_server_certificate_from_the_private_ca_in_the_file() {
    let ca = private_ca();
    let url = start_https_server(&ca).await;
    let file = write_file(&ca.ca_pem);

    let endpoint_ca = load_endpoint_ca(file.path()).unwrap();
    assert_eq!(endpoint_ca.len(), 1);
    // The same builder call as Pusher::new and AssignmentClient::new.
    let trusted = reqwest::Client::builder()
        .tls_certs_merge(endpoint_ca)
        .build()
        .unwrap();
    assert_eq!(trusted.get(&url).send().await.unwrap().status(), 200);

    let untrusted = reqwest::Client::new().get(&url).send().await;
    assert!(untrusted.is_err(), "{untrusted:?}");
}

#[test]
fn a_missing_file_names_the_path() {
    let error = load_endpoint_ca(std::path::Path::new("/nonexistent/coolify-ca.pem")).unwrap_err();
    assert!(matches!(error, PushError::EndpointCa { .. }));
    assert!(
        error
            .to_string()
            .starts_with("PUSH_ENDPOINT_CA_PATH /nonexistent/coolify-ca.pem: "),
        "{error}"
    );
}

#[test]
fn a_file_without_a_pem_certificate_is_refused() {
    let file = write_file("not a certificate\n");
    let error = load_endpoint_ca(file.path()).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "PUSH_ENDPOINT_CA_PATH {}: the file has no PEM certificate",
            file.path().display()
        )
    );
}
