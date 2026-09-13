use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{CertificateParams, KeyPair};
use sentinel_protocol::{CAPABILITY_SYSTEM_PING, PROTOCOL_MAX, PROTOCOL_MIN};
use tonic::transport::Server;

use super::*;

fn token(
    signing_key: &SigningKey,
    kid: &str,
    subject: &str,
    expires_delta: i64,
    not_before_delta: i64,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "EdDSA", "typ": "JWT", "kid": kid
        }))
        .unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": "coolify-dev", "aud": "flux", "purpose": "node-control-channel",
            "sub": subject, "jti": "token-id", "iat": now, "nbf": now + not_before_delta,
            "exp": now + expires_delta, "caps": [CAPABILITY_SYSTEM_PING],
            "pmin": PROTOCOL_MIN, "pmax": PROTOCOL_MAX
        }))
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    let signature = signing_key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

#[test]
fn verifies_bound_short_lived_eddsa_credentials() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let verifier = CredentialVerifier::new(
        "dev-key",
        signing_key.verifying_key().to_bytes(),
        "coolify-dev",
        Duration::from_secs(15 * 60),
    );
    let credential = token(&signing_key, "dev-key", "server-1", 15 * 60, -1);

    let claims = verifier.verify(&credential).unwrap();

    assert_eq!(claims.subject, "server-1");
    assert_eq!(claims.capabilities, vec![CAPABILITY_SYSTEM_PING]);
}

#[test]
fn rejects_wrong_key_id_subject_and_excessive_lifetime() {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let verifier = CredentialVerifier::new(
        "dev-key",
        signing_key.verifying_key().to_bytes(),
        "coolify-dev",
        Duration::from_secs(15 * 60),
    );

    assert_eq!(
        verifier
            .verify(&token(&signing_key, "other", "server-1", 60, -1))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::KeyId
    );
    assert_eq!(
        verifier
            .verify(&token(&signing_key, "dev-key", "server-1", 16 * 60, -1))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::Lifetime
    );
    assert_eq!(
        verifier
            .verify(&token(&signing_key, "dev-key", "server-1", 60, 30))
            .unwrap_err()
            .kind(),
        CredentialErrorKind::Claims
    );
}

#[test]
fn selects_protocol_and_capabilities_for_valid_hello() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![CAPABILITY_SYSTEM_PING.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![CAPABILITY_SYSTEM_PING.into()],
        boot_id: "boot-1".into(),
        trust_bundle_version: 1,
    };

    let negotiated = negotiate(&claims, &hello).unwrap();

    assert_eq!(negotiated.protocol_version, 1);
    assert_eq!(negotiated.capabilities, vec![CAPABILITY_SYSTEM_PING]);
}

#[tokio::test]
async fn registry_replaces_the_previous_connection() {
    let registry = ConnectionRegistry::default();
    let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(1);
    let (second_tx, _) = tokio::sync::mpsc::channel(1);
    registry
        .insert("server-1", "connection-1", first_tx, 1, vec![])
        .await;
    registry
        .insert("server-1", "connection-2", second_tx, 1, vec![])
        .await;

    let message = first_rx.recv().await.unwrap();
    assert!(matches!(
        message.message,
        Some(sentinel_protocol::control::v1::control_message::Message::ShutdownHint(_))
    ));
    assert_eq!(
        registry.get("server-1").await.unwrap().connection_id,
        "connection-2"
    );
}

#[tokio::test]
async fn registry_routes_a_ping_result_to_the_waiting_request() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let command = sentinel_protocol::control::v1::Command {
        command_id: "command-1".into(),
        command_type: CAPABILITY_SYSTEM_PING.into(),
        payload_version: 1,
        created_at_unix_ms: now_millis(),
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::SystemPing(
                sentinel_protocol::control::v1::SystemPingRequest {
                    nonce: "nonce-1".into(),
                },
            ),
        ),
        expires_at_unix_ms: now_millis() + 10_000,
    };
    let pending_registry = registry.clone();
    let waiter = tokio::spawn(async move {
        pending_registry
            .dispatch("server-1", command, Duration::from_secs(1))
            .await
    });
    receiver.recv().await.unwrap();
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "event-1".into(),
                command_id: "command-1".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: now_millis(),
                payload: None,
            },
        )
        .await;

    assert_eq!(waiter.await.unwrap().unwrap().command_id, "command-1");
}

#[tokio::test]
async fn registry_reports_an_offline_server_without_waiting() {
    let result = ConnectionRegistry::default()
        .dispatch(
            "offline",
            sentinel_protocol::control::v1::Command::default(),
            Duration::from_secs(1),
        )
        .await;

    assert_eq!(result.unwrap_err(), CommandDispatchError::Offline);
}

#[tokio::test]
async fn registry_times_out_when_sentinel_does_not_return_a_result() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let command = sentinel_protocol::control::v1::Command {
        command_id: "command-timeout".into(),
        command_type: CAPABILITY_SYSTEM_PING.into(),
        ..Default::default()
    };

    let result = registry
        .dispatch("server-1", command, Duration::from_millis(1))
        .await;
    assert!(receiver.recv().await.is_some());
    assert_eq!(result.unwrap_err(), CommandDispatchError::Timeout);
}

#[tokio::test]
async fn endpoint_reconcile_route_requires_internal_authentication() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        ConnectionRegistry::default(),
        "internal-secret".into(),
    ));

    let response = reqwest::Client::new()
        .post(format!(
            "http://{address}/v1/commands/discovery.corrosion.endpoints.reconcile"
        ))
        .json(&serde_json::json!({
            "server_id": "server-1",
            "command_id": "endpoint-1",
            "owner_node_ip": "10.240.0.2",
            "endpoints": []
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    server.abort();
}

struct TestTlsMaterial {
    certificate: String,
    private_key: String,
}

fn test_tls_material(expired: bool) -> TestTlsMaterial {
    let now = time::OffsetDateTime::now_utc();
    let mut parameters = CertificateParams::new(vec!["localhost".into()]).unwrap();
    parameters.not_before = now - time::Duration::minutes(1);
    parameters.not_after = if expired {
        now - time::Duration::seconds(1)
    } else {
        now + time::Duration::hours(1)
    };
    let private_key = KeyPair::generate().unwrap();
    let certificate = parameters.self_signed(&private_key).unwrap();

    TestTlsMaterial {
        certificate: certificate.pem(),
        private_key: private_key.serialize_pem(),
    }
}

struct TestTlsFiles {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
}

impl TestTlsFiles {
    fn new(certificate: &str, private_key: &str) -> Self {
        static NEXT_FILE_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let certificate_path = std::env::temp_dir().join(format!("flux-tls-{nanos}-{id}.crt"));
        let private_key_path = std::env::temp_dir().join(format!("flux-tls-{nanos}-{id}.key"));
        std::fs::write(&certificate_path, certificate).unwrap();
        std::fs::write(&private_key_path, private_key).unwrap();

        Self {
            certificate_path,
            private_key_path,
        }
    }
}

impl Drop for TestTlsFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.certificate_path);
        let _ = std::fs::remove_file(&self.private_key_path);
    }
}

#[test]
fn loads_valid_flux_tls_files() {
    let material = test_tls_material(false);
    let files = TestTlsFiles::new(&material.certificate, &material.private_key);

    assert!(
        load_server_tls(
            Some(files.certificate_path.clone()),
            Some(files.private_key_path.clone()),
            false,
        )
        .unwrap()
        .is_some()
    );
}

#[test]
fn configures_tonic_with_validated_flux_tls() {
    let material = test_tls_material(false);
    let files = TestTlsFiles::new(&material.certificate, &material.private_key);
    let tls_config = load_server_tls(
        Some(files.certificate_path.clone()),
        Some(files.private_key_path.clone()),
        false,
    )
    .unwrap()
    .unwrap();

    assert!(Server::builder().tls_config(tls_config).is_ok());
}

#[test]
fn rejects_incomplete_flux_tls_configuration() {
    let material = test_tls_material(false);
    let files = TestTlsFiles::new(&material.certificate, &material.private_key);

    let error = load_server_tls(Some(files.certificate_path.clone()), None, false).unwrap_err();

    assert_eq!(
        error.to_string(),
        "FLUX_TLS_CERT_PATH and FLUX_TLS_KEY_PATH must both be set"
    );
}

#[test]
fn rejects_unreadable_flux_tls_files_without_exposing_the_path() {
    let missing = PathBuf::from("/tmp/flux-tls-does-not-exist.pem");

    let error =
        load_server_tls(Some(missing), Some(PathBuf::from("/tmp/key.pem")), false).unwrap_err();

    assert_eq!(error.to_string(), "cannot read Flux TLS certificate");
}

#[test]
fn rejects_invalid_flux_tls_pem() {
    let files = TestTlsFiles::new("not a certificate", "not a private key");

    let error = load_server_tls(
        Some(files.certificate_path.clone()),
        Some(files.private_key_path.clone()),
        false,
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "Flux TLS certificate is invalid");
}

#[test]
fn rejects_flux_tls_certificate_and_private_key_mismatch() {
    let certificate = test_tls_material(false);
    let private_key = test_tls_material(false);
    let files = TestTlsFiles::new(&certificate.certificate, &private_key.private_key);

    let error = load_server_tls(
        Some(files.certificate_path.clone()),
        Some(files.private_key_path.clone()),
        false,
    )
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "Flux TLS certificate and private key do not match"
    );
}

#[test]
fn rejects_an_expired_flux_tls_leaf_certificate() {
    let material = test_tls_material(true);
    let files = TestTlsFiles::new(&material.certificate, &material.private_key);

    let error = load_server_tls(
        Some(files.certificate_path.clone()),
        Some(files.private_key_path.clone()),
        false,
    )
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "Flux TLS certificate is not currently valid"
    );
}

#[test]
fn permits_plaintext_only_with_the_explicit_development_opt_in() {
    let error = load_server_tls(None, None, false).unwrap_err();

    assert_eq!(
        error.to_string(),
        "Flux TLS is required unless FLUX_DEVELOPMENT_ALLOW_PLAINTEXT=true"
    );
    assert!(load_server_tls(None, None, true).unwrap().is_none());
}
