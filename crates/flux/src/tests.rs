use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use rcgen::{CertificateParams, KeyPair};
use sentinel_protocol::{
    CAPABILITY_CORROSION_RECONCILE, CAPABILITY_LOGS_READ, CAPABILITY_SYSTEM_PING, PROTOCOL_MAX,
    PROTOCOL_MIN,
};
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
        capabilities: vec![
            CAPABILITY_SYSTEM_PING.into(),
            CAPABILITY_CORROSION_RECONCILE.into(),
        ],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![
            CAPABILITY_SYSTEM_PING.into(),
            CAPABILITY_CORROSION_RECONCILE.into(),
        ],
        boot_id: "boot-1".into(),
        trust_bundle_version: 1,
    };

    let negotiated = negotiate(&claims, &hello).unwrap();

    assert_eq!(negotiated.protocol_version, 1);
    assert_eq!(
        negotiated.capabilities,
        vec![CAPABILITY_SYSTEM_PING, CAPABILITY_CORROSION_RECONCILE]
    );
}

#[tokio::test]
async fn accepts_a_hello_with_unknown_or_ungranted_capabilities_without_granting_them() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![CAPABILITY_SYSTEM_PING.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "9.9.9".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![
            CAPABILITY_SYSTEM_PING.into(),
            CAPABILITY_LOGS_READ.into(),
            "future.capability.v7".into(),
        ],
        boot_id: "boot-1".into(),
        trust_bundle_version: 1,
    };

    let negotiated = negotiate(&claims, &hello).unwrap();
    assert_eq!(negotiated.capabilities, vec![CAPABILITY_SYSTEM_PING]);

    let registry = ConnectionRegistry::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            negotiated.protocol_version,
            negotiated.capabilities,
        )
        .await;
    let result = registry
        .dispatch(
            "server-1",
            sentinel_protocol::control::v1::Command {
                command_id: "logs-1".into(),
                command_type: CAPABILITY_LOGS_READ.into(),
                ..Default::default()
            },
            Duration::from_secs(1),
        )
        .await;
    assert_eq!(result.unwrap_err(), CommandDispatchError::Unsupported);
}

#[test]
fn still_refuses_a_hello_with_an_invalid_identity_or_protocol() {
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

    for invalid in [
        sentinel_protocol::control::v1::Hello {
            sentinel_version: String::new(),
            ..hello.clone()
        },
        sentinel_protocol::control::v1::Hello {
            server_id: "server-2".into(),
            ..hello.clone()
        },
        sentinel_protocol::control::v1::Hello {
            protocol_min: 2,
            protocol_max: 2,
            ..hello.clone()
        },
    ] {
        assert!(negotiate(&claims, &invalid).is_err());
    }
}

#[tokio::test]
async fn logs_read_route_returns_sentinel_log_events() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_LOGS_READ.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/logs.read"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "source": "discovery_dns",
                "limit": 50,
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(sentinel_protocol::control::v1::control_message::Message::Command(command)) =
        message.message
    else {
        panic!("expected a command");
    };
    assert_eq!(command.command_type, CAPABILITY_LOGS_READ);
    assert!(matches!(
        command.payload,
        Some(sentinel_protocol::control::v1::command::Payload::LogsRead(
            sentinel_protocol::control::v1::LogsReadRequest { source, limit: 50 }
        )) if source == sentinel_protocol::control::v1::LogSource::DiscoveryDns as i32
    ));
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: format!("{}:result", command.command_id),
                command_id: command.command_id.clone(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: 1_700_000_000_500,
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::LogsRead(
                        sentinel_protocol::control::v1::LogsReadResult {
                            source: sentinel_protocol::control::v1::LogSource::DiscoveryDns.into(),
                            events: vec![sentinel_protocol::control::v1::LogEvent {
                                timestamp_unix_ms: 1_700_000_000_000,
                                level: "warn".into(),
                                component: "coolify-discovery-dns".into(),
                                message: "query failed".into(),
                                fields: [("_PID".to_string(), "42".to_string())].into(),
                            }],
                            truncated: true,
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "command_id": command.command_id,
            "observed_at_unix_ms": 1_700_000_000_500_i64,
            "source": "discovery_dns",
            "truncated": true,
            "events": [{
                "timestamp_unix_ms": 1_700_000_000_000_i64,
                "level": "warn",
                "component": "coolify-discovery-dns",
                "message": "query failed",
                "fields": {"_PID": "42"}
            }]
        })
    );
    server.abort();
}

#[tokio::test]
async fn logs_read_route_validates_the_request_and_capability() {
    let registry = ConnectionRegistry::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry,
        "internal-secret".into(),
    ));
    let send = |token: &str, body: serde_json::Value| {
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/logs.read"))
            .bearer_auth(token)
            .json(&body)
            .send()
    };
    let valid = |server_id: &str| serde_json::json!({"server_id": server_id, "source": "sentinel", "limit": 10});

    for (token, body, status) in [
        (
            "wrong",
            valid("server-1"),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            "internal-secret",
            serde_json::json!({"server_id": "server-1", "source": "sentinel", "limit": 0}),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            serde_json::json!({"server_id": "server-1", "source": "sentinel", "limit": 501}),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            serde_json::json!({"server_id": "server-1", "source": "syslog", "limit": 10}),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            valid("offline"),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "internal-secret",
            valid("server-1"),
            reqwest::StatusCode::CONFLICT,
        ),
    ] {
        assert_eq!(
            send(token, body.clone()).await.unwrap().status(),
            status,
            "{body}"
        );
    }
    server.abort();
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
async fn coolify_driven_endpoint_reconcile_route_is_removed() {
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
        .bearer_auth("internal-secret")
        .json(&serde_json::json!({
            "server_id": "server-1",
            "command_id": "endpoint-1",
            "owner_node_ip": "10.240.0.2",
            "endpoints": []
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    server.abort();
}

#[tokio::test]
async fn corrosion_reconcile_route_forwards_the_node_dns_name() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_CORROSION_RECONCILE.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!(
                "http://{address}/v1/commands/discovery.corrosion.reconcile"
            ))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "corrosion-1",
                "version": "v1.0.0",
                "cluster_id": "cluster-one",
                "bind_address": "10.240.0.2",
                "peers": ["10.240.0.3:8787"],
                "node_dns_name": "worker-1",
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(sentinel_protocol::control::v1::control_message::Message::Command(command)) =
        message.message
    else {
        panic!("expected a command");
    };
    let Some(sentinel_protocol::control::v1::command::Payload::CorrosionReconcile(payload)) =
        command.payload
    else {
        panic!("expected a Corrosion reconcile payload");
    };
    assert_eq!(payload.node_dns_name, "worker-1");
    assert_eq!(payload.bind_address, "10.240.0.2");
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "corrosion-1:result".into(),
                command_id: "corrosion-1".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: now_millis(),
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::CorrosionReconcile(
                        sentinel_protocol::control::v1::CorrosionReconcileResult {
                            state: Some(sentinel_protocol::control::v1::CorrosionInspectResult {
                                version: "v1.0.0".into(),
                                member_state: "joining".into(),
                                endpoint_count: 0,
                                last_convergence_unix_seconds: None,
                                alive_member_count: Some(1),
                            }),
                            changed: true,
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["member_state"], "joining");
    assert_eq!(body["alive_member_count"], 1);
    server.abort();
}

#[tokio::test]
async fn corrosion_reconcile_route_requires_the_node_dns_name() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        ConnectionRegistry::default(),
        "internal-secret".into(),
    ));

    let response = reqwest::Client::new()
        .post(format!(
            "http://{address}/v1/commands/discovery.corrosion.reconcile"
        ))
        .bearer_auth("internal-secret")
        .json(&serde_json::json!({
            "server_id": "server-1",
            "command_id": "corrosion-1",
            "version": "v1.0.0",
            "cluster_id": "cluster-one",
            "bind_address": "10.240.0.2",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    server.abort();
}

#[test]
fn validates_and_canonicalizes_workload_pull_policy() {
    use crate::internal_api::workload_pull_policy;

    assert_eq!(workload_pull_policy("").unwrap(), "");
    assert_eq!(workload_pull_policy("missing").unwrap(), "");
    assert_eq!(workload_pull_policy("newer").unwrap(), "newer");
    assert_eq!(workload_pull_policy("always").unwrap(), "always");
    for invalid in ["never", "Newer", "newer --privileged", " always"] {
        assert_eq!(
            workload_pull_policy(invalid).unwrap_err().0,
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
    }
}

#[tokio::test]
async fn workload_deploy_route_rejects_an_invalid_pull_policy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        ConnectionRegistry::default(),
        "internal-secret".into(),
    ));
    let deploy = |pull_policy: Option<&str>| {
        let mut body = serde_json::json!({
            "server_id": "server-1",
            "command_id": "deploy-1",
            "name": "coolify-test-web",
            "image": "docker.io/library/nginx:latest",
            "restart_policy": "unless-stopped",
        });
        if let Some(pull_policy) = pull_policy {
            body["pull_policy"] = pull_policy.into();
        }
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/workload.deploy"))
            .bearer_auth("internal-secret")
            .json(&body)
            .send()
    };

    assert_eq!(
        deploy(Some("never")).await.unwrap().status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY
    );
    for accepted in [
        None,
        Some(""),
        Some("missing"),
        Some("newer"),
        Some("always"),
    ] {
        assert_eq!(
            deploy(accepted).await.unwrap().status(),
            reqwest::StatusCode::NOT_FOUND,
            "{accepted:?} should pass validation and reach dispatch"
        );
    }
    server.abort();
}

#[tokio::test]
async fn workload_deploy_route_returns_the_sentinel_failure_message() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![sentinel_protocol::CAPABILITY_WORKLOAD_DEPLOY.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/workload.deploy"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "deploy-1",
                "name": "coolify-test-web",
                "image": "docker.io/library/nginx:latest",
                "restart_policy": "unless-stopped",
            }))
            .send(),
    );

    receiver.recv().await.unwrap();
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "deploy-1:result".into(),
                command_id: "deploy-1".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Failed.into(),
                observed_at_unix_ms: now_millis(),
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::Error(
                        sentinel_protocol::control::v1::CommandError {
                            code: "workload_deploy_failed".into(),
                            message: "listen tcp4 10.240.0.2:8080: bind: address already in use"
                                .into(),
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.text().await.unwrap(),
        "listen tcp4 10.240.0.2:8080: bind: address already in use"
    );
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

#[tokio::test]
async fn trust_bundle_update_route_forwards_the_bundle_and_returns_the_installed_version() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let bundle = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/trust.bundle.update"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "trust-bundle-3",
                "version": 3,
                "bundle_pem": bundle,
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(sentinel_protocol::control::v1::control_message::Message::Command(command)) =
        message.message
    else {
        panic!("expected a command");
    };
    assert_eq!(command.command_id, "trust-bundle-3");
    assert_eq!(
        command.command_type,
        sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE
    );
    assert!(matches!(
        &command.payload,
        Some(sentinel_protocol::control::v1::command::Payload::TrustBundleUpdate(
            sentinel_protocol::control::v1::TrustBundleUpdateRequest { version: 3, bundle_pem }
        )) if bundle_pem == bundle
    ));
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "trust-bundle-3:result".into(),
                command_id: "trust-bundle-3".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: 1_700_000_000_500,
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::TrustBundleUpdate(
                        sentinel_protocol::control::v1::TrustBundleUpdateResult {
                            installed_version: 3,
                            changed: true,
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "command_id": "trust-bundle-3",
            "observed_at_unix_ms": 1_700_000_000_500_i64,
            "installed_version": 3,
            "changed": true,
        })
    );
    server.abort();
}

#[tokio::test]
async fn trust_bundle_update_route_validates_the_request_and_capability() {
    let registry = ConnectionRegistry::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry,
        "internal-secret".into(),
    ));
    let send = |token: &str, body: serde_json::Value| {
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/trust.bundle.update"))
            .bearer_auth(token)
            .json(&body)
            .send()
    };
    let body = |server_id: &str, command_id: &str, version: u64, bundle: &str| serde_json::json!({"server_id": server_id, "command_id": command_id, "version": version, "bundle_pem": bundle});
    let pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";

    for (token, request, status) in [
        (
            "wrong",
            body("server-1", "trust-1", 2, pem),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            "wrong",
            body("server-1", "trust-1", 0, pem),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            "internal-secret",
            body("server-1", "trust-1", 0, pem),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            body("server-1", "trust-1", 2, " "),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            body("server-1", "trust-1", 2, &"A".repeat(64 * 1024 + 1)),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            body("server-1", "bad id!", 2, pem),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            body("offline", "trust-1", 2, pem),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "internal-secret",
            body("server-1", "trust-1", 2, pem),
            reqwest::StatusCode::CONFLICT,
        ),
    ] {
        assert_eq!(send(token, request.clone()).await.unwrap().status(), status);
    }
    server.abort();
}

#[test]
fn negotiates_the_trust_bundle_update_capability_when_granted() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE.into()],
        boot_id: "boot-1".into(),
        trust_bundle_version: 2,
    };

    assert_eq!(
        negotiate(&claims, &hello).unwrap().capabilities,
        vec![sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE]
    );
}

#[tokio::test]
async fn ingress_reconcile_route_forwards_routes_and_names_and_returns_the_ingress_state() {
    use sentinel_protocol::control::v1::{
        CommandResult, CommandStatus, IngressReconcileRequest, IngressReconcileResult,
        IngressRoute, WorkloadName, command::Payload, command_result, control_message::Message,
    };

    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![sentinel_protocol::CAPABILITY_INGRESS_RECONCILE.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/ingress.reconcile"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "ingress-7",
                "enabled": true,
                "caddy_version": "v2.11.7",
                "revision": 7,
                "routes": [
                    {"host": "app.example.com", "workload_id": "web", "namespace": "default", "port": 3000},
                    {"host": "api.example.com", "workload_id": "api", "namespace": "default", "port": 8080}
                ],
                "names": [
                    {"name": "frontend", "workload_id": "web", "namespace": "default"}
                ],
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(Message::Command(command)) = message.message else {
        panic!("expected a command");
    };
    assert_eq!(command.command_id, "ingress-7");
    assert_eq!(
        command.command_type,
        sentinel_protocol::CAPABILITY_INGRESS_RECONCILE
    );
    assert_eq!(
        command.payload,
        Some(Payload::IngressReconcile(IngressReconcileRequest {
            enabled: true,
            caddy_version: "v2.11.7".into(),
            revision: 7,
            routes: vec![
                IngressRoute {
                    host: "app.example.com".into(),
                    workload_id: "web".into(),
                    namespace: "default".into(),
                    port: 3000,
                },
                IngressRoute {
                    host: "api.example.com".into(),
                    workload_id: "api".into(),
                    namespace: "default".into(),
                    port: 8080,
                },
            ],
            names: vec![WorkloadName {
                name: "frontend".into(),
                workload_id: "web".into(),
                namespace: "default".into(),
            }],
        }))
    );
    registry
        .complete(
            "server-1",
            CommandResult {
                event_id: "ingress-7:result".into(),
                command_id: "ingress-7".into(),
                status: CommandStatus::Succeeded.into(),
                observed_at_unix_ms: 1_700_000_000_500,
                payload: Some(command_result::Payload::IngressReconcile(
                    IngressReconcileResult {
                        enabled: true,
                        caddy_version: "v2.11.7".into(),
                        active: true,
                        revision: 7,
                        route_count: 2,
                        name_count: 1,
                    },
                )),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "command_id": "ingress-7",
            "observed_at_unix_ms": 1_700_000_000_500_i64,
            "enabled": true,
            "caddy_version": "v2.11.7",
            "active": true,
            "revision": 7,
            "route_count": 2,
            "name_count": 1,
        })
    );
    server.abort();
}

#[tokio::test]
async fn ingress_reconcile_route_requires_auth_a_valid_request_and_the_capability() {
    let registry = ConnectionRegistry::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry,
        "internal-secret".into(),
    ));
    let body = |server_id: &str, command_id: &str| {
        serde_json::json!({
            "server_id": server_id,
            "command_id": command_id,
            "enabled": false,
        })
    };

    for (token, request, status) in [
        (
            "wrong",
            body("server-1", "ingress-1"),
            reqwest::StatusCode::UNAUTHORIZED,
        ),
        (
            "internal-secret",
            body("server-1", "bad id!"),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            serde_json::json!({"server_id": "server-1", "command_id": "ingress-1"}),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            body("offline", "ingress-1"),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "internal-secret",
            body("server-1", "ingress-1"),
            reqwest::StatusCode::CONFLICT,
        ),
    ] {
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/ingress.reconcile"))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{request}");
    }
    server.abort();
}

#[test]
fn negotiates_the_ingress_reconcile_capability_when_granted() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![sentinel_protocol::CAPABILITY_INGRESS_RECONCILE.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![sentinel_protocol::CAPABILITY_INGRESS_RECONCILE.into()],
        boot_id: "boot-1".into(),
        trust_bundle_version: 2,
    };

    assert_eq!(
        negotiate(&claims, &hello).unwrap().capabilities,
        vec![sentinel_protocol::CAPABILITY_INGRESS_RECONCILE]
    );
    let ungranted = CredentialClaims {
        capabilities: vec![],
        ..claims
    };
    assert!(
        negotiate(&ungranted, &hello)
            .unwrap()
            .capabilities
            .is_empty()
    );
}

#[tokio::test]
async fn container_logs_route_returns_the_container_output() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![sentinel_protocol::CAPABILITY_CONTAINER_LOGS.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/container.logs"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "container-logs-1",
                "name": "coolify-app",
                "lines": 200,
                "since_unix_seconds": 1_700_000_000,
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(sentinel_protocol::control::v1::control_message::Message::Command(command)) =
        message.message
    else {
        panic!("expected a command");
    };
    assert_eq!(command.command_id, "container-logs-1");
    assert_eq!(
        command.command_type,
        sentinel_protocol::CAPABILITY_CONTAINER_LOGS
    );
    assert_eq!(command.payload_version, 1);
    assert_eq!(
        command.payload,
        Some(
            sentinel_protocol::control::v1::command::Payload::ContainerLogs(
                sentinel_protocol::control::v1::ContainerLogsRequest {
                    name: "coolify-app".into(),
                    lines: 200,
                    since_unix_seconds: Some(1_700_000_000),
                }
            )
        )
    );
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "container-logs-1:result".into(),
                command_id: "container-logs-1".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
                observed_at_unix_ms: 1_700_000_000_500,
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::ContainerLogs(
                        sentinel_protocol::control::v1::ContainerLogsResult {
                            name: "coolify-app".into(),
                            logs: "2026-10-06T10:00:00.000000001Z ready\n".into(),
                            truncated: true,
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap(),
        serde_json::json!({
            "command_id": "container-logs-1",
            "observed_at_unix_ms": 1_700_000_000_500_i64,
            "name": "coolify-app",
            "logs": "2026-10-06T10:00:00.000000001Z ready\n",
            "truncated": true,
        })
    );
    server.abort();
}

#[tokio::test]
async fn container_logs_route_omits_since_and_reports_sentinel_errors() {
    let registry = ConnectionRegistry::default();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![sentinel_protocol::CAPABILITY_CONTAINER_LOGS.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry.clone(),
        "internal-secret".into(),
    ));
    let request = tokio::spawn(
        reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/container.logs"))
            .bearer_auth("internal-secret")
            .json(&serde_json::json!({
                "server_id": "server-1",
                "command_id": "container-logs-2",
                "name": "unmanaged",
                "lines": 10,
            }))
            .send(),
    );

    let message = receiver.recv().await.unwrap();
    let Some(sentinel_protocol::control::v1::control_message::Message::Command(command)) =
        message.message
    else {
        panic!("expected a command");
    };
    assert!(matches!(
        command.payload,
        Some(
            sentinel_protocol::control::v1::command::Payload::ContainerLogs(
                sentinel_protocol::control::v1::ContainerLogsRequest {
                    since_unix_seconds: None,
                    lines: 10,
                    ..
                }
            )
        )
    ));
    registry
        .complete(
            "server-1",
            sentinel_protocol::control::v1::CommandResult {
                event_id: "container-logs-2:result".into(),
                command_id: "container-logs-2".into(),
                status: sentinel_protocol::control::v1::CommandStatus::Failed.into(),
                observed_at_unix_ms: 1,
                payload: Some(
                    sentinel_protocol::control::v1::command_result::Payload::Error(
                        sentinel_protocol::control::v1::CommandError {
                            code: "container_logs_failed".into(),
                            message: "The container is not managed by Coolify.".into(),
                        },
                    ),
                ),
            },
        )
        .await;

    let response = request.await.unwrap().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.text().await.unwrap(),
        "The container is not managed by Coolify."
    );
    server.abort();
}

#[tokio::test]
async fn container_logs_route_validates_auth_the_request_and_the_capability() {
    let registry = ConnectionRegistry::default();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    registry
        .insert(
            "server-1",
            "connection-1",
            sender,
            1,
            vec![CAPABILITY_SYSTEM_PING.into()],
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_internal_api(
        listener,
        registry,
        "internal-secret".into(),
    ));
    let valid = serde_json::json!({
        "server_id": "server-1",
        "command_id": "container-logs-1",
        "name": "coolify-app",
        "lines": 100,
    });
    let with = |field: &str, value: serde_json::Value| {
        let mut body = valid.clone();
        body[field] = value;
        body
    };

    for (token, body, status) in [
        ("wrong", valid.clone(), reqwest::StatusCode::UNAUTHORIZED),
        (
            "internal-secret",
            with("name", "".into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("name", ".hidden".into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("name", "a;rm -rf /".into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("name", "a".repeat(129).into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("lines", 0.into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("lines", 10_001.into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("since_unix_seconds", 0.into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("since_unix_seconds", (-5).into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("command_id", "bad id!".into()),
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "internal-secret",
            with("server_id", "offline".into()),
            reqwest::StatusCode::NOT_FOUND,
        ),
        (
            "internal-secret",
            valid.clone(),
            reqwest::StatusCode::CONFLICT,
        ),
    ] {
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/commands/container.logs"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{token} {body}");
    }
    server.abort();
}

#[test]
fn negotiates_the_container_logs_capability_when_granted() {
    let claims = CredentialClaims {
        subject: "server-1".into(),
        capabilities: vec![sentinel_protocol::CAPABILITY_CONTAINER_LOGS.into()],
        protocol_min: 1,
        protocol_max: 1,
        expires_at: i64::MAX,
    };
    let hello = sentinel_protocol::control::v1::Hello {
        server_id: "server-1".into(),
        sentinel_version: "main".into(),
        protocol_min: 1,
        protocol_max: 1,
        capabilities: vec![sentinel_protocol::CAPABILITY_CONTAINER_LOGS.into()],
        boot_id: "boot-1".into(),
        trust_bundle_version: 2,
    };

    assert_eq!(
        negotiate(&claims, &hello).unwrap().capabilities,
        vec![sentinel_protocol::CAPABILITY_CONTAINER_LOGS]
    );
    let ungranted = CredentialClaims {
        capabilities: vec![],
        ..claims
    };
    assert!(
        negotiate(&ungranted, &hello)
            .unwrap()
            .capabilities
            .is_empty()
    );
}
