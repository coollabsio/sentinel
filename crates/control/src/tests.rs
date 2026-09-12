use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use prost::Message;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use url::Url;

use super::*;

#[test]
fn executes_and_deduplicates_system_ping_commands() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::command_result;
    use sentinel_protocol::control::v1::{Command, SystemPingRequest};

    let mut executor = crate::commands::CommandExecutor::new("dev");
    let command = Command {
        command_id: "command-1".into(),
        command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(Payload::SystemPing(SystemPingRequest {
            nonce: "nonce-1".into(),
        })),
        expires_at_unix_ms: i64::MAX,
    };
    let first = executor.execute(command.clone(), true);
    let second = executor.execute(command, true);

    assert!(first.accepted);
    assert_eq!(first.result, second.result);
    assert!(matches!(
        first.result.payload,
        Some(command_result::Payload::SystemPing(result)) if result.nonce == "nonce-1" && result.sentinel_version == "dev"
    ));
}

#[test]
fn executes_system_info_commands() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::command_result;
    use sentinel_protocol::control::v1::{Command, SystemInfoRequest};

    let mut executor = crate::commands::CommandExecutor::new("dev");
    let execution = executor.execute(
        Command {
            command_id: "system-info-1".into(),
            command_type: sentinel_protocol::CAPABILITY_SYSTEM_INFO.into(),
            payload_version: 1,
            payload: Some(Payload::SystemInfo(SystemInfoRequest {})),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        },
        true,
    );

    assert!(execution.accepted);
    assert!(matches!(
        execution.result.payload,
        Some(command_result::Payload::SystemInfo(result))
            if result.sentinel_version == "dev"
                && result.cpu_count.is_some_and(|count| count > 0)
                && result.memory_bytes.is_some_and(|bytes| bytes > 0)
    ));
}

#[test]
fn system_info_prefers_podman_when_a_docker_compatibility_command_is_also_present() {
    assert_eq!(crate::commands::CONTAINER_RUNTIMES, ["podman", "docker"]);
}

#[test]
fn rejects_a_command_type_and_payload_mismatch() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::{Command, SystemInfoRequest};

    let execution = crate::commands::CommandExecutor::new("dev").execute(
        Command {
            command_id: "mismatch-1".into(),
            command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
            payload_version: 1,
            payload: Some(Payload::SystemInfo(SystemInfoRequest {})),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        },
        true,
    );

    assert!(!execution.accepted);
}

#[test]
fn rejects_expired_system_ping_commands() {
    let mut executor = crate::commands::CommandExecutor::new("dev");
    let result = executor.execute(
        sentinel_protocol::control::v1::Command {
            command_id: "expired".into(),
            command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
            expires_at_unix_ms: 1,
            ..Default::default()
        },
        true,
    );

    assert!(!result.accepted);
    assert_eq!(
        result.result.status,
        sentinel_protocol::control::v1::CommandStatus::Failed as i32
    );
}

#[test]
fn rejects_system_ping_without_a_nonce() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::{Command, SystemPingRequest};

    let mut executor = crate::commands::CommandExecutor::new("dev");
    let result = executor.execute(
        Command {
            command_id: "missing-nonce".into(),
            command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
            payload_version: 1,
            payload: Some(Payload::SystemPing(SystemPingRequest {
                nonce: String::new(),
            })),
            expires_at_unix_ms: i64::MAX,
            ..Default::default()
        },
        true,
    );

    assert!(!result.accepted);
    assert_eq!(
        result.result.status,
        sentinel_protocol::control::v1::CommandStatus::Failed as i32
    );
}

#[test]
fn rejects_a_duplicate_command_id_with_a_different_payload() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::command_result;
    use sentinel_protocol::control::v1::{Command, SystemPingRequest};

    let mut executor = crate::commands::CommandExecutor::new("dev");
    let command = |nonce: &str| Command {
        command_id: "command-1".into(),
        command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
        payload_version: 1,
        payload: Some(Payload::SystemPing(SystemPingRequest {
            nonce: nonce.into(),
        })),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    };
    executor.execute(command("first"), true);
    let duplicate = executor.execute(command("second"), true);

    assert!(!duplicate.accepted);
    assert!(matches!(
        duplicate.result.payload,
        Some(command_result::Payload::Error(error)) if error.code == "command_id_conflict"
    ));
}

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: Value,
    retry_after: Option<&'static str>,
}

#[derive(Debug, Default)]
struct CapturedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Value,
}

#[derive(Clone)]
struct TestState {
    reply: Reply,
    captured: Arc<Mutex<Option<CapturedRequest>>>,
}

async fn handler(State(state): State<TestState>, request: Request<Body>) -> Response<Body> {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = to_bytes(request.into_body(), 64 * 1024).await.unwrap();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    *state.captured.lock().unwrap() = Some(CapturedRequest {
        method,
        path,
        authorization,
        body,
    });

    let mut response = Response::builder().status(state.reply.status);
    if let Some(retry_after) = state.reply.retry_after {
        response = response.header("retry-after", retry_after);
    }
    response
        .header("content-type", "application/json")
        .body(Body::from(state.reply.body.to_string()))
        .unwrap()
}

async fn start_server(reply: Reply) -> (String, Arc<Mutex<Option<CapturedRequest>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(None));
    let app = Router::new().fallback(handler).with_state(TestState {
        reply,
        captured: captured.clone(),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{address}"), captured)
}

fn enabled_response() -> Value {
    json!({
        "enabled": true,
        "server_id": "server-uuid",
        "flux_url": "https://agent.coolify.example.com",
        "credential": "secret-flux-credential",
        "credential_expires_at": "2099-09-11T15:00:00Z",
        "protocol_min": 1,
        "protocol_max": 1,
        "heartbeat_interval_seconds": 30,
        "trust_bundle_version": 1
    })
}

async fn start_counting_disabled_server(retry_after_seconds: u64) -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let handler_requests = requests.clone();
    let app = Router::new().fallback(move || {
        let requests = handler_requests.clone();
        async move {
            requests.fetch_add(1, Ordering::SeqCst);
            axum::Json(json!({
                "enabled": false,
                "retry_after_seconds": retry_after_seconds
            }))
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{address}"), requests)
}

async fn start_stalled_server() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let handler_requests = requests.clone();
    let app = Router::new().fallback(move || {
        let requests = handler_requests.clone();
        async move {
            requests.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Response<Body>>().await
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{address}"), requests)
}

#[tokio::test]
async fn polls_again_after_a_disabled_assignment() {
    let (endpoint, requests) = start_counting_disabled_server(1).await;
    let client =
        AssignmentClient::new(&endpoint, "token", "main", test_control_tls_config()).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(client.run(shutdown_rx));

    tokio::time::timeout(Duration::from_secs(3), async {
        while requests.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_interrupts_the_assignment_retry_delay() {
    let (endpoint, requests) = start_counting_disabled_server(3600).await;
    let client =
        AssignmentClient::new(&endpoint, "token", "main", test_control_tls_config()).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(client.run(shutdown_rx));

    tokio::time::timeout(Duration::from_secs(1), async {
        while requests.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_interrupts_an_assignment_request() {
    let (endpoint, requests) = start_stalled_server().await;
    let client =
        AssignmentClient::new(&endpoint, "token", "main", test_control_tls_config()).unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(client.run(shutdown_rx));

    tokio::time::timeout(Duration::from_secs(1), async {
        while requests.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn assignment_errors_use_the_documented_retry_delays() {
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::AuthenticationRejected, 0, 0),
        Duration::from_secs(15 * 60)
    );
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::Unsupported, 0, 0),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::Incompatible, 0, 0),
        Duration::from_secs(60 * 60)
    );
    assert_eq!(
        crate::assignment::retry_delay(
            &AssignmentError::RateLimited {
                retry_after: Some(Duration::from_secs(75)),
            },
            0,
            0,
        ),
        Duration::from_secs(75)
    );
}

#[test]
fn temporary_assignment_errors_use_bounded_full_jitter() {
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::Temporary, 0, 0),
        Duration::from_secs(1)
    );
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::Temporary, 3, 7),
        Duration::from_secs(8)
    );
    assert_eq!(
        crate::assignment::retry_delay(&AssignmentError::Temporary, 20, u64::MAX),
        Duration::from_secs(16)
    );
}

#[tokio::test]
async fn sends_assignment_request_with_existing_identity_and_protocol_contract() {
    let (endpoint, captured) = start_server(Reply {
        status: StatusCode::OK,
        body: enabled_response(),
        retry_after: None,
    })
    .await;
    let client = AssignmentClient::new(
        &format!("{endpoint}/custom/base/"),
        "existing-token",
        "1.0.1",
        test_control_tls_config(),
    )
    .unwrap();

    let outcome = client.request().await.unwrap();
    assert!(matches!(outcome, AssignmentOutcome::Enabled(_)));

    let captured = captured.lock().unwrap();
    let request = captured.as_ref().unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path,
        "/custom/base/api/v1/sentinel/control/assignment"
    );
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer existing-token")
    );
    assert_eq!(request.body["sentinel_version"], "1.0.1");
    assert_eq!(request.body["protocol_min"], 1);
    assert_eq!(request.body["protocol_max"], 1);
    assert_eq!(
        request.body["capabilities"],
        json!([
            "system.ping.v1",
            "system.info.v1",
            "container.list.v1",
            "workload.deploy.v1"
        ])
    );
}

#[tokio::test]
async fn parses_enabled_assignment_and_redacts_credentials() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::OK,
        body: enabled_response(),
        retry_after: None,
    })
    .await;
    let client = AssignmentClient::new(
        &endpoint,
        "existing-token",
        "1.0.1",
        test_control_tls_config(),
    )
    .unwrap();

    let AssignmentOutcome::Enabled(assignment) = client.request().await.unwrap() else {
        panic!("expected enabled assignment");
    };

    assert_eq!(assignment.server_id(), "server-uuid");
    assert_eq!(
        assignment.flux_url().as_str(),
        "https://agent.coolify.example.com/"
    );
    assert_eq!(assignment.credential(), "secret-flux-credential");
    assert_eq!(assignment.protocol_min(), 1);
    assert_eq!(assignment.protocol_max(), 1);
    assert_eq!(assignment.heartbeat_interval(), Duration::from_secs(30));
    assert!(!format!("{assignment:?}").contains("secret-flux-credential"));
    assert!(!format!("{client:?}").contains("existing-token"));
}

#[tokio::test]
async fn parses_disabled_assignment() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::OK,
        body: json!({"enabled": false, "retry_after_seconds": 3600}),
        retry_after: None,
    })
    .await;
    let client =
        AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();

    assert!(matches!(
        client.request().await.unwrap(),
        AssignmentOutcome::Disabled { retry_after } if retry_after == Duration::from_secs(3600)
    ));
}

#[tokio::test]
async fn rejects_invalid_enabled_assignments() {
    let invalid = [
        ("empty server", "server_id", json!("")),
        ("empty credential", "credential", json!("")),
        ("invalid flux URL", "flux_url", json!("file:///tmp/flux")),
        ("invalid expiry", "credential_expires_at", json!("tomorrow")),
        ("zero protocol", "protocol_min", json!(0)),
        ("inverted protocol", "protocol_min", json!(2)),
        ("short heartbeat", "heartbeat_interval_seconds", json!(9)),
        ("long heartbeat", "heartbeat_interval_seconds", json!(121)),
        (
            "missing trust bundle version",
            "trust_bundle_version",
            Value::Null,
        ),
        (
            "zero trust bundle version",
            "trust_bundle_version",
            json!(0),
        ),
    ];

    for (name, field, value) in invalid {
        let mut body = enabled_response();
        body[field] = value;
        let (endpoint, _) = start_server(Reply {
            status: StatusCode::OK,
            body,
            retry_after: None,
        })
        .await;
        let client =
            AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();
        assert!(
            matches!(
                client.request().await,
                Err(AssignmentError::InvalidResponse(_))
            ),
            "expected invalid response for {name}"
        );
    }
}

#[tokio::test]
async fn rejects_invalid_disabled_assignment() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::OK,
        body: json!({"enabled": false, "retry_after_seconds": 0}),
        retry_after: None,
    })
    .await;
    let client =
        AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();

    assert!(matches!(
        client.request().await,
        Err(AssignmentError::InvalidResponse(_))
    ));
}

#[tokio::test]
async fn rejects_assignment_response_larger_than_64_kib() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::OK,
        body: json!({
            "enabled": false,
            "retry_after_seconds": 60,
            "padding": "x".repeat(65 * 1024)
        }),
        retry_after: None,
    })
    .await;
    let client =
        AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();

    assert!(matches!(
        client.request().await,
        Err(AssignmentError::InvalidResponse(_))
    ));
}

#[tokio::test]
async fn maps_response_statuses_to_stable_errors() {
    let cases = [
        (
            StatusCode::UNAUTHORIZED,
            AssignmentErrorKind::Authentication,
        ),
        (StatusCode::FORBIDDEN, AssignmentErrorKind::Authentication),
        (StatusCode::NOT_FOUND, AssignmentErrorKind::Unsupported),
        (StatusCode::CONFLICT, AssignmentErrorKind::Incompatible),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            AssignmentErrorKind::Temporary,
        ),
    ];

    for (status, expected) in cases {
        let (endpoint, _) = start_server(Reply {
            status,
            body: json!({"secret": "must-not-leak"}),
            retry_after: None,
        })
        .await;
        let client =
            AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();
        let error = client.request().await.unwrap_err();
        assert_eq!(error.kind(), expected);
        assert!(!error.to_string().contains("must-not-leak"));
    }
}

#[tokio::test]
async fn parses_rate_limit_retry_after_seconds() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::TOO_MANY_REQUESTS,
        body: json!({}),
        retry_after: Some("75"),
    })
    .await;
    let client =
        AssignmentClient::new(&endpoint, "token", "1.0.1", test_control_tls_config()).unwrap();

    assert!(matches!(
        client.request().await,
        Err(AssignmentError::RateLimited { retry_after: Some(retry_after) })
            if retry_after == Duration::from_secs(75)
    ));
}

#[tokio::test]
async fn maps_network_failure_to_temporary_without_exposing_token() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = AssignmentClient::new(
        &endpoint,
        "very-secret-token",
        "1.0.1",
        test_control_tls_config(),
    )
    .unwrap();

    let error = client.request().await.unwrap_err();
    assert_eq!(error.kind(), AssignmentErrorKind::Temporary);
    assert!(!error.to_string().contains("very-secret-token"));
}

#[test]
fn rejects_invalid_client_configuration_without_exposing_token() {
    for endpoint in [
        "file:///tmp/coolify",
        "https://user:password@example.com",
        "https://example.com?query=1",
        "https://example.com#fragment",
    ] {
        let error = AssignmentClient::new(
            endpoint,
            "very-secret-token",
            "1.0.1",
            test_control_tls_config(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), AssignmentErrorKind::InvalidConfiguration);
        assert!(!error.to_string().contains("very-secret-token"));
    }
}

#[test]
fn selects_flux_transport_from_assignment_url_scheme() {
    assert_eq!(
        FluxTransport::from_url(&Url::parse("http://127.0.0.1:7443").unwrap(), true).unwrap(),
        FluxTransport::Plaintext
    );
    assert_eq!(
        FluxTransport::from_url(&Url::parse("https://flux.example.com:7443").unwrap(), false)
            .unwrap(),
        FluxTransport::Tls
    );
}

struct TestTlsMaterial {
    ca_pem: String,
    server_pem: String,
    server_key_pem: String,
}

fn test_tls_material(identities: &[&str]) -> TestTlsMaterial {
    let now = time::OffsetDateTime::now_utc();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

    let mut server_params = CertificateParams::new(
        identities
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    server_params.not_before = now - time::Duration::minutes(1);
    server_params.not_after = now + time::Duration::hours(1);
    let server_key = KeyPair::generate().unwrap();
    let server = server_params.signed_by(&server_key, &ca).unwrap();

    TestTlsMaterial {
        ca_pem: ca.pem(),
        server_pem: server.pem(),
        server_key_pem: server_key.serialize_pem(),
    }
}

struct TestCaFile {
    path: PathBuf,
}

impl TestCaFile {
    fn new(pem: &str) -> Self {
        static NEXT_FILE_ID: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sentinel-control-tls-{nanos}-{id}.pem"));
        std::fs::write(&path, pem).unwrap();
        Self { path }
    }
}

impl Drop for TestCaFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn control_tls_config(ca_path: PathBuf, trust_bundle_version: u64) -> config::ControlTlsConfig {
    config::ControlTlsConfig {
        ca_path,
        trust_bundle_version,
        allow_plaintext: false,
    }
}

fn test_control_tls_config() -> config::ControlTlsConfig {
    control_tls_config(PathBuf::from("/tmp/sentinel-test-ca.pem"), 1)
}

async fn start_tls_server(bind_addr: &str, material: &TestTlsMaterial) -> Url {
    crate::connection::install_crypto_provider();
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();
    let address = listener.local_addr().unwrap();
    let certificate = material.server_pem.clone();
    let private_key = material.server_key_pem.clone();
    let (_, health_service) = tonic_health::server::health_reporter();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(
                ServerTlsConfig::new().identity(Identity::from_pem(certificate, private_key)),
            )
            .unwrap()
            .add_service(health_service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    Url::parse(&format!("https://{address}")).unwrap()
}

#[tokio::test]
async fn private_ca_connection_verifies_dns_and_ip_identities() {
    let material = test_tls_material(&["localhost", "127.0.0.1", "::1"]);
    let ca_file = TestCaFile::new(&material.ca_pem);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let ipv4_endpoint = start_tls_server("127.0.0.1:0", &material).await;
    let dns_endpoint = Url::parse(&format!(
        "https://localhost:{}",
        ipv4_endpoint.port().unwrap()
    ))
    .unwrap();
    let ipv6_endpoint = start_tls_server("[::1]:0", &material).await;

    assert!(
        crate::connection::connect_endpoint(&dns_endpoint, &tls_config)
            .await
            .is_ok()
    );
    assert!(
        crate::connection::connect_endpoint(&ipv4_endpoint, &tls_config)
            .await
            .is_ok()
    );
    let ipv6_result = crate::connection::connect_endpoint(&ipv6_endpoint, &tls_config).await;
    assert!(ipv6_result.is_ok(), "{ipv6_result:?}");
}

#[tokio::test]
async fn rejects_a_flux_server_signed_by_a_different_ca() {
    let server_material = test_tls_material(&["127.0.0.1"]);
    let wrong_material = test_tls_material(&["127.0.0.1"]);
    let ca_file = TestCaFile::new(&wrong_material.ca_pem);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let endpoint = start_tls_server("127.0.0.1:0", &server_material).await;

    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &tls_config).await,
        Err(FluxConnectionError::Connection)
    ));
}

#[tokio::test]
async fn rejects_a_flux_server_with_the_wrong_ip_identity() {
    let material = test_tls_material(&["localhost"]);
    let ca_file = TestCaFile::new(&material.ca_pem);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let ipv4_endpoint = start_tls_server("127.0.0.1:0", &material).await;
    let ipv6_endpoint = start_tls_server("[::1]:0", &material).await;

    assert!(matches!(
        crate::connection::connect_endpoint(&ipv4_endpoint, &tls_config).await,
        Err(FluxConnectionError::Connection)
    ));
    assert!(matches!(
        crate::connection::connect_endpoint(&ipv6_endpoint, &tls_config).await,
        Err(FluxConnectionError::Connection)
    ));
}

#[tokio::test]
async fn rejects_missing_or_invalid_private_ca_bundles() {
    let missing = control_tls_config(PathBuf::from("/tmp/sentinel-missing-ca.pem"), 1);
    let endpoint = Url::parse("https://127.0.0.1:7443").unwrap();
    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &missing).await,
        Err(FluxConnectionError::MissingCa)
    ));

    let invalid_file = TestCaFile::new("not a certificate");
    let invalid = control_tls_config(invalid_file.path.clone(), 1);
    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &invalid).await,
        Err(FluxConnectionError::InvalidCa)
    ));

    let invalid_der_file =
        TestCaFile::new("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n");
    let invalid_der = control_tls_config(invalid_der_file.path.clone(), 1);
    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &invalid_der).await,
        Err(FluxConnectionError::InvalidCa)
    ));
}

#[test]
fn rejects_plaintext_flux_urls_outside_development() {
    let endpoint = Url::parse("http://127.0.0.1:7443").unwrap();

    assert!(matches!(
        FluxTransport::from_url(&endpoint, false),
        Err(FluxConnectionError::PlaintextRejected)
    ));
    assert_eq!(
        FluxTransport::from_url(&endpoint, true).unwrap(),
        FluxTransport::Plaintext
    );
}

#[tokio::test]
async fn rejects_assignment_with_a_different_trust_bundle_version_before_connecting() {
    let (endpoint, _) = start_server(Reply {
        status: StatusCode::OK,
        body: json!({
            "enabled": true,
            "server_id": "server-uuid",
            "flux_url": "https://127.0.0.1:7443",
            "credential": "credential",
            "credential_expires_at": "2099-09-11T15:00:00Z",
            "protocol_min": 1,
            "protocol_max": 1,
            "heartbeat_interval_seconds": 30,
            "trust_bundle_version": 2
        }),
        retry_after: None,
    })
    .await;
    let tls_config = control_tls_config(PathBuf::from("/tmp/sentinel-missing-ca.pem"), 1);
    let client = AssignmentClient::new(&endpoint, "token", "1.0.1", tls_config.clone()).unwrap();
    let AssignmentOutcome::Enabled(assignment) = client.request().await.unwrap() else {
        panic!("expected an enabled assignment");
    };
    let (_, shutdown) = tokio::sync::watch::channel(false);
    let command_executor = Arc::new(tokio::sync::Mutex::new(
        crate::commands::CommandExecutor::new("1.0.1"),
    ));

    assert!(matches!(
        crate::connection::connect(&assignment, "1.0.1", tls_config, shutdown, command_executor,)
            .await,
        Err(FluxConnectionError::TrustBundleVersionMismatch)
    ));
}

#[test]
fn parses_podman_container_inventory() {
    let containers = crate::commands::parse_podman_containers(
        br#"[{"Id":"container-1","Image":"docker.io/library/nginx:latest","Names":["web"],"State":"running","Health":"healthy","Restarts":2,"Created":1789237060,"StartedAt":1789237061,"Labels":{"coolify.managed":"true"},"Ports":[{"host_ip":"0.0.0.0","host_port":8080,"container_port":80,"protocol":"tcp"}]}]"#,
    )
    .unwrap();

    assert_eq!(containers.len(), 1);
    let container = &containers[0];
    assert_eq!(container.runtime_id, "container-1");
    assert_eq!(container.name, "web");
    assert_eq!(container.health_status.as_deref(), Some("healthy"));
    assert_eq!(container.restart_count, Some(2));
    assert_eq!(container.created_at_unix_ms, Some(1_789_237_060_000));
    assert_eq!(container.ports[0].host_port, Some(8080));
    assert_eq!(container.labels["coolify.managed"], "true");
}

#[test]
fn rejects_invalid_podman_container_inventory() {
    assert!(crate::commands::parse_podman_containers(b"not-json").is_err());
    assert!(crate::commands::parse_podman_containers(br#"[{"Image":"alpine"}]"#).is_err());
}

fn durable_ping_command(command_id: &str, nonce: &str) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_SYSTEM_PING.into(),
        payload_version: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::SystemPing(
                sentinel_protocol::control::v1::SystemPingRequest {
                    nonce: nonce.into(),
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}

#[test]
fn command_results_replay_from_the_durable_journal_after_restart() {
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let command = durable_ping_command("durable-command", "durable-nonce");
    let first = crate::commands::CommandExecutor::with_journal("dev", journal.clone())
        .execute(command.clone(), true);
    let replayed =
        crate::commands::CommandExecutor::with_journal("dev", journal).execute(command, true);

    assert!(first.accepted);
    assert!(replayed.accepted);
    assert_eq!(first.result, replayed.result);
}

#[test]
fn interrupted_durable_commands_are_not_executed_again() {
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let command = durable_ping_command("interrupted-command", "nonce");
    journal
        .start(&command.command_id, &command.encode_to_vec(), 1)
        .unwrap();

    let execution =
        crate::commands::CommandExecutor::with_journal("dev", journal).execute(command, true);
    let Some(sentinel_protocol::control::v1::command_result::Payload::Error(error)) =
        execution.result.payload
    else {
        panic!("expected command error");
    };

    assert!(execution.accepted);
    assert_eq!(error.code, "command_interrupted");
}

#[test]
fn completed_commands_replay_after_the_request_expired() {
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let mut command = durable_ping_command("expired-replay", "nonce");
    command.expires_at_unix_ms = 1;
    let result = sentinel_protocol::control::v1::CommandResult {
        command_id: command.command_id.clone(),
        status: sentinel_protocol::control::v1::CommandStatus::Succeeded.into(),
        ..Default::default()
    };
    journal
        .start(&command.command_id, &command.encode_to_vec(), 1)
        .unwrap();
    journal
        .finish(&command.command_id, &result.encode_to_vec(), 2)
        .unwrap();

    let execution =
        crate::commands::CommandExecutor::with_journal("dev", journal).execute(command, true);

    assert!(execution.accepted);
    assert_eq!(
        execution.result.status,
        sentinel_protocol::control::v1::CommandStatus::Succeeded as i32
    );
}

#[test]
fn builds_shell_free_podman_deploy_arguments() {
    let request = sentinel_protocol::control::v1::WorkloadDeployRequest {
        name: "coolify-test-web".into(),
        image: "docker.io/library/alpine:latest".into(),
        command: vec!["sleep".into(), "3600".into()],
        environment: vec![
            sentinel_protocol::control::v1::WorkloadEnvironmentVariable {
                key: "APP_ENV".into(),
                value: "production".into(),
            },
        ],
        ports: vec![sentinel_protocol::control::v1::ContainerPort {
            host_ip: Some("127.0.0.1".into()),
            host_port: Some(18080),
            container_port: 8080,
            protocol: "tcp".into(),
        }],
        labels: vec![sentinel_protocol::control::v1::WorkloadLabel {
            key: "coolify.managed".into(),
            value: "true".into(),
        }],
        restart_policy: "unless-stopped".into(),
    };

    let arguments = crate::commands::podman_deploy_args(&request).unwrap();

    assert_eq!(arguments[0], "run");
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--name", "coolify-test-web"])
    );
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--env", "APP_ENV=production"])
    );
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--publish", "127.0.0.1:18080:8080/tcp"])
    );
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--label", "coolify.managed=true"])
    );
    assert_eq!(
        &arguments[arguments.len() - 3..],
        ["docker.io/library/alpine:latest", "sleep", "3600"]
    );
}

#[test]
fn rejects_unsafe_or_oversized_deploy_requests() {
    let request = |name: &str, image: &str| sentinel_protocol::control::v1::WorkloadDeployRequest {
        name: name.into(),
        image: image.into(),
        restart_policy: "unless-stopped".into(),
        ..Default::default()
    };

    assert!(crate::commands::podman_deploy_args(&request("bad name", "alpine")).is_err());
    assert!(crate::commands::podman_deploy_args(&request("safe-name", "")).is_err());
    assert!(crate::commands::podman_deploy_args(&request("safe-name", "alpine;rm")).is_err());
}
