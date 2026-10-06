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
fn watches_container_runtime_events_and_builds_typed_notifications() {
    assert_eq!(
        crate::connection::podman_event_args(),
        [
            "events",
            "--filter",
            "type=container",
            "--format",
            "{{json .}}"
        ]
    );
    let message = crate::connection::runtime_changed_message(1_700_000_000_000);
    assert!(matches!(
        message.message,
        Some(sentinel_protocol::control::v1::agent_message::Message::RuntimeChanged(event))
            if event.observed_at_unix_ms == 1_700_000_000_000
                && event.event_id.starts_with("runtime-1700000000000-")
    ));
}

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
fn executes_typed_wireguard_inspection_without_exposing_a_private_key() {
    use sentinel_protocol::control::v1::command::Payload;
    use sentinel_protocol::control::v1::command_result;
    use sentinel_protocol::control::v1::{Command, CommandStatus, WireguardInspectRequest};

    let root = tempfile::tempdir().unwrap();
    let mut executor = crate::commands::CommandExecutor::new("dev").with_network_root(root.path());
    let execution = executor.execute(
        Command {
            command_id: "network-inspect-1".into(),
            command_type: sentinel_protocol::CAPABILITY_WIREGUARD_INSPECT.into(),
            payload_version: 1,
            created_at_unix_ms: 1,
            payload: Some(Payload::WireguardInspect(WireguardInspectRequest {
                interface: "coolify0".into(),
                expected_revision: 1,
                expected_hash: "expected".into(),
            })),
            expires_at_unix_ms: i64::MAX,
        },
        true,
    );

    assert!(execution.accepted);
    assert_eq!(execution.result.status, CommandStatus::Succeeded as i32);
    let Some(command_result::Payload::WireguardInspect(state)) = execution.result.payload else {
        panic!("missing inspection result")
    };
    assert_eq!(state.interface, "coolify0");
    assert!(state.drifted);
    assert!(!format!("{state:?}").to_lowercase().contains("private"));
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
                && result.cpu_usage_percent.is_some_and(|value| (0.0..=100.0).contains(&value))
                && result.memory_used_bytes.is_some()
                && result.memory_available_bytes.is_some()
                && result.load_average_one.is_some_and(|value| value >= 0.0)
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
    assert_eq!(request.body["trust_bundle_version"], 1);
    assert_eq!(
        request.body["capabilities"],
        json!([
            "system.ping.v1",
            "system.info.v1",
            "container.list.v1",
            "workload.deploy.v1",
            "workload.resources.v1",
            "workload.lifecycle.v1",
            "logs.read.v1",
            "container.logs.v1",
            "trust.bundle.update.v1",
            "network.cluster.leave.v1",
            "network.wireguard.key.ensure.v1",
            "network.wireguard.inspect.v1",
            "network.wireguard.reconcile.v1",
            "network.firewall.inspect.v1",
            "network.firewall.reconcile.v1",
            "discovery.corrosion.inspect.v1",
            "discovery.corrosion.reconcile.v1",
            "ingress.reconcile.v1"
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
fn refreshes_flux_credentials_before_they_expire() {
    let now = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();

    assert_eq!(
        crate::connection::credential_refresh_delay(now + time::Duration::minutes(15), now),
        Duration::from_secs(14 * 60)
    );
    assert_eq!(
        crate::connection::credential_refresh_delay(now + time::Duration::seconds(30), now),
        Duration::from_secs(1)
    );
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
fn command_recovery_ignores_dispatch_timestamps() {
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let first_command = durable_ping_command("recovered-command", "nonce");
    let first = crate::commands::CommandExecutor::with_journal("dev", journal.clone())
        .execute(first_command, true);
    let mut recovery_command = durable_ping_command("recovered-command", "nonce");
    recovery_command.created_at_unix_ms = 123_456;
    recovery_command.expires_at_unix_ms = i64::MAX - 1;

    let recovered = crate::commands::CommandExecutor::with_journal("dev", journal)
        .execute(recovery_command, true);

    assert!(recovered.accepted);
    assert_eq!(first.result, recovered.result);
}

fn corrosion_reconcile_command(
    command_id: &str,
    node_dns_name: &str,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_CORROSION_RECONCILE.into(),
        payload_version: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::CorrosionReconcile(
                sentinel_protocol::control::v1::CorrosionReconcileRequest {
                    version: "v1.0.0".into(),
                    cluster_id: "cluster-one".into(),
                    bind_address: "10.240.0.2".into(),
                    peers: vec![],
                    node_dns_name: node_dns_name.into(),
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}

#[test]
fn corrosion_reconcile_command_writes_the_node_dns_name() {
    let root = tempfile::tempdir().unwrap();

    let execution = crate::commands::CommandExecutor::new("dev")
        .with_network_root(root.path())
        .execute(corrosion_reconcile_command("corrosion-1", "worker-1"), true);

    assert!(execution.accepted);
    assert_eq!(
        execution.result.status,
        sentinel_protocol::control::v1::CommandStatus::Succeeded as i32
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("etc/corrosion/coolify-node-name")).unwrap(),
        "worker-1\n"
    );
}

#[test]
fn corrosion_reconcile_command_rejects_a_missing_or_invalid_node_dns_name() {
    for (index, invalid) in ["", "worker.1", "-worker"].into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();

        let execution = crate::commands::CommandExecutor::new("dev")
            .with_network_root(root.path())
            .execute(
                corrosion_reconcile_command(&format!("corrosion-invalid-{index}"), invalid),
                true,
            );

        assert!(!execution.accepted);
        assert!(!root.path().join("etc/corrosion/coolify-node-name").exists());
        assert!(!root.path().join("etc/corrosion/config.toml").exists());
    }
}

#[test]
fn the_coolify_driven_endpoint_reconcile_command_is_no_longer_accepted() {
    let command = sentinel_protocol::control::v1::Command {
        command_id: "endpoint-snapshot-1".into(),
        command_type: "discovery.corrosion.endpoints.reconcile.v1".into(),
        payload_version: 1,
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    };

    let execution = crate::commands::CommandExecutor::new("dev").execute(command, true);

    assert!(!execution.accepted);
}

#[test]
fn interrupted_durable_commands_are_not_executed_again() {
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let command = durable_ping_command("interrupted-command", "nonce");
    journal
        .start(
            &command.command_id,
            &crate::commands::journal_request(&command),
            1,
        )
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
        .start(
            &command.command_id,
            &crate::commands::journal_request(&command),
            1,
        )
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
        network_name: "coolify-node-1".into(),
        network_subnet: "100.64.0.0/24".into(),
        container_ip: "100.64.0.2".into(),
        dns_server: "10.240.0.2".into(),
        cpu_limit: Some(2.5),
        cpu_reservation: Some(1.25),
        memory_limit_bytes: Some(1_073_741_824),
        memory_reservation_bytes: Some(536_870_912),
        pull_policy: "newer".into(),
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
            .any(|v| v == ["--network", "coolify-node-1"])
    );
    assert!(arguments.windows(2).any(|v| v == ["--pull", "newer"]));
    assert!(arguments.windows(2).any(|v| v == ["--ip", "100.64.0.2"]));
    // The MAC follows the address, so neighbor caches stay valid across restarts.
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--mac-address", "02:42:64:40:00:02"])
    );
    assert!(arguments.windows(2).any(|v| v == ["--dns", "10.240.0.2"]));
    assert!(arguments.windows(2).any(|v| v == ["--cpus", "2.5"]));
    assert!(arguments.windows(2).any(|v| v == ["--cpu-shares", "1280"]));
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--memory", "1073741824b"])
    );
    assert!(
        arguments
            .windows(2)
            .any(|v| v == ["--memory-reservation", "536870912b"])
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
fn validates_the_existing_podman_network_subnet() {
    let correct = br#"[{"name":"coolify-node-1","subnets":[{"subnet":"100.64.0.0/24","gateway":"100.64.0.1"}]}]"#;
    let wrong = br#"[{"name":"coolify-node-1","subnets":[{"subnet":"100.65.0.0/24"}]}]"#;

    assert!(crate::commands::network_inspect_has_subnet(
        correct,
        "100.64.0.0/24"
    ));
    assert!(!crate::commands::network_inspect_has_subnet(
        wrong,
        "100.64.0.0/24"
    ));
    assert!(!crate::commands::network_inspect_has_subnet(
        b"not-json",
        "100.64.0.0/24"
    ));
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

#[test]
fn uses_the_requested_image_pull_policy() {
    let request = |pull_policy: &str| sentinel_protocol::control::v1::WorkloadDeployRequest {
        name: "safe-name".into(),
        image: "docker.io/library/nginx:latest".into(),
        restart_policy: "unless-stopped".into(),
        pull_policy: pull_policy.into(),
        ..Default::default()
    };
    let pull = |pull_policy: &str| {
        let arguments = crate::commands::podman_deploy_args(&request(pull_policy)).unwrap();
        let index = arguments.iter().position(|v| v == "--pull").unwrap();
        assert_eq!(arguments.iter().filter(|v| *v == "--pull").count(), 1);
        arguments[index + 1].clone()
    };

    assert_eq!(pull(""), "missing");
    assert_eq!(pull("missing"), "missing");
    assert_eq!(pull("newer"), "newer");
    assert_eq!(pull("always"), "always");
    for invalid in ["never", "Newer", "newer --privileged", " always"] {
        assert!(crate::commands::podman_deploy_args(&request(invalid)).is_err());
    }
}

#[test]
fn rejects_invalid_workload_resource_settings() {
    let request = |cpu_limit, cpu_reservation, memory_limit_bytes, memory_reservation_bytes| {
        sentinel_protocol::control::v1::WorkloadDeployRequest {
            name: "safe-name".into(),
            image: "docker.io/library/alpine:latest".into(),
            restart_policy: "unless-stopped".into(),
            cpu_limit,
            cpu_reservation,
            memory_limit_bytes,
            memory_reservation_bytes,
            ..Default::default()
        }
    };

    assert!(crate::commands::podman_deploy_args(&request(Some(0.0), None, None, None)).is_err());
    assert!(
        crate::commands::podman_deploy_args(&request(Some(f64::NAN), None, None, None)).is_err()
    );
    assert!(
        crate::commands::podman_deploy_args(&request(Some(1.0), Some(2.0), None, None)).is_err()
    );
    assert!(
        crate::commands::podman_deploy_args(&request(None, None, Some(1024), Some(2048))).is_err()
    );
    assert!(crate::commands::podman_deploy_args(&request(None, None, Some(0), None)).is_err());
}

#[test]
fn builds_shell_free_podman_lifecycle_arguments() {
    use sentinel_protocol::control::v1::{WorkloadLifecycleAction, WorkloadLifecycleRequest};

    let request = |action| WorkloadLifecycleRequest {
        name: "coolify-test-web".into(),
        action,
    };

    assert_eq!(
        crate::commands::podman_lifecycle_args(&request(WorkloadLifecycleAction::Start.into()))
            .unwrap(),
        ["start", "coolify-test-web"]
    );
    assert_eq!(
        crate::commands::podman_lifecycle_args(&request(WorkloadLifecycleAction::Stop.into()))
            .unwrap(),
        ["stop", "--time", "10", "coolify-test-web"]
    );
    assert_eq!(
        crate::commands::podman_lifecycle_args(&request(WorkloadLifecycleAction::Restart.into()))
            .unwrap(),
        ["restart", "--time", "10", "coolify-test-web"]
    );
    assert_eq!(
        crate::commands::podman_lifecycle_args(&request(WorkloadLifecycleAction::Remove.into()))
            .unwrap(),
        ["rm", "--force", "coolify-test-web"]
    );
}

#[test]
fn rejects_unsafe_workload_lifecycle_requests() {
    use sentinel_protocol::control::v1::WorkloadLifecycleRequest;

    assert!(
        crate::commands::podman_lifecycle_args(&WorkloadLifecycleRequest {
            name: "bad name".into(),
            action: 1
        })
        .is_err()
    );
    assert!(
        crate::commands::podman_lifecycle_args(&WorkloadLifecycleRequest {
            name: "coolify-safe".into(),
            action: 0
        })
        .is_err()
    );
}

fn logs_read_command(
    command_id: &str,
    source: sentinel_protocol::control::v1::LogSource,
    limit: u32,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_LOGS_READ.into(),
        payload_version: 1,
        payload: Some(sentinel_protocol::control::v1::command::Payload::LogsRead(
            sentinel_protocol::control::v1::LogsReadRequest {
                source: source.into(),
                limit,
            },
        )),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}

#[test]
fn executes_sentinel_logs_read_commands() {
    use sentinel_protocol::control::v1::LogSource;
    use sentinel_protocol::control::v1::command_result;

    let execution = crate::commands::CommandExecutor::new("dev")
        .execute(logs_read_command("logs-1", LogSource::Sentinel, 5), true);

    assert!(execution.accepted);
    assert!(matches!(
        execution.result.payload,
        Some(command_result::Payload::LogsRead(result))
            if result.source == LogSource::Sentinel as i32 && result.events.len() <= 5
    ));
}

#[test]
fn rejects_invalid_logs_read_requests() {
    use sentinel_protocol::control::v1::LogSource;

    for (index, (source, limit)) in [
        (LogSource::Sentinel, 0),
        (LogSource::Sentinel, 501),
        (LogSource::Unspecified, 10),
    ]
    .into_iter()
    .enumerate()
    {
        let execution = crate::commands::CommandExecutor::new("dev").execute(
            logs_read_command(&format!("logs-invalid-{index}"), source, limit),
            true,
        );
        assert!(!execution.accepted, "{source:?} {limit}");
    }
    let mut command = logs_read_command("logs-unknown-source", LogSource::Sentinel, 10);
    if let Some(sentinel_protocol::control::v1::command::Payload::LogsRead(request)) =
        command.payload.as_mut()
    {
        request.source = 99;
    }
    assert!(
        !crate::commands::CommandExecutor::new("dev")
            .execute(command, true)
            .accepted
    );
    assert!(
        !crate::commands::CommandExecutor::new("dev")
            .execute(
                logs_read_command("logs-not-granted", LogSource::Sentinel, 10),
                false
            )
            .accepted
    );
}

#[test]
fn log_buffer_keeps_the_newest_events_within_its_limits() {
    use sentinel_protocol::control::v1::LogEvent;

    let buffer = crate::logs::LogBuffer::new();
    for index in 0..2_100 {
        buffer.push(LogEvent {
            timestamp_unix_ms: index,
            level: "info".into(),
            message: format!("event {index}"),
            ..Default::default()
        });
    }
    let (events, truncated) = buffer.newest(3);
    assert!(truncated);
    assert_eq!(
        events
            .iter()
            .map(|event| event.timestamp_unix_ms)
            .collect::<Vec<_>>(),
        [2_097, 2_098, 2_099]
    );
    let (events, _) = buffer.newest(usize::MAX);
    assert_eq!(events.len(), 2_000);
    assert_eq!(events[0].timestamp_unix_ms, 100);

    let buffer = crate::logs::LogBuffer::new();
    for index in 0..400 {
        buffer.push(LogEvent {
            timestamp_unix_ms: index,
            message: "x".repeat(4 * 1024),
            ..Default::default()
        });
    }
    let (events, _) = buffer.newest(usize::MAX);
    assert!(events.len() < 400 && events.len() > 200);
    assert_eq!(events.last().unwrap().timestamp_unix_ms, 399);
    assert!(
        events
            .iter()
            .map(|event| event.message.len())
            .sum::<usize>()
            <= 1024 * 1024
    );

    let (events, truncated) = crate::logs::LogBuffer::new().newest(10);
    assert!(events.is_empty() && !truncated);
}

#[test]
fn redacts_secrets_from_log_text() {
    use crate::logs::redact_text;

    let jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJzZXJ2ZXItMSJ9.c2lnbmF0dXJlLXZhbHVl";
    for (input, expected) in [
        (
            "Authorization: Bearer abc.def-123",
            "Authorization: Bearer [redacted]",
        ),
        ("sent bearer s3cr3t now", "sent bearer [redacted] now"),
        (&format!("credential {jwt}."), "credential [redacted]."),
        (
            "token=abc123 password=\"hunter 2\" user=root",
            "token=[redacted] password=[redacted] user=root",
        ),
        (
            "https://host/cb?api_key=abc&x=1",
            "https://host/cb?api_key=[redacted]&x=1",
        ),
        (
            "authorization=Bearer abc123 next",
            "authorization=[redacted] next",
        ),
        (
            "DB_PASSWORD=pw, COOKIE=c; ENVIRONMENT=prod",
            "DB_PASSWORD=[redacted], COOKIE=[redacted]; ENVIRONMENT=[redacted]",
        ),
        (
            "Sentinel 1.0.2 connected to flux.coolify.io with id=42",
            "Sentinel 1.0.2 connected to flux.coolify.io with id=42",
        ),
        ("bearer", "bearer"),
        ("überbearer token", "überbearer token"),
    ] {
        assert_eq!(redact_text(input), expected, "{input}");
    }
    assert!(crate::logs::is_secret_name("private_key"));
    assert!(crate::logs::is_secret_name("X-Auth-Token"));
    assert!(!crate::logs::is_secret_name("connection_id"));
}

#[test]
fn log_layer_records_redacted_bounded_events_that_pass_the_filter() {
    use tracing_subscriber::layer::SubscriberExt;

    let buffer: &'static crate::logs::LogBuffer =
        Box::leak(Box::new(crate::logs::LogBuffer::new()));
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(crate::logs::log_layer_for(buffer));
    tracing::subscriber::with_default(subscriber, || {
        tracing::debug!("filtered out");
        tracing::info!(
            target: "control::connection",
            token = "abc",
            transport = "Tls",
            long = %"y".repeat(5_000),
            "connected with password={}",
            "hunter2"
        );
        tracing::warn!(message = %"z".repeat(10_000));
        tracing::error!(
            f0 = 0,
            f1 = 1,
            f2 = 2,
            f3 = 3,
            f4 = 4,
            f5 = 5,
            f6 = 6,
            f7 = 7,
            f8 = 8,
            f9 = 9,
            f10 = 10,
            f11 = 11,
            f12 = 12,
            f13 = 13,
            f14 = 14,
            f15 = 15,
            f16 = 16,
            f17 = 17,
            "many fields"
        );
    });

    let (events, truncated) = buffer.newest(10);
    assert!(!truncated);
    assert_eq!(events.len(), 3);
    let event = &events[0];
    assert_eq!(event.level, "info");
    assert_eq!(event.component, "control::connection");
    assert_eq!(event.message, "connected with password=[redacted]");
    assert_eq!(event.fields["token"], "[redacted]");
    assert_eq!(event.fields["transport"], "Tls");
    assert_eq!(event.fields["long"].len(), 1024);
    assert!(event.timestamp_unix_ms > 0);
    assert_eq!(events[1].level, "warn");
    assert_eq!(events[1].message.len(), 4 * 1024);
    assert_eq!(events[2].level, "error");
    assert_eq!(events[2].fields.len(), 16);
}

#[test]
fn builds_fixed_shell_free_journalctl_arguments() {
    assert_eq!(
        crate::logs::journal_args("corrosion.service", 11),
        [
            "--unit",
            "corrosion.service",
            "--no-pager",
            "--quiet",
            "--output",
            "json",
            "--lines",
            "11"
        ]
    );
}

#[test]
fn parses_journald_json_output() {
    let output = concat!(
        "-- No entries --\n",
        r#"{"__REALTIME_TIMESTAMP":"1700000000000001","PRIORITY":"6","MESSAGE":"first","_PID":"10"}"#,
        "\n",
        r#"{"__REALTIME_TIMESTAMP":"1700000001000000","PRIORITY":"3","MESSAGE":"failed token=abc","_PID":"10"}"#,
        "\n",
        r#"{"__REALTIME_TIMESTAMP":"1700000002000000","PRIORITY":"4","MESSAGE":[104,105,255]}"#,
        "\n",
        r#"{"__REALTIME_TIMESTAMP":"1700000003000000","PRIORITY":"7","MESSAGE":"debug"}"#,
        "\n",
        r#"{"__REALTIME_TIMESTAMP":"1700000004000000","MESSAGE":"no priority"}"#,
        "\n",
    );

    let (events, truncated) =
        crate::logs::parse_journal(output.as_bytes(), "coolify-discovery-dns.service", 4);

    assert!(truncated);
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].timestamp_unix_ms, 1_700_000_001_000);
    assert_eq!(events[0].level, "error");
    assert_eq!(events[0].message, "failed token=[redacted]");
    assert_eq!(events[0].component, "coolify-discovery-dns");
    assert_eq!(events[0].fields["_PID"], "10");
    assert_eq!(events[1].level, "warn");
    assert_eq!(events[1].message, "hi\u{fffd}");
    assert!(events[1].fields.is_empty());
    assert_eq!(events[2].level, "debug");
    assert_eq!(events[3].level, "info");

    let (events, truncated) = crate::logs::parse_journal(b"", "corrosion.service", 10);
    assert!(events.is_empty() && !truncated);
}

#[test]
fn logs_read_commands_are_not_journaled_but_other_commands_are() {
    use sentinel_protocol::control::v1::LogSource;

    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let mut executor = crate::commands::CommandExecutor::with_journal("dev", journal.clone());
    let logs = logs_read_command("logs-unjournaled", LogSource::Sentinel, 10);
    let ping = durable_ping_command("ping-journaled", "nonce");

    assert!(executor.execute(logs.clone(), true).accepted);
    assert!(executor.execute(logs.clone(), true).accepted);
    assert!(executor.execute(ping.clone(), true).accepted);

    assert!(matches!(
        journal.lookup(&logs.command_id, &crate::commands::journal_request(&logs)),
        Ok(store::CommandLookup::Missing)
    ));
    assert!(matches!(
        journal.lookup(&ping.command_id, &crate::commands::journal_request(&ping)),
        Ok(store::CommandLookup::Completed(_))
    ));
}

/// A fake Podman that logs `<subcommand> <marker present|absent>` for the
/// container named by its last argument, at the moment it runs.
fn fake_podman(root: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = root.join("fake-podman");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nfor last in \"$@\"; do :; done\nif [ -e '{root}/var/lib/coolify/workloads/stopped/'\"$last\"'.stopped' ]; then marker=present; else marker=absent; fi\necho \"$1 $marker\" >> '{root}/podman.log'\nif [ -e '{root}/podman-fails' ]; then echo 'podman failed' >&2; exit 125; fi\nif [ \"$1\" = run ]; then echo 0123abcd; fi\n",
            root = root.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    script
}

fn workload_lifecycle_command(
    command_id: &str,
    name: &str,
    action: sentinel_protocol::control::v1::WorkloadLifecycleAction,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_WORKLOAD_LIFECYCLE.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::WorkloadLifecycle(
                sentinel_protocol::control::v1::WorkloadLifecycleRequest {
                    name: name.into(),
                    action: action.into(),
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
    }
}

fn workload_deploy_command(
    command_id: &str,
    name: &str,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_WORKLOAD_DEPLOY.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::WorkloadDeploy(
                sentinel_protocol::control::v1::WorkloadDeployRequest {
                    name: name.into(),
                    image: "docker.io/library/alpine:latest".into(),
                    restart_policy: "unless-stopped".into(),
                    ..Default::default()
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
    }
}

fn podman_log(root: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(root.join("podman.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn stop_marker(root: &std::path::Path, name: &str) -> PathBuf {
    root.join("var/lib/coolify/workloads/stopped")
        .join(format!("{name}.stopped"))
}

#[test]
fn workload_commands_keep_a_durable_stop_marker() {
    use sentinel_protocol::control::v1::CommandStatus;
    use sentinel_protocol::control::v1::WorkloadLifecycleAction::{Remove, Restart, Start, Stop};

    let root = tempfile::tempdir().unwrap();
    let podman = fake_podman(root.path());
    let mut executor = crate::commands::CommandExecutor::new("dev")
        .with_network_root(root.path())
        .with_podman(&podman);
    let marker = stop_marker(root.path(), "coolify-web");
    let mut run = |command| {
        let execution = executor.execute(command, true);
        assert_eq!(
            execution.result.status,
            CommandStatus::Succeeded as i32,
            "{:?}",
            execution.result
        );
    };

    run(workload_lifecycle_command("stop-1", "coolify-web", Stop));
    assert!(marker.exists());
    run(workload_lifecycle_command("start-1", "coolify-web", Start));
    assert!(!marker.exists());

    run(workload_lifecycle_command("stop-2", "coolify-web", Stop));
    run(workload_lifecycle_command(
        "restart-1",
        "coolify-web",
        Restart,
    ));
    assert!(!marker.exists());

    run(workload_lifecycle_command("stop-3", "coolify-web", Stop));
    run(workload_lifecycle_command(
        "remove-1",
        "coolify-web",
        Remove,
    ));
    assert!(!marker.exists());

    run(workload_lifecycle_command("stop-4", "coolify-web", Stop));
    run(workload_deploy_command("deploy-1", "coolify-web"));
    assert!(!marker.exists());

    // The marker exists while Podman stops the workload, and is removed only
    // after Podman started, restarted or removed it.
    assert_eq!(
        podman_log(root.path()),
        [
            "stop present",
            "start present",
            "stop present",
            "restart present",
            "stop present",
            "rm present",
            "stop present",
            "run absent",
        ]
    );

    // Other workloads keep their own markers.
    run(workload_lifecycle_command("stop-5", "coolify-api", Stop));
    run(workload_lifecycle_command("start-2", "coolify-web", Start));
    assert!(stop_marker(root.path(), "coolify-api").exists());
}

#[test]
fn failed_workload_commands_leave_the_prior_stop_intent() {
    use sentinel_protocol::control::v1::CommandStatus;
    use sentinel_protocol::control::v1::WorkloadLifecycleAction::{Start, Stop};

    let root = tempfile::tempdir().unwrap();
    let podman = fake_podman(root.path());
    let mut executor = crate::commands::CommandExecutor::new("dev")
        .with_network_root(root.path())
        .with_podman(&podman);
    let marker = stop_marker(root.path(), "coolify-web");
    let fails = root.path().join("podman-fails");

    // A failed stop of a running workload removes the marker it created.
    std::fs::write(&fails, "").unwrap();
    let failed = executor.execute(
        workload_lifecycle_command("stop-1", "coolify-web", Stop),
        true,
    );
    assert_eq!(failed.result.status, CommandStatus::Failed as i32);
    assert!(!marker.exists());
    assert_eq!(podman_log(root.path()), ["stop present"]);

    // A failed stop of a workload already stopped on purpose keeps the marker.
    std::fs::remove_file(&fails).unwrap();
    executor.execute(
        workload_lifecycle_command("stop-2", "coolify-web", Stop),
        true,
    );
    std::fs::write(&fails, "").unwrap();
    let failed = executor.execute(
        workload_lifecycle_command("stop-3", "coolify-web", Stop),
        true,
    );
    assert_eq!(failed.result.status, CommandStatus::Failed as i32);
    assert!(marker.exists());

    // Failed starts and deploys keep it too.
    let failed = executor.execute(
        workload_lifecycle_command("start-1", "coolify-web", Start),
        true,
    );
    assert_eq!(failed.result.status, CommandStatus::Failed as i32);
    let failed = executor.execute(workload_deploy_command("deploy-1", "coolify-web"), true);
    assert_eq!(failed.result.status, CommandStatus::Failed as i32);
    assert!(marker.exists());
}

#[test]
fn workload_commands_reject_names_that_cannot_be_a_stop_marker() {
    use sentinel_protocol::control::v1::CommandStatus;
    use sentinel_protocol::control::v1::WorkloadLifecycleAction::Stop;

    let root = tempfile::tempdir().unwrap();
    let podman = fake_podman(root.path());
    let mut executor = crate::commands::CommandExecutor::new("dev")
        .with_network_root(root.path())
        .with_podman(&podman);

    for (index, name) in ["..", ".", ".hidden", "-web", "a/b", "", "bad name"]
        .into_iter()
        .enumerate()
    {
        let stop = executor.execute(
            workload_lifecycle_command(&format!("stop-{index}"), name, Stop),
            true,
        );
        let deploy = executor.execute(
            workload_deploy_command(&format!("deploy-{index}"), name),
            true,
        );
        assert_ne!(
            stop.result.status,
            CommandStatus::Succeeded as i32,
            "{name}"
        );
        assert_ne!(
            deploy.result.status,
            CommandStatus::Succeeded as i32,
            "{name}"
        );
    }
    assert!(podman_log(root.path()).is_empty());
    assert!(!root.path().join("var/lib/coolify/workloads").exists());
}

fn test_ca_pem(expired: bool) -> String {
    let now = time::OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.not_before = now - time::Duration::days(2);
    params.not_after = if expired {
        now - time::Duration::days(1)
    } else {
        now + time::Duration::days(1)
    };
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap())
        .unwrap()
        .pem()
}

fn trust_directory_config(
    root: &tempfile::TempDir,
    bundle: &str,
    version: u64,
) -> config::ControlTlsConfig {
    let ca_path = root.path().join("sentinel-flux-ca.pem");
    std::fs::write(&ca_path, bundle).unwrap();
    std::fs::write(
        root.path().join("sentinel-flux-ca.version"),
        format!("{version}\n"),
    )
    .unwrap();
    control_tls_config(ca_path, 1)
}

fn trust_bundle_update_command(
    command_id: &str,
    version: u64,
    bundle_pem: &str,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_TRUST_BUNDLE_UPDATE.into(),
        payload_version: 1,
        created_at_unix_ms: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::TrustBundleUpdate(
                sentinel_protocol::control::v1::TrustBundleUpdateRequest {
                    version,
                    bundle_pem: bundle_pem.into(),
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
    }
}

#[test]
fn validates_trust_bundles_as_bounded_lists_of_ca_certificates() {
    let first = test_ca_pem(false);
    let second = test_ca_pem(false);
    let leaf = test_tls_material(&["127.0.0.1"]).server_pem;

    assert_eq!(
        crate::trust::validate_bundle(&format!("{first}{second}")),
        Ok(2)
    );
    for (name, bundle) in [
        ("empty", String::new()),
        ("garbage", "not a certificate".to_string()),
        (
            "invalid DER",
            "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_string(),
        ),
        ("leaf certificate", format!("{first}{leaf}")),
        ("expired CA", test_ca_pem(true)),
        (
            "private key",
            format!("{first}{}", KeyPair::generate().unwrap().serialize_pem()),
        ),
        ("stray text", format!("{first}trailing text\n")),
        (
            "unterminated",
            first
                .trim_end()
                .trim_end_matches("-----END CERTIFICATE-----")
                .to_string(),
        ),
        (
            "too many",
            first.repeat(crate::trust::MAX_BUNDLE_CERTIFICATES + 1),
        ),
        (
            "too large",
            format!("{first}{}", "\n".repeat(crate::trust::MAX_BUNDLE_BYTES)),
        ),
    ] {
        assert!(
            crate::trust::validate_bundle(&bundle).is_err(),
            "{name} must be rejected"
        );
    }
}

#[test]
fn installs_a_newer_trust_bundle_atomically_and_keeps_the_previous_one() {
    let root = tempfile::tempdir().unwrap();
    let old = test_ca_pem(false);
    let new = test_ca_pem(false);
    let config = trust_directory_config(&root, &old, 3);
    let dual = format!("{old}{new}");

    assert_eq!(crate::trust::installed_version(&config), 3);
    assert_eq!(
        crate::trust::install(&config, 4, &dual),
        Ok(crate::trust::TrustBundleUpdate {
            installed_version: 4,
            changed: true,
        })
    );

    assert_eq!(std::fs::read_to_string(&config.ca_path).unwrap(), dual);
    assert_eq!(crate::trust::installed_version(&config), 4);
    assert_eq!(
        std::fs::read_to_string(root.path().join("sentinel-flux-ca.pem.previous")).unwrap(),
        old
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("sentinel-flux-ca.version.previous")).unwrap(),
        "3\n"
    );
    assert!(!root.path().join("sentinel-flux-ca.pem.update").exists());
    assert!(!root.path().join("sentinel-flux-ca.version.update").exists());
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&config.ca_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    // Re-delivery of the installed bundle is an idempotent no-op.
    assert_eq!(
        crate::trust::install(&config, 4, &dual),
        Ok(crate::trust::TrustBundleUpdate {
            installed_version: 4,
            changed: false,
        })
    );
}

#[test]
fn rejects_trust_bundle_downgrades_and_conflicting_versions() {
    let root = tempfile::tempdir().unwrap();
    let old = test_ca_pem(false);
    let config = trust_directory_config(&root, &old, 5);
    let other = test_ca_pem(false);

    assert!(crate::trust::install(&config, 4, &other).is_err());
    assert!(crate::trust::install(&config, 5, &other).is_err());
    assert!(crate::trust::install(&config, 6, "garbage").is_err());
    assert_eq!(std::fs::read_to_string(&config.ca_path).unwrap(), old);
    assert_eq!(crate::trust::installed_version(&config), 5);
}

#[test]
fn falls_back_to_the_configured_trust_bundle_version_without_a_version_file() {
    let root = tempfile::tempdir().unwrap();
    let ca_path = root.path().join("sentinel-flux-ca.pem");
    std::fs::write(&ca_path, test_ca_pem(false)).unwrap();

    assert_eq!(
        crate::trust::installed_version(&control_tls_config(ca_path.clone(), 7)),
        7
    );
    std::fs::write(root.path().join("sentinel-flux-ca.version"), "garbage").unwrap();
    assert_eq!(
        crate::trust::installed_version(&control_tls_config(ca_path, 7)),
        7
    );
}

#[test]
fn restores_the_previous_trust_bundle_when_the_version_cannot_be_written() {
    let root = tempfile::tempdir().unwrap();
    let old = test_ca_pem(false);
    let ca_path = root.path().join("sentinel-flux-ca.pem");
    std::fs::write(&ca_path, &old).unwrap();
    // A non-empty directory in place of the version file makes the final rename fail.
    let version_path = root.path().join("sentinel-flux-ca.version");
    std::fs::create_dir(&version_path).unwrap();
    std::fs::write(version_path.join("blocker"), "x").unwrap();
    let config = control_tls_config(ca_path.clone(), 1);

    let result = crate::trust::install(&config, 2, &format!("{old}{}", test_ca_pem(false)));

    assert!(result.unwrap_err().contains("previous bundle was restored"));
    assert_eq!(std::fs::read_to_string(&ca_path).unwrap(), old);
    assert_eq!(crate::trust::installed_version(&config), 1);
    assert!(!root.path().join("sentinel-flux-ca.pem.update").exists());
    assert!(!root.path().join("sentinel-flux-ca.version.update").exists());
}

#[test]
fn executes_capability_gated_trust_bundle_updates() {
    use sentinel_protocol::control::v1::command_result;

    let root = tempfile::tempdir().unwrap();
    let old = test_ca_pem(false);
    let config = trust_directory_config(&root, &old, 1);
    let dual = format!("{old}{}", test_ca_pem(false));
    let mut executor =
        crate::commands::CommandExecutor::new("dev").with_control_tls(config.clone());

    let refused = executor.execute(trust_bundle_update_command("trust-0", 2, &dual), false);
    assert!(!refused.accepted);
    assert_eq!(crate::trust::installed_version(&config), 1);

    let installed = executor.execute(trust_bundle_update_command("trust-1", 2, &dual), true);
    assert!(installed.accepted);
    assert!(matches!(
        installed.result.payload,
        Some(command_result::Payload::TrustBundleUpdate(result))
            if result.installed_version == 2 && result.changed
    ));

    let downgrade = executor.execute(trust_bundle_update_command("trust-2", 1, &old), true);
    assert_eq!(
        downgrade.result.status,
        sentinel_protocol::control::v1::CommandStatus::Failed as i32
    );
    assert!(matches!(
        downgrade.result.payload,
        Some(command_result::Payload::Error(error)) if error.code == "trust_bundle_update_failed"
    ));

    let mut without_trust = crate::commands::CommandExecutor::new("dev");
    let unavailable = without_trust.execute(trust_bundle_update_command("trust-3", 2, &dual), true);
    assert!(matches!(
        unavailable.result.payload,
        Some(command_result::Payload::Error(error)) if error.code == "trust_bundle_unavailable"
    ));
}

#[tokio::test]
async fn reconnects_with_an_updated_trust_bundle_without_a_restart() {
    let material = test_tls_material(&["127.0.0.1"]);
    let root = tempfile::tempdir().unwrap();
    let old = test_ca_pem(false);
    let config = trust_directory_config(&root, &old, 1);
    let endpoint = start_tls_server("127.0.0.1:0", &material).await;

    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &config).await,
        Err(FluxConnectionError::Connection)
    ));

    let mut executor =
        crate::commands::CommandExecutor::new("dev").with_control_tls(config.clone());
    let update = executor.execute(
        trust_bundle_update_command("trust-1", 2, &format!("{old}{}", material.ca_pem)),
        true,
    );
    assert_eq!(
        update.result.status,
        sentinel_protocol::control::v1::CommandStatus::Succeeded as i32
    );

    let reconnected = crate::connection::connect_endpoint(&endpoint, &config).await;
    assert!(reconnected.is_ok(), "{reconnected:?}");
    assert_eq!(crate::trust::installed_version(&config), 2);
}

fn ingress_reconcile_command(
    command_id: &str,
    request: sentinel_protocol::control::v1::IngressReconcileRequest,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_INGRESS_RECONCILE.into(),
        payload_version: 1,
        payload: Some(sentinel_protocol::control::v1::command::Payload::IngressReconcile(request)),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}

fn ingress_request(
    enabled: bool,
    caddy_version: &str,
    host: &str,
) -> sentinel_protocol::control::v1::IngressReconcileRequest {
    sentinel_protocol::control::v1::IngressReconcileRequest {
        enabled,
        caddy_version: caddy_version.into(),
        revision: 2,
        routes: vec![sentinel_protocol::control::v1::IngressRoute {
            host: host.into(),
            workload_id: "web".into(),
            namespace: "default".into(),
            port: 3000,
        }],
    }
}

#[test]
fn executes_capability_gated_ingress_reconciles_and_wakes_the_renderer() {
    use sentinel_protocol::control::v1::command_result;

    let root = tempfile::tempdir().unwrap();
    for (file, contents) in [
        ("etc/corrosion/coolify-owner", "10.240.0.2\n"),
        ("etc/corrosion/coolify-node-name", "worker-1\n"),
    ] {
        let path = root.path().join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let trigger = Arc::new(tokio::sync::Notify::new());
    let mut executor = crate::commands::CommandExecutor::new("dev")
        .with_network_root(root.path())
        .with_ingress_trigger(trigger.clone());
    let state = root.path().join("var/lib/coolify/network/ingress.state");

    let refused = executor.execute(
        ingress_reconcile_command(
            "ingress-0",
            ingress_request(true, "v2.11.7", "app.example.com"),
        ),
        false,
    );
    assert!(!refused.accepted);
    assert!(!state.exists());

    for (index, request) in [
        ingress_request(true, "v2.11.7", "10.0.0.1"),
        ingress_request(true, "v2.11.7", "*.example.com"),
        ingress_request(true, "v2.11.7", "App.example.com"),
    ]
    .into_iter()
    .enumerate()
    {
        let invalid = executor.execute(
            ingress_reconcile_command(&format!("ingress-invalid-{index}"), request),
            true,
        );
        assert!(!invalid.accepted);
    }
    assert!(!state.exists());

    let wrong_version = executor.execute(
        ingress_reconcile_command(
            "ingress-1",
            ingress_request(true, "v2.10.0", "app.example.com"),
        ),
        true,
    );
    assert!(wrong_version.accepted);
    assert!(matches!(
        wrong_version.result.payload,
        Some(command_result::Payload::Error(error))
            if error.code == "ingress_reconcile_failed" && error.message.contains("v2.11.7")
    ));
    assert!(!state.exists());

    let enabled = executor.execute(
        ingress_reconcile_command(
            "ingress-2",
            ingress_request(true, "v2.11.7", "app.example.com"),
        ),
        true,
    );
    assert_eq!(
        enabled.result.payload,
        Some(command_result::Payload::IngressReconcile(
            sentinel_protocol::control::v1::IngressReconcileResult {
                enabled: true,
                caddy_version: "v2.11.7".into(),
                active: false,
                revision: 2,
                route_count: 1,
            }
        ))
    );
    assert!(state.exists());
    // The renderer was woken: a stored permit completes immediately.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), trigger.notified())
            .await
            .unwrap();
    });

    let disabled = executor.execute(
        ingress_reconcile_command("ingress-3", ingress_request(false, "", "app.example.com")),
        true,
    );
    assert!(matches!(
        disabled.result.payload,
        Some(command_result::Payload::IngressReconcile(result)) if !result.enabled && !result.active
    ));
    assert!(!state.exists());
    assert!(!root.path().join("etc/coolify-ingress/caddy.json").exists());
    assert!(
        !root
            .path()
            .join("etc/systemd/system/coolify-ingress.service")
            .exists()
    );
}

#[test]
fn container_mac_addresses_are_stable_locally_administered_and_unique_per_address() {
    let mac = crate::commands::container_mac_address("100.64.3.254".parse().unwrap());

    assert_eq!(mac, "02:42:64:40:03:fe");
    assert_eq!(
        mac,
        crate::commands::container_mac_address("100.64.3.254".parse().unwrap())
    );
    assert_ne!(
        mac,
        crate::commands::container_mac_address("100.64.3.253".parse().unwrap())
    );
    // Locally administered unicast: bit 1 of the first octet set, bit 0 clear.
    assert_eq!(u8::from_str_radix(&mac[..2], 16).unwrap() & 0b11, 0b10);
}

const MANAGED_CONTAINER_ID: &str =
    "4f1c2b0e9d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";

/// A fake Podman for `container.logs.v1`. It records its arguments, answers
/// `container inspect` for `coolify-app` (managed), `unmanaged`, and anything
/// else (missing), and prints interleaved stdout and stderr lines for `logs`.
fn fake_logs_podman(root: &std::path::Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = root.join("fake-podman");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
echo "$@" >> '{root}/podman.log'
if [ "$1 $2" = "container inspect" ]; then
  case "$3" in
    coolify-app) echo '[{{"Id":"{id}","Name":"coolify-app","Config":{{"Labels":{{"coolify.managed":"true"}}}}}}]' ;;
    unmanaged) echo '[{{"Id":"{id}","Name":"unmanaged","Config":{{"Labels":{{"coolify.managed":"false"}}}}}}]' ;;
    *) echo '[]'; echo "Error: no such container $3" >&2; exit 125 ;;
  esac
  exit 0
fi
if [ "$1" = logs ]; then
  echo '2026-10-06T10:00:00.000000001Z out one'
  echo '2026-10-06T10:00:00.000000002Z err one' >&2
  echo '2026-10-06T10:00:00.000000003Z out two'
  echo '2026-10-06T10:00:00.000000004Z err two' >&2
  exit 0
fi
exit 125
"#,
            root = root.display(),
            id = MANAGED_CONTAINER_ID,
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    script
}

fn container_logs_command(
    command_id: &str,
    name: &str,
    lines: u32,
    since_unix_seconds: Option<i64>,
) -> sentinel_protocol::control::v1::Command {
    sentinel_protocol::control::v1::Command {
        command_id: command_id.into(),
        command_type: sentinel_protocol::CAPABILITY_CONTAINER_LOGS.into(),
        payload_version: 1,
        payload: Some(
            sentinel_protocol::control::v1::command::Payload::ContainerLogs(
                sentinel_protocol::control::v1::ContainerLogsRequest {
                    name: name.into(),
                    lines,
                    since_unix_seconds,
                },
            ),
        ),
        expires_at_unix_ms: i64::MAX,
        ..Default::default()
    }
}

fn command_error_message(result: &sentinel_protocol::control::v1::CommandResult) -> String {
    match &result.payload {
        Some(sentinel_protocol::control::v1::command_result::Payload::Error(error)) => {
            assert_eq!(error.code, "container_logs_failed");
            error.message.clone()
        }
        other => panic!("expected a command error, got {other:?}"),
    }
}

#[test]
fn validates_container_logs_requests() {
    use sentinel_protocol::control::v1::ContainerLogsRequest;

    let valid = ContainerLogsRequest {
        name: "coolify-app".into(),
        lines: 100,
        since_unix_seconds: None,
    };
    assert!(crate::container_logs::validate(&valid).is_ok());
    for lines in [1, 10_000] {
        assert!(
            crate::container_logs::validate(&ContainerLogsRequest {
                lines,
                ..valid.clone()
            })
            .is_ok()
        );
    }
    assert!(
        crate::container_logs::validate(&ContainerLogsRequest {
            since_unix_seconds: Some(1),
            ..valid.clone()
        })
        .is_ok()
    );

    for name in [
        "",
        ".hidden",
        "-flag",
        "a b",
        "a;rm",
        "a/b",
        "$(id)",
        &"a".repeat(129),
    ] {
        assert!(
            crate::container_logs::validate(&ContainerLogsRequest {
                name: name.into(),
                ..valid.clone()
            })
            .is_err(),
            "{name}"
        );
    }
    for lines in [0, 10_001] {
        assert!(
            crate::container_logs::validate(&ContainerLogsRequest {
                lines,
                ..valid.clone()
            })
            .is_err(),
            "{lines}"
        );
    }
    for since in [0, -1] {
        assert!(
            crate::container_logs::validate(&ContainerLogsRequest {
                since_unix_seconds: Some(since),
                ..valid.clone()
            })
            .is_err(),
            "{since}"
        );
    }
}

#[test]
fn rejects_invalid_or_ungranted_container_logs_commands() {
    for (index, (name, lines, since)) in [
        ("", 10, None),
        ("bad name", 10, None),
        ("coolify-app", 0, None),
        ("coolify-app", 10_001, None),
        ("coolify-app", 10, Some(0)),
    ]
    .into_iter()
    .enumerate()
    {
        let execution = crate::commands::CommandExecutor::new("dev").execute(
            container_logs_command(
                &format!("container-logs-invalid-{index}"),
                name,
                lines,
                since,
            ),
            true,
        );
        assert!(!execution.accepted, "{name} {lines} {since:?}");
    }
    assert!(
        !crate::commands::CommandExecutor::new("dev")
            .execute(
                container_logs_command("container-logs-not-granted", "coolify-app", 10, None),
                false
            )
            .accepted
    );
}

#[test]
fn builds_podman_container_logs_arguments_without_a_shell() {
    assert_eq!(
        crate::container_logs::podman_inspect_args("coolify-app"),
        ["container", "inspect", "coolify-app"]
    );
    assert_eq!(
        crate::container_logs::podman_logs_args(MANAGED_CONTAINER_ID, 100, None),
        [
            "logs",
            "--timestamps",
            "--tail",
            "100",
            MANAGED_CONTAINER_ID
        ]
    );
    assert_eq!(
        crate::container_logs::podman_logs_args(MANAGED_CONTAINER_ID, 5, Some(1_700_000_000)),
        [
            "logs",
            "--timestamps",
            "--tail",
            "5",
            "--since",
            "1700000000",
            MANAGED_CONTAINER_ID
        ]
    );
}

#[test]
fn only_reads_logs_of_containers_managed_by_coolify() {
    let managed = |labels: Value| {
        serde_json::to_vec(&json!([{
            "Id": MANAGED_CONTAINER_ID,
            "Name": "coolify-app",
            "Config": {"Labels": labels}
        }]))
        .unwrap()
    };

    assert_eq!(
        crate::container_logs::managed_container_id(&managed(json!({"coolify.managed": "true"})))
            .unwrap(),
        MANAGED_CONTAINER_ID
    );
    for labels in [
        json!({"coolify.managed": "false"}),
        json!({"coolify.managed": "TRUE"}),
        json!({"coolify.managed": true}),
        json!({"other": "true"}),
        json!({}),
        Value::Null,
    ] {
        assert_eq!(
            crate::container_logs::managed_container_id(&managed(labels.clone())).unwrap_err(),
            "The container is not managed by Coolify.",
            "{labels}"
        );
    }
    assert_eq!(
        crate::container_logs::managed_container_id(b"[]").unwrap_err(),
        "The container does not exist."
    );
    assert_eq!(
        crate::container_logs::managed_container_id(b"not json").unwrap_err(),
        "Podman returned invalid container data."
    );
    let bad_id = serde_json::to_vec(&json!([{
        "Id": "abc; rm -rf /",
        "Config": {"Labels": {"coolify.managed": "true"}}
    }]))
    .unwrap();
    assert_eq!(
        crate::container_logs::managed_container_id(&bad_id).unwrap_err(),
        "Podman returned invalid container data."
    );
}

#[test]
fn container_logs_truncation_keeps_the_newest_whole_lines() {
    let output = b"line one\nline two\nline three\n";

    assert_eq!(
        crate::container_logs::keep_newest(output, output.len()),
        (&output[..], false)
    );
    // The cut lands inside "line two", so the partial line is dropped too.
    assert_eq!(
        crate::container_logs::keep_newest(output, 16),
        (&b"line three\n"[..], true)
    );
    // The cut lands exactly on a line start.
    assert_eq!(
        crate::container_logs::keep_newest(output, 20),
        (&b"line two\nline three\n"[..], true)
    );
    // One line longer than the limit keeps its newest bytes.
    assert_eq!(
        crate::container_logs::keep_newest(b"0123456789", 4),
        (&b"6789"[..], true)
    );

    let lines: Vec<u8> = (0..50_000)
        .flat_map(|index| format!("2026-10-06T10:00:00Z line {index}\n").into_bytes())
        .collect();
    let streamed = crate::container_logs::read_newest(std::io::Cursor::new(&lines), 1_000).unwrap();
    assert!(streamed.len() <= 2 * 1_001);
    let (kept, truncated) = crate::container_logs::keep_newest(&streamed, 1_000);
    assert!(truncated);
    assert_eq!(kept, crate::container_logs::keep_newest(&lines, 1_000).0);
    assert!(kept.len() <= 1_000);
    assert!(kept.ends_with(b"line 49999\n"));
    assert!(kept.starts_with(b"2026-10-06T10:00:00Z line "));
}

#[test]
fn reads_managed_container_logs_with_stdout_and_stderr_in_order() {
    use sentinel_protocol::control::v1::command_result;

    let root = tempfile::tempdir().unwrap();
    let podman = fake_logs_podman(root.path());
    let mut executor = crate::commands::CommandExecutor::new("dev").with_podman(&podman);

    let execution = executor.execute(
        container_logs_command("container-logs-1", "coolify-app", 100, Some(1_700_000_000)),
        true,
    );

    assert!(execution.accepted);
    let Some(command_result::Payload::ContainerLogs(result)) = execution.result.payload else {
        panic!(
            "expected container logs, got {:?}",
            execution.result.payload
        );
    };
    assert_eq!(result.name, "coolify-app");
    assert!(!result.truncated);
    assert_eq!(
        result.logs,
        "2026-10-06T10:00:00.000000001Z out one\n\
         2026-10-06T10:00:00.000000002Z err one\n\
         2026-10-06T10:00:00.000000003Z out two\n\
         2026-10-06T10:00:00.000000004Z err two\n"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("podman.log")).unwrap(),
        format!(
            "container inspect coolify-app\nlogs --timestamps --tail 100 --since 1700000000 {MANAGED_CONTAINER_ID}\n"
        )
    );
}

#[test]
fn refuses_to_read_logs_of_unmanaged_or_missing_containers() {
    let root = tempfile::tempdir().unwrap();
    let podman = fake_logs_podman(root.path());
    let mut executor = crate::commands::CommandExecutor::new("dev").with_podman(&podman);

    let unmanaged = executor.execute(
        container_logs_command("container-logs-unmanaged", "unmanaged", 10, None),
        true,
    );
    assert!(unmanaged.accepted);
    assert_eq!(
        command_error_message(&unmanaged.result),
        "The container is not managed by Coolify."
    );

    let missing = executor.execute(
        container_logs_command("container-logs-missing", "missing", 10, None),
        true,
    );
    assert!(missing.accepted);
    assert_eq!(
        command_error_message(&missing.result),
        "The container does not exist."
    );

    // Podman never read the logs of either container.
    assert_eq!(
        std::fs::read_to_string(root.path().join("podman.log")).unwrap(),
        "container inspect unmanaged\ncontainer inspect missing\n"
    );
}

#[test]
fn container_logs_commands_are_not_journaled() {
    let root = tempfile::tempdir().unwrap();
    let podman = fake_logs_podman(root.path());
    let journal = store::CommandJournal::open_in_memory(7, 100_000).unwrap();
    let mut executor =
        crate::commands::CommandExecutor::with_journal("dev", journal.clone()).with_podman(&podman);
    let logs = container_logs_command("container-logs-unjournaled", "coolify-app", 10, None);

    assert!(executor.execute(logs.clone(), true).accepted);
    assert!(executor.execute(logs.clone(), true).accepted);

    assert!(matches!(
        journal.lookup(&logs.command_id, &crate::commands::journal_request(&logs)),
        Ok(store::CommandLookup::Missing)
    ));
    // A repeated ID reads the logs again instead of replaying a result.
    assert_eq!(
        std::fs::read_to_string(root.path().join("podman.log"))
            .unwrap()
            .matches("logs --timestamps")
            .count(),
        2
    );
}
