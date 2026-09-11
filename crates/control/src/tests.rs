use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
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
        json!(["system.ping.v1", "system.info.v1"])
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

const CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIUDdUnU4DNANdpu0bE/+L916MX0zkwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQU2VudGluZWwgVGVzdCBDQTAeFw0yNjA5MTExOTAzMDJa
Fw0zNjA5MDgxOTAzMDJaMBsxGTAXBgNVBAMMEFNlbnRpbmVsIFRlc3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMabWYkkTqmQFyJMMrLRjOgx+T
ImvuSEuE0Eyc8AtZ6dOXvZfSwF967blusCe58jcr/SM2y5xo3NmdM3t8gJHXEQHh
h0cxl98D2J5QrTXyZfudFYxtDxOaMgUghnZBdIawrLie4I6p8M6rXMQ06Hml57Nj
V/QUIbVTOjikvnlcfy9IMBV2OZ+q6rOrKoIwdprZDn+51+F8r71Yz81IOmrzlUEn
Wyyejuy+wxup4hyldshTeNOWVD9az+I4IfrwLW7y/BHky/jhDEfja8nvWHWPXGPY
XS0kcQDPnwxYMkOAukIOoVTy/xGxubcKhlioM8pQSZ4SRWcBth3ZyVjEdhVfAgMB
AAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQW
BBQ7PY42RTQNWs72/BRVtI6h4idqczANBgkqhkiG9w0BAQsFAAOCAQEALE6K5D8C
zF+MmAQonMZjN8oybUftZwFzSY21WHl6JWAHQ1hgfLW1Kgd4OKdyJgBFMLA4Sp3/
d6ht1Lic7mmhdqgnUlEz8RY5XH6ER6ges7zdU2eNeTPRC54DkG6/28DJ8OC1vrT6
08tnbp04WJsTi6ksyI1wDLD/hPgDMtAckWj1dk8VOshmnnh2jjD6mzUsGI2RiJYy
eiFlhOtrgLZf2spcMP+iIY6Z6HcM26pRX2vlF7SYJi2b0EnbE621ASww1+YcqKxr
q4LKCiHs9vstrnVxTCDX45ujwFFYga9+jMmHwd9ue/o1vE0LrPNKza5/AwJmzGiZ
JYhQnAj6phxwyA==
-----END CERTIFICATE-----
"#;

const SERVER_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIUOQEjPftSkrJxLuWvFbttwhz5/3UwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQU2VudGluZWwgVGVzdCBDQTAeFw0yNjA5MTExOTAzMDNa
Fw0yNzA5MTExOTAzMDNaMBsxGTAXBgNVBAMMEFNlbnRpbmVsIFRlc3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeDeXUAcsjw1qbOXHwLUIfbDnm
iYLoJ3FoYNx/epyj90+b9kzyBMYtgTdmeqYGtF6IHgBk3S9G66z+NJJviJyJN3e+
nchD/V60TUAQPqc6lmSTv6RjXGFxE4jqpijzxZtLgn6D/7MzqEW8rstHfbejs5wU
B+37ZksysSesw12jANUJwfvldoNGO33x8mhLQc+kcG4YBQszlrSpTyUk0MODDcDH
Yjj3HXcAXM8UjaK9Aoomd8Yr+Q+aBfgSqObuAoynfQTfQlyNyfB4JOph7FQUy3Zz
xars5oPA0NdY65ko33ozoXipNQp6OronhS9JDiPrBETLhksQpqb5zmrqcPMpAgMB
AAGjgaQwgaEwLAYDVR0RBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG
CCsGAQUFBwMBMB0GA1UdDgQWBBTNLdHWIpmTquoYAAPFBCYKYalquzAfBgNVHSME
GDAWgBQ7PY42RTQNWs72/BRVtI6h4idqczANBgkqhkiG9w0BAQsFAAOCAQEAcnL1
XAcQp6ugInzCgOIqnBZk0y9LS6d21C7NTM+M+Kcl866yKkDjN3VhI700XNy2s6r0
tfEN7wfke1GGAUjZ+HSD0T8oGiTO0tUWX3sVesl1C1ftiePA2BCjPpuJeUwqcGDt
hGZ+oo8X8dThqujfjUbULZI8SEh2z3SGinNTPnd6kERxpfP92077+oTNlhNdPbm1
k54Mb3LAeP4yPNWam+HO/dWuaSLr0erB1iV32bVVQ4i94UDzNfDESQ2ifh6bsYDQ
QUyhZCa8RkCQYgRRflBd/3VcyFZPwxx+vvjvSLWZDH3AIHnSb3um5nfXK+prR6+A
3MnZPk8sT3Noga0Scw==
-----END CERTIFICATE-----
"#;

const SERVER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDeDeXUAcsjw1qb
OXHwLUIfbDnmiYLoJ3FoYNx/epyj90+b9kzyBMYtgTdmeqYGtF6IHgBk3S9G66z+
NJJviJyJN3e+nchD/V60TUAQPqc6lmSTv6RjXGFxE4jqpijzxZtLgn6D/7MzqEW8
rstHfbejs5wUB+37ZksysSesw12jANUJwfvldoNGO33x8mhLQc+kcG4YBQszlrSp
TyUk0MODDcDHYjj3HXcAXM8UjaK9Aoomd8Yr+Q+aBfgSqObuAoynfQTfQlyNyfB4
JOph7FQUy3Zzxars5oPA0NdY65ko33ozoXipNQp6OronhS9JDiPrBETLhksQpqb5
zmrqcPMpAgMBAAECggEABKh8z5JunYYVV5YZG3uHIAuuXAq61DNOEO1JQDHozLD5
pU2P1H5yT7kerzQwvNCLxeYOG8h0Kel0InAIgLVqIpHDrA3cyhpWjPM66Nb/Lz6k
6lJu1SLhLE3HaQlmdupzKKzFNLdk5RAMz5KBr49UHK6oviwNaaEozi3YJZWCmG7/
UeOt/3OlhGPftzRO2iVAq95qesrAMC69CYpzDYep0iWWN15+Twk0TGKd7pB6F4f7
z/WI4fe4NSrQ8ad9BY3xK+GITBjNbvU1cukj0ZXerOf/w1iH2Au62P1Y+Y5uyXzf
UKbyKwFtEL/nYTpcReDISM+JMBheZM/HHiyqw0xaxQKBgQD9IjyxCZC8dZ06SK3x
O+ZDAl0DT5XV7nGFChWDoHBsYjXBSf6Iqbbf7ta0vtw/Bn3bGLo8XQjuwqxkIDr3
iomLSL7v2uKekwGDdZEr0Kn8Vlv0x8sb3fIt0PE/0L5eI6LTuZbQgx5rSQUZOYXB
3NOzQZgToYNFHGrFXdihPMuspQKBgQDgkZH3GQT07kl32icsX5FlyT2rBF8ISD8y
3rgq8/EmbxrEzmXAGpgy6cYZc+QiFq5EtVyDDtBwtEa5bUhTEwmZuKdHoEi4FMN0
+rApFpcolkUiIm9pFWVaVDQImU88zeH6T/jYarBFj/bQ8REcou1N3Bl6zPBGcl5K
i+Cs2S5RNQKBgFrTXQl80CT+4oJWL6td/bnPcEZO2Qlgu/SrcJrBB3WsK3OGNEEe
/BIPZZSG4wnuL1xc2/3qt9jLmwV2FxJY8A88892mISgawTFFDui0vzleVzJWOcdu
9IWB8f4ezR+EE9l6PuXkFhcSpTSu0hKERKWOBJ4OlsZGcv0MNj1sTfxNAoGBAJZE
MgTDBBMUw6pkGmRRyovufcpKkYCMP2W9rERpmQqbu7DHX0SNRxyCWyE68ANzY8bs
CGxV5FoV92EqZAPasEjhS2XdNeufUS6cdHX5/MmWy8nMevo46+nmgC7kzyWjqjuB
ecTulublL0WemVGtH9dCmPYX3gt1ieyd7ogahyilAoGBALOE15mLh3f5W0YmHRMH
Vr4AyZGQYMOzKkgp4Z5WnJrmUbBggJoMU9jW+l4kSerT4ot6IsDDe8Ca/qUgL5R8
Dtnefx9LxTU2sYM892Icj6okOhguokY6dlFR1gJomqVF8uni5pzlC5rAAVp79l+X
crXmeGExHABKnwonAzoorm01
-----END PRIVATE KEY-----
"#;

const WRONG_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUKdH3CX5RuECi66I7xhGW8zGJ5iYwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNV3JvbmcgVGVzdCBDQTAeFw0yNjA5MTExOTAzMDNaFw0z
NjA5MDgxOTAzMDNaMBgxFjAUBgNVBAMMDVdyb25nIFRlc3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5KO1O1PrZ2VklDSkIEueRFXviWEXLvwzu
tOiHmHZrxT4HTvlbUhRhoNGlxJXEdnlz2ZTC2DPN5UEgdgdXmZ/SMNgwi6czKMID
bQlntNkpxRm9ZoemmGfm3F+rsLDiMtpqC4G/eX4NHN9WRpWR0NvjxbiNTOLPPZaw
UBp6Q0nOPZH/OIEgY00VqceZCmhe3ImJI0Veb/FAvWcu6bT9sX0QVVdGybd1Sbch
0m6AIaNlPPJoypmr+2nNvg5/XlQSC1H8N94Mp05UC85Fwvhug+U9hKJNGT0cBShM
SwVKUpg2oODnYIGEmtQaJ7F4JkeHv6OKI7mkVgYuAWbirm0XhfdNAgMBAAGjUzBR
MB0GA1UdDgQWBBSSN4jR995amKKQVu6FzkuPDY7GnzAfBgNVHSMEGDAWgBSSN4jR
995amKKQVu6FzkuPDY7GnzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQCmvYrwTgV1UJiAwoHejNzIB9K0ldUJbNMmhmFSmk6LznEHMDw64dxG6tdt
kSIaTUOQvHAY8qEVLxxR57juOqwnb6bLXY4SbU0phQR/AlwlNOKI5TX6qSSMVqqP
X2Zdm+5/nTGkLTjkbdne3q6K9R9wnMONq2RwPyaU1Ih/eYl4e1qgMO2+gys8kkvl
8QexxLYqTalG6pWXRiSK2u76s0qjmgktF6hvLmpnUnlU1RQTHgs+cXc410GcRvzF
FOL1j2gqV97B+1yFrQv+69ZAdtjrWIq6g5HXsu/yHG4JSUnY+etigRrs1I/YRsXO
tVSfJFkQoxnPQISNZJ2VoECKZ1T6
-----END CERTIFICATE-----
"#;

const DNS_SERVER_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIUOQEjPftSkrJxLuWvFbttwhz5/3YwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQU2VudGluZWwgVGVzdCBDQTAeFw0yNjA5MTExOTA0Mjha
Fw0yNzA5MTExOTA0MjhaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAPPy6fMK1OHkaeKVHCG30dz4cR/y+28U19kF
yBwg0dk/m5/tvbD/rcobmiIvh+68Q907Tj5GF+HMVLEBDVN2bgGghChxb0vpRwlw
Z1g7gVRUyur2gJMP+C37jk65VQpmxiYQYofB4+SoEVEUn3q2PHgbsSbflkk9OvwA
Itp4ymiLHwQNdHRUg5FNwn65xJU/RXkvJ+DB25rYAcPPw0ldmri4h9UFzOCv4YWn
dnh1Fw29r1RXRwyE9wB87dHZWIg+rvBKnwTZ4bpOiSyWVdLqteEVVOZUCrS4gRkc
46ZJusiqwDrZyrabZplYBphh5Fd+G0RaFaVnN7VduL8o7Q3bC10CAwEAAaOBjDCB
iTAUBgNVHREEDTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E
BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFO4mbRQDyxcLj1ef
SVlclu/FcL6sMB8GA1UdIwQYMBaAFDs9jjZFNA1azvb8FFW0jqHiJ2pzMA0GCSqG
SIb3DQEBCwUAA4IBAQBKe60fWb34lx7lfxWsybotAOQopIOqbPyHiiBzJEt0/RuR
45kD07aHiJ13PppYWjVc5tC6HsqHm4Awc41ZDmktL2D2eSZ8A9Ys4tuxpqHO4Olx
874X/9f9S2j2uqhl+alD6UlTvTlHHhSM/9E/3DZea9FauZNaE6H6qWpjYYY+XGjD
bg5qAvpjR2I1kl+ga1Ivz2SIy9EEJzuMAT7iDYvsSdAcuk0k53OE4vMD74qXcgiE
fDHRqmuW7q98tplkCib4ECnwsURqoFQj27KbCERYMqON+71auBZQwoVoNyk4knFG
NQ9Foz/Jm29iXfH+3ucMC7d1n6G7awoOO7/8n7ir
-----END CERTIFICATE-----
"#;

const DNS_SERVER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDz8unzCtTh5Gni
lRwht9Hc+HEf8vtvFNfZBcgcINHZP5uf7b2w/63KG5oiL4fuvEPdO04+RhfhzFSx
AQ1Tdm4BoIQocW9L6UcJcGdYO4FUVMrq9oCTD/gt+45OuVUKZsYmEGKHwePkqBFR
FJ96tjx4G7Em35ZJPTr8ACLaeMpoix8EDXR0VIORTcJ+ucSVP0V5Lyfgwdua2AHD
z8NJXZq4uIfVBczgr+GFp3Z4dRcNva9UV0cMhPcAfO3R2ViIPq7wSp8E2eG6Toks
llXS6rXhFVTmVAq0uIEZHOOmSbrIqsA62cq2m2aZWAaYYeRXfhtEWhWlZze1Xbi/
KO0N2wtdAgMBAAECggEACBqtZv0yVIBpr06HOexVznxHPDZ7eXwJx63t5Fe6x14N
MrAlOYVLWSGEBCRSfoqs/nzpfOwhmWC+ZFSSnfYBpZAwxvjHWvalY4AWdTnucl/2
wpa51fWvDjTP/3fsuVG8vdr7F8nhlkd3FWh7LwpxOKEPrsKF+mmyu4unNl047DKF
lJR5Q66TuTi6zi6aKSZxVQh9wxOXYdMIpVmv+JFZAEDS7Ow6uymFmrUHqhqM0NMF
FuPhhcdD3s/opQdjt5bo7Jy7QZUBWVQ5TNsg2VYoBN0qLbPCN3I8RNfxkXAb7zRx
FdFjQnaLJ+B7ticpYCXi8dWO3d0ulj6nCXi+AzIViQKBgQD6RQZrb187Iw496VCd
XxqmyzDd4FMA+GQpEi5esRlHQggNlh7w54gcKkjEOd64sEnGOoTEOrzGR5HF0Nc7
AGbdD4A2xbs00ZZ9IfpeVMdIKkmjBNSKXQDtIKNEnePcgaTVQtqtyxH0Qq/SHoG9
V/CVgV+Js904GbY7j2rYSimR1wKBgQD5iNbYRmZHX2Ekq6IFzNwJ1c3MeYZRCbwg
s/1sCwNglfCV+lVJQVIy0pIbRtcGWJSn1G3D2+VAO+5fEDIkbGVsJ7WuYfzL3UsL
fb4NozkjtJZItRs8nV3fbPNXSUtSS05Qe3HjOm8nLXOfouEyCcBsudec5XIllX0C
OlnSFD/N6wKBgEYbxgOcrGnNlTTEwl+Df9zPuP2+1KHF85EJ1dGS/QjYN5dOwZYs
1hVFxyKpL3o/cDtGs2ChL7a/39cxfMm7gBVXPUyasanHOMgPF6sLRtQxfHVdagjk
qtjCttoG/QkNjFZtpwLei0YI1GYhQ6j+FJhdKJ1TtJn9oe4na//xLpn7AoGBANFL
5jAm9DifFoLEdrR4vIJ/UwtTTsZ/7MxdS40ou59yhAW3n3s/D6vTFHtOcqI/AAi4
04w4z1OOMQSJOBV22abas7ddNsTjisNLp3IW2qFJIdhAF2VC9O6mmoA22LdgtIIq
2D5nz71DkTxvSIVIyp4nTmKpzJEbjmuk95uOImobAoGAEqLHoxRhP11UXM74MAwQ
QT/WIK80SJXNYmgVfpojHieWWoJILb/denGcakXF0S0xM8bx2nqT9C6ST7IEmToR
zBifBBO6s0VeNfwxZ5eXOmfE8FiFS3uWEvYyfvesMzLRtOiyIExzHOV/UL1Zdlco
KD1P2C7BLFeOaq+NQLMqSUU=
-----END PRIVATE KEY-----
"#;

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

async fn start_tls_server(certificate: &'static str, private_key: &'static str) -> Url {
    crate::connection::install_crypto_provider();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
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
    let ca_file = TestCaFile::new(CA_PEM);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let ip_endpoint = start_tls_server(SERVER_PEM, SERVER_KEY_PEM).await;
    let dns_endpoint = Url::parse(&format!(
        "https://localhost:{}",
        ip_endpoint.port().unwrap()
    ))
    .unwrap();

    assert!(
        crate::connection::connect_endpoint(&dns_endpoint, &tls_config)
            .await
            .is_ok()
    );
    assert!(
        crate::connection::connect_endpoint(&ip_endpoint, &tls_config)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn rejects_a_flux_server_signed_by_a_different_ca() {
    let ca_file = TestCaFile::new(WRONG_CA_PEM);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let endpoint = start_tls_server(SERVER_PEM, SERVER_KEY_PEM).await;

    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &tls_config).await,
        Err(FluxConnectionError::Connection)
    ));
}

#[tokio::test]
async fn rejects_a_flux_server_with_the_wrong_identity() {
    let ca_file = TestCaFile::new(CA_PEM);
    let tls_config = control_tls_config(ca_file.path.clone(), 1);
    let endpoint = start_tls_server(DNS_SERVER_PEM, DNS_SERVER_KEY_PEM).await;

    assert!(matches!(
        crate::connection::connect_endpoint(&endpoint, &tls_config).await,
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
