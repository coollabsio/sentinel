use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use serde_json::{Value, json};

use super::*;

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
        "heartbeat_interval_seconds": 30
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
    let client = AssignmentClient::new(&endpoint, "token", "main").unwrap();
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
    let client = AssignmentClient::new(&endpoint, "token", "main").unwrap();
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
    let client = AssignmentClient::new(&endpoint, "token", "main").unwrap();
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
    let client = AssignmentClient::new(&endpoint, "existing-token", "1.0.1").unwrap();

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
    let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();

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
        let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();
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
    let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();

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
    let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();

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
        let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();
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
    let client = AssignmentClient::new(&endpoint, "token", "1.0.1").unwrap();

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
    let client = AssignmentClient::new(&endpoint, "very-secret-token", "1.0.1").unwrap();

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
        let error = AssignmentClient::new(endpoint, "very-secret-token", "1.0.1").unwrap_err();
        assert_eq!(error.kind(), AssignmentErrorKind::InvalidConfiguration);
        assert!(!error.to_string().contains("very-secret-token"));
    }
}
