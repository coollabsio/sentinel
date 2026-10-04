use std::sync::{Arc, Mutex};

use push::{MAX_ERROR_CHARS, PushError, PushStatus, SharedPushStatus, record_attempt};
use time::OffsetDateTime;
use time::macros::datetime;

const T1: OffsetDateTime = datetime!(2026-10-04 12:00:00 UTC);
const T2: OffsetDateTime = datetime!(2026-10-04 12:01:00 UTC);
const T3: OffsetDateTime = datetime!(2026-10-04 12:02:00 UTC);

fn shared() -> SharedPushStatus {
    Arc::new(Mutex::new(PushStatus::default()))
}

fn snapshot(status: &SharedPushStatus) -> PushStatus {
    status.lock().unwrap().clone()
}

fn status_error(status: u16, body: &str) -> PushError {
    PushError::Status {
        url: "https://coolify.example/api/v1/sentinel/push".into(),
        status,
        body: body.into(),
    }
}

#[test]
fn starts_empty() {
    assert_eq!(
        PushStatus::default(),
        PushStatus {
            last_attempt_at: None,
            last_success_at: None,
            last_error: None,
            last_status: None,
            consecutive_failures: 0,
        }
    );
}

#[test]
fn failure_records_error_status_code_and_counts() {
    let status = shared();

    record_attempt(&status, T1, &Err(status_error(401, "Unauthenticated.")));
    let s = snapshot(&status);
    assert_eq!(s.last_attempt_at, Some(T1));
    assert_eq!(s.last_success_at, None);
    assert_eq!(s.last_status, Some(401));
    assert_eq!(
        s.last_error.as_deref(),
        Some("push to https://coolify.example/api/v1/sentinel/push returned 401: Unauthenticated.")
    );
    assert_eq!(s.consecutive_failures, 1);

    // A non-HTTP failure has no status code, and the counter keeps climbing.
    let io = PushError::Io(std::io::Error::other("disk gone"));
    record_attempt(&status, T2, &Err(io));
    let s = snapshot(&status);
    assert_eq!(s.last_attempt_at, Some(T2));
    assert_eq!(s.last_status, None);
    assert_eq!(s.last_error.as_deref(), Some("io: disk gone"));
    assert_eq!(s.consecutive_failures, 2);
}

#[test]
fn success_resets_error_status_and_counter() {
    let status = shared();
    record_attempt(&status, T1, &Err(status_error(500, "boom")));
    record_attempt(&status, T2, &Err(status_error(502, "bad gateway")));

    record_attempt(&status, T3, &Ok(()));

    assert_eq!(
        snapshot(&status),
        PushStatus {
            last_attempt_at: Some(T3),
            last_success_at: Some(T3),
            last_error: None,
            last_status: None,
            consecutive_failures: 0,
        }
    );

    // last_success_at survives a later failure.
    record_attempt(&status, T3, &Err(status_error(503, "")));
    assert_eq!(snapshot(&status).last_success_at, Some(T3));
}

#[test]
fn error_is_truncated_to_max_chars() {
    let status = shared();
    // Multi-byte chars: truncation must count chars, not bytes.
    let body = "é".repeat(MAX_ERROR_CHARS * 2);

    record_attempt(&status, T1, &Err(status_error(413, &body)));

    let error = snapshot(&status).last_error.unwrap();
    assert_eq!(error.chars().count(), MAX_ERROR_CHARS);
    assert!(error.starts_with("push to https://coolify.example"));
}

/// reqwest's own display hides the cause; the stored error must carry it so
/// Coolify can tell connection refused / DNS / TLS apart.
#[tokio::test]
async fn http_error_includes_source_chain() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let error = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .unwrap_err();
    let message = push::error_message(&PushError::Http(error));

    assert!(
        message.starts_with("http: error sending request"),
        "{message}"
    );
    assert!(
        message.to_lowercase().contains("refused"),
        "cause missing from {message}"
    );
}
