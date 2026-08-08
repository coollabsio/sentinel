use std::process::Command;

/// The binary must refuse to start without required configuration, matching
/// the Go implementation's fail-fast behavior.
#[test]
fn exits_nonzero_without_token() {
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env_remove("TOKEN")
        .env("PUSH_ENDPOINT", "https://example.com")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TOKEN"), "stderr was: {stderr}");
}

#[test]
fn exits_nonzero_without_push_endpoint() {
    // Force production mode explicitly: without this, a debug-profile test
    // binary defaults to development mode, which supplies a PUSH_ENDPOINT
    // fallback and this test would hang waiting for a process that never
    // exits instead of asserting the failure.
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env("TOKEN", "t")
        .env("SENTINEL_DEVELOPMENT", "0")
        .env_remove("PUSH_ENDPOINT")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("PUSH_ENDPOINT"), "stderr was: {stderr}");
}
