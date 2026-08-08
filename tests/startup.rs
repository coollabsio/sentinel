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

/// A bind failure (e.g. the configured PORT already in use) must fail the
/// whole process non-zero, matching the Go implementation's errgroup
/// cascade — not be silently swallowed while every other service keeps
/// running as if nothing were wrong.
#[test]
fn exits_nonzero_when_port_already_in_use() {
    // Hold the port open for the whole test so the spawned binary's bind
    // attempt genuinely collides with it.
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();

    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .env("TOKEN", "t")
        .env("PUSH_ENDPOINT", "https://example.com")
        .env("SENTINEL_DEVELOPMENT", "0")
        .env("PORT", port.to_string())
        .output()
        .unwrap();

    drop(holder);
    assert!(
        !out.status.success(),
        "binary must exit non-zero on a bind failure"
    );
}
