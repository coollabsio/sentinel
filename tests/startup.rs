use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sentinel_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentinel"));
    command.env_clear();
    command
}

#[test]
fn help_does_not_require_runtime_configuration() {
    let out = sentinel_command().arg("--help").output().unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage:"), "stdout was: {stdout}");
    assert!(stdout.contains("--version"), "stdout was: {stdout}");
    assert!(
        out.stderr.is_empty(),
        "stderr was: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn version_does_not_require_runtime_configuration() {
    let out = sentinel_command().arg("--version").output().unwrap();

    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        format!("sentinel {}", env!("CARGO_PKG_VERSION"))
    );
    assert!(
        out.stderr.is_empty(),
        "stderr was: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn unknown_arguments_are_rejected_before_startup() {
    let out = sentinel_command().arg("--verison").output().unwrap();

    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "stderr was: {stderr}"
    );
}

/// The binary must refuse to start without required configuration, matching
/// the Go implementation's fail-fast behavior.
#[test]
fn exits_nonzero_without_token() {
    let out = sentinel_command()
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
    let out = sentinel_command()
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
    let workdir = std::env::temp_dir().join(format!("sentinel-startup-{}", std::process::id()));
    std::fs::create_dir_all(&workdir).unwrap();

    let mut child = sentinel_command()
        .current_dir(&workdir)
        .env("TOKEN", "t")
        .env("PUSH_ENDPOINT", "https://example.com")
        .env("SENTINEL_DEVELOPMENT", "1")
        .env("PORT", port.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    let out = loop {
        if child.try_wait().unwrap().is_some() {
            break child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("binary did not exit after the expected bind failure");
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    drop(holder);
    assert!(
        !out.status.success(),
        "binary must exit non-zero on a bind failure"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Address already in use"),
        "expected bind failure, stderr was: {stderr}"
    );
    std::fs::remove_dir_all(workdir).ok();
}

/// A legacy schema migration can take minutes on a large history. Coolify
/// restarts a Sentinel whose health check fails, which rolls the migration
/// back, so `/api/health` must answer while the migration runs.
#[test]
fn health_answers_during_legacy_schema_migration() {
    use std::io::{BufRead, BufReader, Read, Write};

    let workdir = std::env::temp_dir().join(format!("sentinel-migrating-{}", std::process::id()));
    std::fs::create_dir_all(workdir.join("db")).unwrap();
    let db = rusqlite::Connection::open(workdir.join("db/metrics.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TABLE container_cpu_usage (
            time VARCHAR, container_id VARCHAR, percent VARCHAR,
            PRIMARY KEY (time, container_id));
        WITH RECURSIVE t(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM t WHERE i < 99999),
            c(j) AS (SELECT 0 UNION ALL SELECT j + 1 FROM c WHERE j < 19)
        INSERT INTO container_cpu_usage
            SELECT CAST(1700000000000 + i * 10000 AS TEXT), 'container-' || j, '12.50' FROM t, c;",
    )
    .unwrap();
    drop(db);

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = sentinel_command()
        .current_dir(&workdir)
        .env("TOKEN", "t")
        .env("PUSH_ENDPOINT", "https://example.com")
        .env("SENTINEL_DEVELOPMENT", "1")
        .env("COLLECTOR_ENABLED", "false")
        .env("PORT", port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let migration_started = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .any(|line| line.contains("legacy metrics schema detected"));
    let get = |path: &str| {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    let (health, cpu) = if migration_started {
        (get("/api/health"), get("/api/cpu"))
    } else {
        Default::default()
    };

    child.kill().ok();
    child.wait().ok();
    std::fs::remove_dir_all(workdir).ok();

    assert!(
        migration_started,
        "the legacy schema migration did not start"
    );
    assert!(
        health.starts_with("HTTP/1.1 200"),
        "health response was: {health}"
    );
    assert!(health.ends_with("ok"), "health response was: {health}");
    // The full API answers 401 without a token, so 503 proves that the
    // migration was still running.
    assert!(cpu.starts_with("HTTP/1.1 503"), "cpu response was: {cpu}");
}
