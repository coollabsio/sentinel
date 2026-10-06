//! The `container.logs.v1` command: reads the newest output of one container
//! that Coolify manages, like `docker logs --timestamps --tail <lines>`.
//!
//! Podman writes the container's stdout lines to its own stdout and the
//! container's stderr lines to its own stderr, each line with a single write.
//! Both of Podman's output streams go into one pipe, so the result holds the
//! lines in exactly the order Podman wrote them (`2>&1`), without parsing or
//! re-sorting timestamps.

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sentinel_protocol::control::v1::{ContainerLogsRequest, ContainerLogsResult};
use sentinel_protocol::valid_container_name;

pub(crate) const CONTAINER_LOGS_MAX_LINES: u32 = 10_000;
pub(crate) const CONTAINER_LOGS_MAX_BYTES: usize = 4 * 1024 * 1024;
const CONTAINER_LOGS_TIMEOUT: Duration = Duration::from_secs(20);
const MANAGED_LABEL: &str = "coolify.managed";
const ERROR_MAX_CHARS: usize = 2_000;
const STDERR_MAX_BYTES: usize = 64 * 1024;

pub(crate) fn validate(request: &ContainerLogsRequest) -> Result<(), String> {
    if !valid_container_name(&request.name) {
        return Err("The container name is invalid.".into());
    }
    if !(1..=CONTAINER_LOGS_MAX_LINES).contains(&request.lines) {
        return Err("The number of log lines is invalid.".into());
    }
    if request.since_unix_seconds.is_some_and(|since| since <= 0) {
        return Err("The log start time is invalid.".into());
    }
    Ok(())
}

/// `podman container inspect` only matches containers, never an image, pod or
/// volume with the same name.
pub(crate) fn podman_inspect_args(name: &str) -> Vec<String> {
    vec!["container".into(), "inspect".into(), name.into()]
}

/// Podman 4.9 accepts a Unix timestamp for `--since`.
pub(crate) fn podman_logs_args(container: &str, lines: u32, since: Option<i64>) -> Vec<String> {
    let mut args = vec![
        "logs".into(),
        "--timestamps".into(),
        "--tail".into(),
        lines.to_string(),
    ];
    if let Some(since) = since {
        args.extend(["--since".into(), since.to_string()]);
    }
    args.push(container.into());
    args
}

/// Returns the full ID of the inspected container when it carries the label
/// `coolify.managed=true`. Logs are then read by ID, so a container that is
/// replaced under the same name in between is never read.
pub(crate) fn managed_container_id(inspect_output: &[u8]) -> Result<String, String> {
    let containers: Vec<serde_json::Value> = serde_json::from_slice(inspect_output)
        .map_err(|_| "Podman returned invalid container data.".to_string())?;
    let container = containers
        .first()
        .ok_or_else(|| "The container does not exist.".to_string())?;
    let managed = container
        .get("Config")
        .and_then(|config| config.get("Labels"))
        .and_then(|labels| labels.get(MANAGED_LABEL))
        .and_then(serde_json::Value::as_str)
        == Some("true");
    if !managed {
        return Err("The container is not managed by Coolify.".into());
    }
    container
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string)
        .ok_or_else(|| "Podman returned invalid container data.".to_string())
}

/// Keeps the newest `max_bytes` of `output`. When older output is dropped, the
/// cut moves forward to the next line start so no partial line is returned.
/// A single line longer than the limit keeps its newest bytes.
pub(crate) fn keep_newest(output: &[u8], max_bytes: usize) -> (&[u8], bool) {
    if output.len() <= max_bytes {
        return (output, false);
    }
    let mut start = output.len() - max_bytes;
    if output[start - 1] != b'\n'
        && let Some(newline) = output[start..].iter().position(|byte| *byte == b'\n')
    {
        start += newline + 1;
    }
    (&output[start..], true)
}

/// Reads all of `reader` but keeps only enough of the newest bytes for
/// [`keep_newest`] (`max_bytes` plus the byte before them), so memory stays
/// bounded however much a container logged.
pub(crate) fn read_newest(mut reader: impl Read, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let keep = max_bytes + 1;
    let mut output = Vec::new();
    let mut chunk = vec![0; 64 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => return Ok(output),
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        output.extend_from_slice(&chunk[..read]);
        if output.len() > keep * 2 {
            output.drain(..output.len() - keep);
        }
    }
}

pub(crate) fn read(
    podman: &Path,
    request: &ContainerLogsRequest,
) -> Result<ContainerLogsResult, String> {
    validate(request)?;
    let deadline = Instant::now() + CONTAINER_LOGS_TIMEOUT;

    let inspected = run(podman, &podman_inspect_args(&request.name), false, deadline)?;
    if !inspected.status.success() {
        let message = String::from_utf8_lossy(&inspected.stderr);
        if message.to_ascii_lowercase().contains("no such container") {
            return Err("The container does not exist.".into());
        }
        return Err(podman_error(
            &message,
            "Podman could not inspect the container.",
        ));
    }
    let container_id = managed_container_id(&inspected.output)?;

    let logs = run(
        podman,
        &podman_logs_args(&container_id, request.lines, request.since_unix_seconds),
        true,
        deadline,
    )?;
    if !logs.status.success() {
        let message = String::from_utf8_lossy(&logs.output);
        if message.to_ascii_lowercase().contains("no such container") {
            return Err("The container does not exist.".into());
        }
        return Err(podman_error(
            &message,
            "Podman could not read the container logs.",
        ));
    }
    let (output, truncated) = keep_newest(&logs.output, CONTAINER_LOGS_MAX_BYTES);
    Ok(ContainerLogsResult {
        name: request.name.clone(),
        logs: String::from_utf8_lossy(output).into_owned(),
        truncated,
    })
}

/// The newest part of Podman's message, since its error is printed last.
fn podman_error(message: &str, fallback: &str) -> String {
    let message = message.trim();
    if message.is_empty() {
        return fallback.into();
    }
    let skip = message.chars().count().saturating_sub(ERROR_MAX_CHARS);
    message.chars().skip(skip).collect()
}

struct Captured {
    status: ExitStatus,
    /// Stdout, or stdout and stderr together when they were combined.
    output: Vec<u8>,
    /// Stderr when it was read on its own.
    stderr: Vec<u8>,
}

/// Runs Podman directly (never through a shell) until `deadline`. With
/// `combine`, stdout and stderr share one pipe, so their lines keep the order
/// in which Podman wrote them.
fn run(
    podman: &Path,
    args: &[String],
    combine: bool,
    deadline: Instant,
) -> Result<Captured, String> {
    let unavailable = |_| "Podman is unavailable.".to_string();
    let (reader, writer) = std::io::pipe().map_err(unavailable)?;
    let mut command = Command::new(podman);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(writer.try_clone().map_err(unavailable)?);
    if combine {
        command.stderr(writer);
    } else {
        drop(writer);
        command.stderr(Stdio::piped());
    }
    let mut child = command.spawn().map_err(unavailable)?;
    // The command keeps copies of the pipe's write end; the reader only sees
    // the end of the output once they are closed.
    drop(command);

    // Each stream is drained on its own thread so a full pipe never blocks
    // Podman while the other one is read.
    let (output_sender, output_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = output_sender.send(read_newest(reader, CONTAINER_LOGS_MAX_BYTES));
    });
    let stderr_receiver = child.stderr.take().map(|stderr| {
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(read_newest(stderr, STDERR_MAX_BYTES));
        });
        receiver
    });
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let output = output_receiver.recv_timeout(remaining());
    let stderr = match &stderr_receiver {
        Some(receiver) => receiver.recv_timeout(remaining()).map(Some),
        None => Ok(None),
    };
    let (output, stderr) = match (output, stderr) {
        (Ok(Ok(output)), Ok(stderr)) => (output, stderr.and_then(Result::ok).unwrap_or_default()),
        (Ok(Err(_)), Ok(_)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Podman output could not be read.".into());
        }
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Podman timed out reading the container logs.".into());
        }
    };
    let status = child.wait().map_err(unavailable)?;
    Ok(Captured {
        status,
        output,
        stderr,
    })
}
