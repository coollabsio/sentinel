//! The `workload.exec.v1` command (decision 0018): runs one command in a
//! workload container that Coolify manages, like `docker exec <container>
//! <argv...>`. The argv goes to Podman as arguments; no host shell runs it.
//!
//! The first call for an `exec_id` starts the command on its own thread and
//! returns; every call returns the current state. A command that runs for an
//! hour therefore never holds the command queue of the connection. State is in
//! memory only: the arguments and the output can hold secrets.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sentinel_protocol::control::v1::{WorkloadExecRequest, WorkloadExecResult};
use sentinel_protocol::valid_container_name;

use crate::network::output_with_timeout;

pub(crate) const EXEC_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
const EXEC_TIMEOUT_MAX_SECONDS: u32 = 36_000;
const ARGV_MAX: usize = 256;
const ARGV_MAX_BYTES: usize = 64 * 1024;
/// A finished command stays readable this long, so Coolify can poll it after
/// a restart of its worker.
const RETENTION: Duration = Duration::from_secs(60 * 60);
const MAX_ENTRIES: usize = 64;
const INSPECT_TIMEOUT: Duration = Duration::from_secs(20);
const ERROR_MAX_CHARS: usize = 2_000;
const MANAGED_LABEL: &str = "coolify.managed";
const WORKLOAD_LABEL: &str = "coolify.workload";
/// Set on Sentinel's own containers (BuildKit, the registry), which also carry
/// `coolify.managed=true` but are not workloads.
const SERVICE_LABEL: &str = "coolify.service";

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Running,
    Succeeded,
    Failed,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

struct Exec {
    container: String,
    argv: Vec<String>,
    state: State,
    exit_code: Option<i32>,
    output: Vec<u8>,
    truncated: bool,
    timed_out: bool,
    error: String,
    finished_at: Option<Instant>,
}

impl Exec {
    fn result(&self) -> WorkloadExecResult {
        WorkloadExecResult {
            state: self.state.as_str().into(),
            exit_code: self.exit_code,
            output: self.output.clone(),
            truncated: self.truncated,
            timed_out: self.timed_out,
            error: self.error.clone(),
        }
    }
}

static EXECS: Mutex<BTreeMap<String, Arc<Mutex<Exec>>>> = Mutex::new(BTreeMap::new());

fn valid_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

pub(crate) fn validate(request: &WorkloadExecRequest) -> Result<(), String> {
    if !valid_id(&request.exec_id) {
        return Err("The exec ID is invalid.".into());
    }
    if !valid_container_name(&request.container) {
        return Err("The container name is invalid.".into());
    }
    if request.argv.is_empty()
        || request.argv.len() > ARGV_MAX
        || request.argv.iter().map(String::len).sum::<usize>() > ARGV_MAX_BYTES
        || request.argv[0].is_empty()
        || request.argv.iter().any(|argument| argument.contains('\0'))
    {
        return Err("The command is invalid.".into());
    }
    if !(1..=EXEC_TIMEOUT_MAX_SECONDS).contains(&request.timeout_seconds) {
        return Err("The timeout is invalid.".into());
    }
    Ok(())
}

/// Returns the ID of a running workload container: it carries
/// `coolify.managed=true` and `coolify.workload`, and is not one of Sentinel's
/// own service containers. Exec and terminal sessions then use the ID, so a
/// container that is replaced under the same name in between is never used.
pub(crate) fn running_workload_container(podman: &Path, name: &str) -> Result<String, String> {
    let output = output_with_timeout(
        Command::new(podman).args(["container", "inspect", name]),
        INSPECT_TIMEOUT,
    )
    .map_err(|_| "Podman could not inspect the container.".to_string())?;
    if !output.status.success() {
        if String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("no such container")
        {
            return Err("The container does not exist.".into());
        }
        return Err("Podman could not inspect the container.".into());
    }
    workload_container_id(&output.stdout)
}

pub(crate) fn workload_container_id(inspect_output: &[u8]) -> Result<String, String> {
    let containers: Vec<serde_json::Value> = serde_json::from_slice(inspect_output)
        .map_err(|_| "Podman returned invalid container data.".to_string())?;
    let container = containers
        .first()
        .ok_or_else(|| "The container does not exist.".to_string())?;
    let label = |key: &str| {
        container
            .get("Config")
            .and_then(|config| config.get("Labels"))
            .and_then(|labels| labels.get(key))
            .and_then(serde_json::Value::as_str)
    };
    let workload = label(MANAGED_LABEL) == Some("true")
        && label(WORKLOAD_LABEL).is_some_and(|workload| !workload.is_empty())
        && label(SERVICE_LABEL).is_none();
    if !workload {
        return Err("The container is not a workload that Coolify manages.".into());
    }
    let running = container
        .get("State")
        .and_then(|state| state.get("Running"))
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    if !running {
        return Err("The container is not running.".into());
    }
    container
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_string)
        .ok_or_else(|| "Podman returned invalid container data.".to_string())
}

pub(crate) fn podman_exec_args(container_id: &str, argv: &[String]) -> Vec<String> {
    let mut args = vec!["exec".into(), container_id.into()];
    args.extend(argv.iter().cloned());
    args
}

pub(crate) fn exec(
    podman: &Path,
    request: &WorkloadExecRequest,
) -> Result<WorkloadExecResult, String> {
    validate(request)?;
    let existing = EXECS
        .lock()
        .map_err(|_| "The exec state is unavailable.".to_string())?
        .get(&request.exec_id)
        .cloned();
    if let Some(existing) = existing {
        let exec = existing
            .lock()
            .map_err(|_| "The exec state is unavailable.".to_string())?;
        if exec.container != request.container || exec.argv != request.argv {
            return Err("The exec ID was used for another command.".into());
        }
        return Ok(exec.result());
    }

    let container_id = running_workload_container(podman, &request.container)?;
    let exec = Arc::new(Mutex::new(Exec {
        container: request.container.clone(),
        argv: request.argv.clone(),
        state: State::Running,
        exit_code: None,
        output: Vec::new(),
        truncated: false,
        timed_out: false,
        error: String::new(),
        finished_at: None,
    }));
    {
        let mut execs = EXECS
            .lock()
            .map_err(|_| "The exec state is unavailable.".to_string())?;
        execs.retain(|_, exec| {
            exec.lock()
                .map(|exec| exec.finished_at.is_none_or(|at| at.elapsed() < RETENTION))
                .unwrap_or(false)
        });
        if execs.len() >= MAX_ENTRIES {
            let oldest_finished = execs
                .iter()
                .filter_map(|(id, exec)| Some((id.clone(), exec.lock().ok()?.finished_at?)))
                .min_by_key(|(_, at)| *at)
                .map(|(id, _)| id);
            match oldest_finished {
                Some(id) => {
                    execs.remove(&id);
                }
                None => return Err("Too many commands run on this server.".into()),
            }
        }
        if let Some(existing) = execs.get(&request.exec_id) {
            return existing
                .lock()
                .map(|exec| exec.result())
                .map_err(|_| "The exec state is unavailable.".to_string());
        }
        execs.insert(request.exec_id.clone(), exec.clone());
    }
    let result = exec
        .lock()
        .map(|exec| exec.result())
        .map_err(|_| "The exec state is unavailable.".to_string())?;
    let podman = podman.to_path_buf();
    let args = podman_exec_args(&container_id, &request.argv);
    let timeout = Duration::from_secs(u64::from(request.timeout_seconds));
    std::thread::spawn(move || run(&podman, &args, timeout, &exec));
    Ok(result)
}

fn run(podman: &Path, args: &[String], timeout: Duration, exec: &Mutex<Exec>) {
    let outcome = run_capturing(podman, args, timeout);
    let Ok(mut exec) = exec.lock() else {
        return;
    };
    match outcome {
        Ok(run) => {
            exec.exit_code = run.exit_code;
            exec.output = run.output;
            exec.truncated = run.truncated;
            exec.timed_out = run.timed_out;
            exec.state = if run.exit_code == Some(0) && !run.timed_out {
                State::Succeeded
            } else {
                State::Failed
            };
            if run.timed_out {
                exec.error = format!(
                    "The command did not finish in {} seconds.",
                    timeout.as_secs()
                );
            }
        }
        Err(error) => {
            exec.state = State::Failed;
            exec.error = error.chars().take(ERROR_MAX_CHARS).collect();
        }
    }
    exec.finished_at = Some(Instant::now());
}

struct Run {
    exit_code: Option<i32>,
    output: Vec<u8>,
    truncated: bool,
    timed_out: bool,
}

/// Runs Podman with stdout and stderr in one pipe, so the output keeps the
/// order of the writes, and keeps the first [`EXEC_OUTPUT_MAX_BYTES`].
fn run_capturing(podman: &Path, args: &[String], timeout: Duration) -> Result<Run, String> {
    let unavailable = |_| "Podman is unavailable.".to_string();
    let (reader, writer) = std::io::pipe().map_err(unavailable)?;
    let mut command = Command::new(podman);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(writer.try_clone().map_err(unavailable)?)
        .stderr(writer);
    let mut child = command.spawn().map_err(unavailable)?;
    // The command keeps copies of the write end; the reader sees the end of
    // the output only once they are closed.
    drop(command);
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(read_head(reader, EXEC_OUTPUT_MAX_BYTES));
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break None,
        }
    };
    // A process in the container can keep the pipe open after Podman ended.
    let (output, truncated) = receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or((Vec::new(), false));
    Ok(Run {
        exit_code: status.and_then(|status| status.code()),
        output,
        truncated,
        timed_out,
    })
}

/// Reads all of `reader` and keeps its first `max_bytes`.
fn read_head(mut reader: impl Read, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::new();
    let mut truncated = false;
    let mut chunk = vec![0; 64 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return (output, truncated),
            Ok(read) => {
                let room = max_bytes.saturating_sub(output.len());
                output.extend_from_slice(&chunk[..read.min(room)]);
                truncated |= read > room;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (output, truncated),
        }
    }
}
