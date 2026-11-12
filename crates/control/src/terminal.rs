//! The `workload.terminal.v1` command (decision 0018): an interactive shell in
//! a workload container that Coolify manages, streamed through Flux.
//!
//! The command opens the session: `podman exec -it` runs on a PTY that
//! Sentinel allocates, under `setsid --ctty`, so a resize of the PTY reaches
//! Podman as SIGWINCH. After that, `TerminalInput` frames from Flux carry
//! keyboard input, resizes, acknowledgements, keepalives and the close, and
//! `TerminalOutput` frames carry the PTY output and the exit.
//!
//! Backpressure: at most [`WINDOW_BYTES`] and [`WINDOW_FRAMES`] of output wait
//! for an acknowledgement from Flux. When the window is full, the reader stops
//! reading the PTY, so the shell blocks on its writes instead of filling
//! memory. Sessions outlive a reconnect to Flux: output goes to the current
//! connection, and the window starts empty on each connection, because frames
//! on the old one are delivered or lost.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};

use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};
use sentinel_protocol::control::v1::{
    AgentMessage, TerminalExit, TerminalInput, TerminalOutput, WorkloadTerminalRequest,
    WorkloadTerminalResult, agent_message, terminal_input, terminal_output,
};
use sentinel_protocol::valid_container_name;
use tokio::sync::mpsc;

const WINDOW_BYTES: usize = 256 * 1024;
const WINDOW_FRAMES: usize = 256;
const OUTPUT_FRAME_BYTES: usize = 32 * 1024;
const INPUT_FRAME_BYTES: usize = 16 * 1024;
/// Input frames that wait for the shell to read them. A shell that does not
/// read its input for this long is ended.
const INPUT_QUEUE: usize = 256;
const MAX_SESSIONS: usize = 16;
/// Flux sends a keepalive every minute; a session without any frame from
/// Flux for this long has lost its browser.
const ORPHAN_AFTER: Duration = Duration::from_secs(3 * 60);
const WATCH_INTERVAL: Duration = Duration::from_secs(10);
/// The shell that v4 starts with `docker exec -it`: the login profile, then
/// `$SHELL`, bash or sh.
const SHELL: &str = "PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && \
    if [ -f ~/.profile ]; then . ~/.profile; fi && \
    if [ -n \"$SHELL\" ] && [ -x \"$SHELL\" ] && [ \"${SHELL##*/}\" != nologin ] && [ \"${SHELL##*/}\" != false ]; then exec $SHELL; \
    elif command -v bash >/dev/null 2>&1; then exec bash; else sh; fi";

struct Flow {
    in_flight_bytes: usize,
    in_flight_frames: usize,
    last_frame: Instant,
    /// Why the session ends; set once.
    ending: Option<&'static str>,
}

struct Session {
    master: File,
    child: Mutex<Child>,
    input: SyncSender<Vec<u8>>,
    flow: Mutex<Flow>,
    flow_changed: Condvar,
}

impl Session {
    fn end(&self, reason: &'static str) {
        if let Ok(mut flow) = self.flow.lock() {
            flow.ending.get_or_insert(reason);
        }
        self.flow_changed.notify_all();
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
    }
}

static SESSIONS: Mutex<BTreeMap<String, Arc<Session>>> = Mutex::new(BTreeMap::new());
/// The sender of the current Flux connection.
static OUTBOUND: Mutex<Option<mpsc::Sender<AgentMessage>>> = Mutex::new(None);
static WATCHER: Once = Once::new();

fn valid_session_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn valid_dimension(value: u32) -> bool {
    (1..=1000).contains(&value)
}

pub(crate) fn validate(request: &WorkloadTerminalRequest) -> Result<(), String> {
    if !valid_session_id(&request.session_id) {
        return Err("The session ID is invalid.".into());
    }
    if !valid_container_name(&request.container) {
        return Err("The container name is invalid.".into());
    }
    if !valid_dimension(request.cols) || !valid_dimension(request.rows) {
        return Err("The terminal size is invalid.".into());
    }
    Ok(())
}

pub(crate) fn podman_terminal_args(podman: &Path, container_id: &str) -> Vec<String> {
    vec![
        "--ctty".into(),
        podman.to_string_lossy().into_owned(),
        "exec".into(),
        "--interactive".into(),
        "--tty".into(),
        "--env".into(),
        "TERM=xterm-256color".into(),
        container_id.into(),
        "sh".into(),
        "-c".into(),
        SHELL.into(),
    ]
}

fn pty_error<E>(_: E) -> String {
    "Sentinel could not open a terminal.".into()
}

fn winsize(cols: u32, rows: u32) -> Winsize {
    Winsize {
        ws_row: rows as u16,
        ws_col: cols as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

/// Starts a session. Its output goes to the connection that [`attach`] set.
pub(crate) fn open(
    podman: &Path,
    request: &WorkloadTerminalRequest,
) -> Result<WorkloadTerminalResult, String> {
    validate(request)?;
    {
        let sessions = SESSIONS
            .lock()
            .map_err(|_| "The terminal state is unavailable.".to_string())?;
        if sessions.contains_key(&request.session_id) {
            return Err("The session ID is already in use.".into());
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err("Too many terminal sessions are open on this server.".into());
        }
    }
    let container_id = crate::exec::running_workload_container(podman, &request.container)?;

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)
        .map_err(pty_error)?;
    grantpt(&master).map_err(pty_error)?;
    unlockpt(&master).map_err(pty_error)?;
    tcsetwinsize(&master, winsize(request.cols, request.rows)).map_err(pty_error)?;
    let peer =
        ioctl_tiocgptpeer(&master, OpenptFlags::RDWR | OpenptFlags::NOCTTY).map_err(pty_error)?;
    let peer = File::from(peer);
    let child = Command::new("setsid")
        .args(podman_terminal_args(podman, &container_id))
        .stdin(Stdio::from(peer.try_clone().map_err(pty_error)?))
        .stdout(Stdio::from(peer.try_clone().map_err(pty_error)?))
        .stderr(Stdio::from(peer))
        .spawn()
        .map_err(|_| "Sentinel could not start the terminal.".to_string())?;
    let master = File::from(master);
    let reader = master.try_clone().map_err(pty_error)?;
    let mut writer = master.try_clone().map_err(pty_error)?;
    let (input, input_receiver) = std::sync::mpsc::sync_channel::<Vec<u8>>(INPUT_QUEUE);
    let session = Arc::new(Session {
        master,
        child: Mutex::new(child),
        input,
        flow: Mutex::new(Flow {
            in_flight_bytes: 0,
            in_flight_frames: 0,
            last_frame: Instant::now(),
            ending: None,
        }),
        flow_changed: Condvar::new(),
    });
    {
        let mut sessions = SESSIONS
            .lock()
            .map_err(|_| "The terminal state is unavailable.".to_string())?;
        if sessions.contains_key(&request.session_id) || sessions.len() >= MAX_SESSIONS {
            session.end("closed");
            return Err("The session ID is already in use.".into());
        }
        sessions.insert(request.session_id.clone(), session.clone());
    }
    WATCHER.call_once(|| {
        std::thread::spawn(watch_orphans);
    });
    std::thread::spawn(move || {
        while let Ok(data) = input_receiver.recv() {
            if writer.write_all(&data).is_err() {
                return;
            }
        }
    });
    let session_id = request.session_id.clone();
    std::thread::spawn(move || pump_output(&session_id, &session, reader));
    tracing::info!(session_id = %request.session_id, container = %request.container, "terminal session opened");
    Ok(WorkloadTerminalResult {
        session_id: request.session_id.clone(),
    })
}

fn pump_output(session_id: &str, session: &Session, mut reader: File) {
    let mut chunk = vec![0; OUTPUT_FRAME_BYTES];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            // EIO: every process on the PTY has exited.
            Err(_) => break,
        };
        if !wait_for_window(session, read) {
            break;
        }
        let frame = terminal_output::Frame::Stdout(chunk[..read].to_vec());
        if !send(session_id, frame, Some(session)) {
            break;
        }
    }
    let exit_code = session.child.lock().ok().and_then(|mut child| {
        let _ = child.kill();
        child.wait().ok().and_then(|status| status.code())
    });
    let reason = session
        .flow
        .lock()
        .ok()
        .and_then(|flow| flow.ending)
        .unwrap_or("exited");
    if let Ok(mut sessions) = SESSIONS.lock() {
        sessions.remove(session_id);
    }
    tracing::info!(%session_id, reason, "terminal session ended");
    send(
        session_id,
        terminal_output::Frame::Exit(TerminalExit {
            exit_code: if reason == "exited" { exit_code } else { None },
            reason: reason.into(),
        }),
        None,
    );
}

/// Waits until `bytes` fit in the output window. False when the session ends.
fn wait_for_window(session: &Session, bytes: usize) -> bool {
    let Ok(mut flow) = session.flow.lock() else {
        return false;
    };
    loop {
        if flow.ending.is_some() {
            return false;
        }
        if flow.in_flight_frames < WINDOW_FRAMES
            && flow.in_flight_bytes + bytes <= WINDOW_BYTES.max(bytes)
        {
            flow.in_flight_bytes += bytes;
            flow.in_flight_frames += 1;
            return true;
        }
        flow = match session
            .flow_changed
            .wait_timeout(flow, Duration::from_secs(1))
        {
            Ok((flow, _)) => flow,
            Err(_) => return false,
        };
    }
}

/// Sends a frame on the current connection, and waits for a connection while
/// there is none. False when the session ends first.
fn send(session_id: &str, frame: terminal_output::Frame, session: Option<&Session>) -> bool {
    let mut message = AgentMessage {
        message: Some(agent_message::Message::TerminalOutput(TerminalOutput {
            session_id: session_id.into(),
            frame: Some(frame),
        })),
    };
    let deadline = Instant::now() + ORPHAN_AFTER;
    loop {
        let sender = OUTBOUND.lock().ok().and_then(|outbound| outbound.clone());
        if let Some(sender) = sender {
            match sender.blocking_send(message) {
                Ok(()) => return true,
                Err(mpsc::error::SendError(returned)) => message = returned,
            }
        }
        let ended = session.is_some_and(|session| {
            session
                .flow
                .lock()
                .map(|flow| flow.ending.is_some())
                .unwrap_or(true)
        });
        if ended || Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Ends sessions that got no frame from Flux for [`ORPHAN_AFTER`].
fn watch_orphans() {
    loop {
        std::thread::sleep(WATCH_INTERVAL);
        let sessions: Vec<Arc<Session>> = match SESSIONS.lock() {
            Ok(sessions) => sessions.values().cloned().collect(),
            Err(_) => continue,
        };
        for session in sessions {
            let orphaned = session
                .flow
                .lock()
                .map(|flow| flow.last_frame.elapsed() >= ORPHAN_AFTER)
                .unwrap_or(true);
            if orphaned {
                session.end("idle");
            }
        }
    }
}

/// Routes the output of every session to this connection, and resets the
/// output windows: frames on an earlier connection are delivered or lost.
pub(crate) struct OutboundGuard;

pub(crate) fn attach(sender: mpsc::Sender<AgentMessage>) -> OutboundGuard {
    if let Ok(mut outbound) = OUTBOUND.lock() {
        *outbound = Some(sender);
    }
    if let Ok(sessions) = SESSIONS.lock() {
        for session in sessions.values() {
            if let Ok(mut flow) = session.flow.lock() {
                flow.in_flight_bytes = 0;
                flow.in_flight_frames = 0;
            }
            session.flow_changed.notify_all();
        }
    }
    OutboundGuard
}

impl Drop for OutboundGuard {
    fn drop(&mut self) {
        if let Ok(mut outbound) = OUTBOUND.lock() {
            *outbound = None;
        }
    }
}

/// Handles a frame from Flux. Never blocks the connection loop.
pub(crate) fn input(frame: TerminalInput) {
    let Some(session) = SESSIONS
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(&frame.session_id).cloned())
    else {
        return;
    };
    if let Ok(mut flow) = session.flow.lock() {
        flow.last_frame = Instant::now();
    }
    match frame.frame {
        Some(terminal_input::Frame::Stdin(data)) => {
            if data.len() > INPUT_FRAME_BYTES {
                session.end("input frame is too large");
                return;
            }
            match session.input.try_send(data) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => session.end("the shell does not read its input"),
                Err(TrySendError::Disconnected(_)) => session.end("closed"),
            }
        }
        Some(terminal_input::Frame::Resize(size)) => {
            if valid_dimension(size.cols) && valid_dimension(size.rows) {
                let _ = tcsetwinsize(&session.master, winsize(size.cols, size.rows));
            }
        }
        Some(terminal_input::Frame::Ack(bytes)) => {
            if let Ok(mut flow) = session.flow.lock() {
                flow.in_flight_bytes = flow.in_flight_bytes.saturating_sub(bytes as usize);
                flow.in_flight_frames = flow.in_flight_frames.saturating_sub(1);
            }
            session.flow_changed.notify_all();
        }
        Some(terminal_input::Frame::Close(_)) => session.end("closed"),
        Some(terminal_input::Frame::Keepalive(_)) | None => {}
    }
}
