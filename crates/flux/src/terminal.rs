//! Terminal sessions (decision 0018). A session is registered before Flux
//! asks Sentinel to open it, so output that Sentinel sends before its command
//! result is kept. The output waits in a bounded channel until the terminal
//! server attaches with the session's one-time ticket; Sentinel's output
//! window keeps it far below the channel size.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sentinel_protocol::control::v1::{TerminalExit, TerminalOutput, terminal_output};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Above Sentinel's window of 256 frames, so a full channel means a broken
/// peer, and the session ends.
const OUTPUT_QUEUE: usize = 1024;
const MAX_SESSIONS: usize = 256;

pub(crate) enum TerminalEvent {
    Stdout(Vec<u8>),
    Exit(TerminalExit),
}

struct Entry {
    server_id: String,
    ticket: String,
    output: mpsc::Sender<TerminalEvent>,
    /// Taken by the attach.
    receiver: Option<mpsc::Receiver<TerminalEvent>>,
}

pub(crate) struct Registered {
    pub(crate) session_id: String,
    pub(crate) ticket: String,
}

pub(crate) struct Attached {
    pub(crate) server_id: String,
    pub(crate) output: mpsc::Receiver<TerminalEvent>,
}

#[derive(Clone, Default)]
pub struct TerminalSessions {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
}

impl TerminalSessions {
    pub(crate) fn register(&self, server_id: &str) -> Option<Registered> {
        let mut entries = self.entries.lock().ok()?;
        if entries.len() >= MAX_SESSIONS {
            return None;
        }
        let session_id = Uuid::new_v4().to_string();
        let ticket = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let (output, receiver) = mpsc::channel(OUTPUT_QUEUE);
        entries.insert(
            session_id.clone(),
            Entry {
                server_id: server_id.into(),
                ticket: ticket.clone(),
                output,
                receiver: Some(receiver),
            },
        );
        Some(Registered { session_id, ticket })
    }

    /// Hands the output to the first caller with the right ticket.
    pub(crate) fn attach(&self, session_id: &str, ticket: &str) -> Option<Attached> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get_mut(session_id)?;
        if !constant_time_eq(entry.ticket.as_bytes(), ticket.as_bytes()) {
            return None;
        }
        Some(Attached {
            server_id: entry.server_id.clone(),
            output: entry.receiver.take()?,
        })
    }

    pub(crate) fn is_attached(&self, session_id: &str) -> bool {
        self.entries
            .lock()
            .ok()
            .and_then(|entries| {
                entries
                    .get(session_id)
                    .map(|entry| entry.receiver.is_none())
            })
            .unwrap_or(false)
    }

    pub(crate) fn remove(&self, session_id: &str) -> Option<String> {
        self.entries
            .lock()
            .ok()?
            .remove(session_id)
            .map(|entry| entry.server_id)
    }

    /// Routes a frame from the Sentinel of `server_id`. A session of another
    /// server is never reached.
    pub fn deliver(&self, server_id: &str, frame: TerminalOutput) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let Some(entry) = entries.get(&frame.session_id) else {
            return;
        };
        if entry.server_id != server_id {
            return;
        }
        let event = match frame.frame {
            Some(terminal_output::Frame::Stdout(data)) => TerminalEvent::Stdout(data),
            Some(terminal_output::Frame::Exit(exit)) => TerminalEvent::Exit(exit),
            None => return,
        };
        if entry.output.try_send(event).is_err() {
            // Dropping the sender ends the session's stream.
            entries.remove(&frame.session_id);
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.iter()
        .zip(right)
        .fold(left.len() ^ right.len(), |difference, (left, right)| {
            difference | usize::from(left ^ right)
        })
        == 0
}
