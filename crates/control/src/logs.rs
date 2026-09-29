//! Redacted, bounded in-memory copy of Sentinel's own logs and the fixed
//! journald readers behind the `logs.read.v1` command.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sentinel_protocol::control::v1::{LogEvent, LogSource};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Context;

pub(crate) const LOGS_READ_MAX_LIMIT: u32 = 500;
const BUFFER_MAX_EVENTS: usize = 2_000;
const BUFFER_MAX_BYTES: usize = 1024 * 1024;
const EVENT_OVERHEAD_BYTES: usize = 64;
const MESSAGE_MAX_BYTES: usize = 4 * 1024;
const FIELD_VALUE_MAX_BYTES: usize = 1024;
const MAX_FIELDS: usize = 16;
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(8);
const REDACTED: &str = "[redacted]";
const SECRET_NAME_PARTS: [&str; 10] = [
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
    "credential",
    "key",
    "cookie",
    "env",
    "private",
];

static SENTINEL_LOGS: LogBuffer = LogBuffer::new();

/// A bounded ring of log events. The oldest events are dropped once either
/// the event or the approximate byte limit is reached.
pub(crate) struct LogBuffer {
    ring: Mutex<Ring>,
}

struct Ring {
    events: VecDeque<(LogEvent, usize)>,
    bytes: usize,
}

impl LogBuffer {
    pub(crate) const fn new() -> Self {
        Self {
            ring: Mutex::new(Ring {
                events: VecDeque::new(),
                bytes: 0,
            }),
        }
    }

    pub(crate) fn push(&self, event: LogEvent) {
        let size = EVENT_OVERHEAD_BYTES
            + event.level.len()
            + event.component.len()
            + event.message.len()
            + event
                .fields
                .iter()
                .map(|(name, value)| name.len() + value.len())
                .sum::<usize>();
        let mut ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        while !ring.events.is_empty()
            && (ring.events.len() >= BUFFER_MAX_EVENTS || ring.bytes + size > BUFFER_MAX_BYTES)
        {
            if let Some((_, dropped)) = ring.events.pop_front() {
                ring.bytes -= dropped;
            }
        }
        ring.bytes += size;
        ring.events.push_back((event, size));
    }

    /// Returns the newest `limit` events, oldest first, and whether older
    /// events were left out.
    pub(crate) fn newest(&self, limit: usize) -> (Vec<LogEvent>, bool) {
        let ring = self.ring.lock().unwrap_or_else(|error| error.into_inner());
        let skip = ring.events.len().saturating_sub(limit);
        let events = ring
            .events
            .iter()
            .skip(skip)
            .map(|(event, _)| event.clone())
            .collect();
        (events, skip > 0)
    }
}

/// A tracing layer that copies redacted events into Sentinel's log buffer.
/// Add it to the same subscriber as the stdout formatter, below the global
/// filter, so it records exactly the events that are printed.
pub struct LogLayer {
    buffer: &'static LogBuffer,
}

pub fn log_layer() -> LogLayer {
    LogLayer {
        buffer: &SENTINEL_LOGS,
    }
}

#[cfg(test)]
pub(crate) fn log_layer_for(buffer: &'static LogBuffer) -> LogLayer {
    LogLayer { buffer }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        self.buffer.push(LogEvent {
            timestamp_unix_ms: now_millis(),
            level: level_name(*metadata.level()).into(),
            component: metadata.target().into(),
            message: truncate(redact_text(&visitor.message), MESSAGE_MAX_BYTES),
            fields: visitor.fields,
        });
    }
}

#[derive(Default)]
struct EventVisitor {
    message: String,
    fields: HashMap<String, String>,
}

impl EventVisitor {
    fn record(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
            return;
        }
        if self.fields.len() >= MAX_FIELDS {
            return;
        }
        let value = if is_secret_name(field.name()) {
            REDACTED.into()
        } else {
            truncate(redact_text(&value), FIELD_VALUE_MAX_BYTES)
        };
        self.fields.insert(field.name().into(), value);
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record(field, value.into());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.record(field, format!("{value:?}"));
    }
}

fn level_name(level: tracing::Level) -> &'static str {
    match level {
        tracing::Level::ERROR => "error",
        tracing::Level::WARN => "warn",
        tracing::Level::INFO => "info",
        tracing::Level::DEBUG => "debug",
        tracing::Level::TRACE => "trace",
    }
}

pub(crate) fn is_secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SECRET_NAME_PARTS.iter().any(|part| name.contains(part))
}

/// Replaces `name=value` pairs with secret-looking names, bearer tokens and
/// JWT-like strings with `[redacted]`.
pub(crate) fn redact_text(input: &str) -> String {
    redact_jwts(&redact_bearer_tokens(&redact_secret_pairs(input)))
}

fn is_name_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || "_-.".contains(character)
}

fn is_token_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || "-._~+/=".contains(character)
}

fn redact_secret_pairs(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(equals) = rest.find('=') {
        let (before, after) = rest.split_at(equals);
        let after = &after[1..];
        let name_start = before
            .char_indices()
            .rev()
            .take_while(|(_, character)| is_name_char(*character))
            .last()
            .map_or(before.len(), |(index, _)| index);
        let name = &before[name_start..];
        output.push_str(before);
        output.push('=');
        if name.is_empty() || !is_secret_name(name) {
            rest = after;
            continue;
        }
        let value_end = match after.chars().next() {
            Some(quote @ ('"' | '\'')) => after[1..]
                .find(quote)
                .map_or(after.len(), |index| index + 2),
            _ => {
                // Keep `authorization=Bearer <token>` from leaking the token.
                let lowercase = after.to_ascii_lowercase();
                let scheme = ["bearer ", "basic "]
                    .into_iter()
                    .find(|scheme| lowercase.starts_with(scheme))
                    .map_or(0, str::len);
                after[scheme..]
                    .find(|character: char| character.is_whitespace() || ",;&".contains(character))
                    .map_or(after.len(), |index| scheme + index)
            }
        };
        if value_end > 0 {
            output.push_str(REDACTED);
        }
        rest = &after[value_end..];
    }
    output.push_str(rest);
    output
}

fn redact_bearer_tokens(input: &str) -> String {
    let lowercase = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut position = 0;
    while let Some(found) = lowercase[position..].find("bearer ") {
        let start = position + found;
        let token_start = start + "bearer ".len();
        let boundary = input[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !character.is_ascii_alphanumeric());
        let token_end = input[token_start..]
            .find(|character: char| !is_token_char(character))
            .map_or(input.len(), |index| token_start + index);
        output.push_str(&input[position..token_start]);
        if boundary && token_end > token_start {
            output.push_str(REDACTED);
            position = token_end;
        } else {
            position = token_start;
        }
    }
    output.push_str(&input[position..]);
    output
}

fn redact_jwts(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut position = 0;
    for (start, character) in input.char_indices() {
        if start < position || !is_jwt_char(character) {
            continue;
        }
        let end = input[start..]
            .find(|character: char| !is_jwt_char(character))
            .map_or(input.len(), |index| start + index);
        let candidate = input[start..end].trim_end_matches('.');
        if is_jwt_like(candidate) {
            output.push_str(&input[position..start]);
            output.push_str(REDACTED);
            position = start + candidate.len();
        } else {
            output.push_str(&input[position..end]);
            position = end;
        }
    }
    output.push_str(&input[position..]);
    output
}

fn is_jwt_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || "-_.".contains(character)
}

fn is_jwt_like(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| !part.is_empty())
        && (parts[0].starts_with("eyJ") || parts.iter().all(|part| part.len() >= 16))
}

fn truncate(mut value: String, max_bytes: usize) -> String {
    if value.len() > max_bytes {
        let mut end = max_bytes;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

/// Reads the newest `limit` events for `source`, oldest first.
pub(crate) fn read_logs(source: LogSource, limit: u32) -> Result<(Vec<LogEvent>, bool), String> {
    let limit = limit.clamp(1, LOGS_READ_MAX_LIMIT) as usize;
    match source {
        LogSource::Sentinel => Ok(SENTINEL_LOGS.newest(limit)),
        LogSource::Corrosion => read_journal("corrosion.service", limit),
        LogSource::DiscoveryDns => read_journal("coolify-discovery-dns.service", limit),
        LogSource::Unspecified => Err("The log source is invalid.".into()),
    }
}

pub(crate) fn journal_args(unit: &str, lines: usize) -> Vec<String> {
    [
        "--unit",
        unit,
        "--no-pager",
        "--quiet",
        "--output",
        "json",
        "--lines",
    ]
    .into_iter()
    .map(str::to_string)
    .chain([lines.to_string()])
    .collect()
}

fn read_journal(unit: &str, limit: usize) -> Result<(Vec<LogEvent>, bool), String> {
    // One extra line tells whether older entries exist.
    let mut child = match Command::new("journalctl")
        .args(journal_args(unit, limit + 1))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok((Vec::new(), false)),
    };
    let mut stdout = child.stdout.take().ok_or("journalctl is unavailable.")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.read_to_end(&mut output);
        let _ = sender.send(output);
    });
    let output = match receiver.recv_timeout(JOURNAL_TIMEOUT) {
        Ok(output) => output,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("journalctl timed out.".into());
        }
    };
    let _ = child.wait();
    Ok(parse_journal(&output, unit, limit))
}

/// Parses `journalctl --output json` lines. Lines that are not JSON objects
/// (such as "-- No entries --") are ignored.
pub(crate) fn parse_journal(output: &[u8], unit: &str, limit: usize) -> (Vec<LogEvent>, bool) {
    let component = unit.strip_suffix(".service").unwrap_or(unit);
    let mut events: Vec<LogEvent> = output
        .split(|byte| *byte == b'\n')
        .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
        .filter(serde_json::Value::is_object)
        .map(|entry| {
            let timestamp_unix_ms = journal_string(&entry, "__REALTIME_TIMESTAMP")
                .and_then(|value| value.parse::<i64>().ok())
                .map_or(0, |micros| micros / 1_000);
            let level = match journal_string(&entry, "PRIORITY")
                .and_then(|value| value.parse::<u8>().ok())
            {
                Some(0..=3) => "error",
                Some(4) => "warn",
                Some(7) => "debug",
                _ => "info",
            };
            let fields = journal_string(&entry, "_PID")
                .map(|pid| HashMap::from([("_PID".to_string(), pid)]))
                .unwrap_or_default();
            LogEvent {
                timestamp_unix_ms,
                level: level.into(),
                component: component.into(),
                message: truncate(
                    redact_text(&journal_string(&entry, "MESSAGE").unwrap_or_default()),
                    MESSAGE_MAX_BYTES,
                ),
                fields,
            }
        })
        .collect();
    let skip = events.len().saturating_sub(limit);
    events.drain(..skip);
    (events, skip > 0)
}

/// journald encodes a field as a string, or as a byte array when it is not
/// valid UTF-8.
fn journal_string(entry: &serde_json::Value, name: &str) -> Option<String> {
    match entry.get(name)? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Array(bytes) => {
            let bytes = bytes
                .iter()
                .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<u8>>>()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
