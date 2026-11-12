//! Volume backups to S3 and restores from S3 (decision 0009).
//!
//! `volume.backup.v1` reads a volume with `tar`, compresses the stream with
//! `zstd`, and uploads it as an S3 multipart upload. Coolify creates the
//! upload, gives presigned UploadPart URLs, and completes the upload with the
//! ETags that Sentinel reports. The Node never gets an S3 key.
//!
//! `volume.restore.v1` downloads an archive from a presigned GetObject URL into
//! a volume and checks its SHA-256 (`download`), and exchanges the data of two
//! volumes (`switch`), so a workload gets the restored data under the name of
//! its volume.
//!
//! The requests hold presigned URLs, so they are never journaled, state is in
//! memory only, and no error contains a URL.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sentinel_protocol::control::v1::{
    VolumeBackupPart, VolumeBackupRequest, VolumeBackupResult, VolumeRestoreRequest,
    VolumeRestoreResult,
};
use sha2::{Digest, Sha256};

use crate::commands::valid_container_name;
use crate::network::output_with_timeout;
use crate::volume_transfer::used_bytes;
use crate::volumes::{containers_using, ensure_volumes, mountpoint, valid_volume_name};

const MIB: u64 = 1024 * 1024;
/// S3 needs at least 5 MiB for every part but the last.
const PART_SIZE_MIN: u64 = 16 * MIB;
const PART_SIZE_MAX: u64 = 5 * 1024 * MIB;
/// The S3 limit.
const MAX_PARTS: u32 = 10_000;
/// The part size makes the used size fit in this many parts. The rest of the
/// S3 limit is for a volume that grows during the backup.
const PLANNED_PARTS: u64 = 8_000;
const MAX_URLS_PER_REQUEST: usize = 1_000;
const URL_MAX_CHARS: usize = 8_192;
/// A backup fails when Coolify sends no URL for the next part in this time,
/// for example after Coolify stopped polling.
const URL_WAIT: Duration = Duration::from_secs(10 * 60);
const PART_ATTEMPTS: u32 = 3;
const PART_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const READ_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const PODMAN_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// A finished backup or restore stays readable this long.
const RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_ENTRIES: usize = 64;
const ERROR_MAX_CHARS: usize = 2_000;
/// The same flags for both directions, so a restore keeps owners, modes, and
/// extended attributes.
const TAR_FLAGS: [&str; 3] = ["--numeric-owner", "--xattrs", "--xattrs-include=*"];

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

fn valid_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn valid_url(value: &str) -> bool {
    value.len() <= URL_MAX_CHARS
        && (value.starts_with("https://") || value.starts_with("http://"))
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

fn truncate(message: &str) -> String {
    message.chars().take(ERROR_MAX_CHARS).collect()
}

/// A reqwest error without the URL, which holds the presigned signature.
fn http_error(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    if message.contains("X-Amz-") {
        return "The request to the S3 storage failed.".into();
    }
    truncate(&message)
}

/// The `<Code>` of an S3 error response. The rest of the body can repeat the
/// signature of the URL.
fn s3_error_code(body: &str) -> Option<&str> {
    let start = body.find("<Code>")? + "<Code>".len();
    let end = start + body[start..].find("</Code>")?;
    let code = &body[start..end];
    (code.len() <= 64
        && code
            .chars()
            .all(|character| character.is_ascii_alphanumeric()))
    .then_some(code)
}

async fn rejected(response: reqwest::Response, what: &str) -> String {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    match s3_error_code(&body) {
        Some(code) => format!("The S3 storage rejected {what} with HTTP {status} ({code})."),
        None => format!("The S3 storage rejected {what} with HTTP {status}."),
    }
}

fn http_client() -> Result<(tokio::runtime::Runtime, reqwest::Client), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The HTTP runtime could not be started.".to_string())?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()
        .map_err(|_| "The HTTP client could not be created.".to_string())?;
    Ok((runtime, client))
}

fn spawn(command: &mut Command, program: &str) -> Result<Child, String> {
    command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("{program} is not installed on this Node.")
        } else {
            format!("{program} could not be started.")
        }
    })
}

/// Reads stderr in the background, so a full pipe never blocks the process.
fn drain(stderr: Option<ChildStderr>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut output = Vec::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_end(&mut output);
        }
        let text = String::from_utf8_lossy(&output).trim().to_string();
        let characters = text.chars().count();
        text.chars()
            .skip(characters.saturating_sub(ERROR_MAX_CHARS))
            .collect()
    })
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Removes everything inside `path`, but not `path` itself.
fn empty_directory(path: &Path) -> Result<(), String> {
    let entries =
        std::fs::read_dir(path).map_err(|_| "The volume directory is not readable.".to_string())?;
    for entry in entries.flatten() {
        let entry_path = entry.path();
        let directory = entry
            .file_type()
            .is_ok_and(|file_type| file_type.is_dir() && !file_type.is_symlink());
        let removed = if directory {
            std::fs::remove_dir_all(&entry_path)
        } else {
            std::fs::remove_file(&entry_path)
        };
        removed.map_err(|_| "The volume could not be emptied.".to_string())?;
    }
    Ok(())
}

fn prune<T>(entries: &mut BTreeMap<String, T>, finished: impl Fn(&T) -> Option<Instant>) {
    entries.retain(|_, entry| finished(entry).is_none_or(|at| at.elapsed() < RETENTION));
    while entries.len() > MAX_ENTRIES {
        let oldest = entries
            .iter()
            .filter_map(|(key, entry)| finished(entry).map(|at| (at, key.clone())))
            .min_by_key(|(at, _)| *at)
            .map(|(_, key)| key);
        match oldest {
            Some(key) => {
                entries.remove(&key);
            }
            None => break,
        }
    }
}

// ---------------------------------------------------------------------------
// volume.backup.v1

struct Backup {
    volume_name: String,
    stop_container: String,
    state: State,
    used_bytes: u64,
    part_size: u64,
    next_part: u32,
    urls: BTreeMap<u32, String>,
    parts: Vec<VolumeBackupPart>,
    bytes_done: u64,
    archive_bytes: u64,
    sha256: String,
    error: String,
    abort: bool,
    finished_at: Option<Instant>,
}

type SharedBackup = Arc<(Mutex<Backup>, Condvar)>;

static BACKUPS: Mutex<BTreeMap<String, SharedBackup>> = Mutex::new(BTreeMap::new());

pub(crate) fn validate_backup(request: &VolumeBackupRequest) -> Result<(), String> {
    if !valid_id(&request.backup_id) {
        return Err("The backup ID is invalid.".into());
    }
    if !valid_volume_name(&request.volume_name) {
        return Err("The volume name is invalid.".into());
    }
    if !request.stop_container.is_empty()
        && (!valid_container_name(&request.stop_container)
            || !(1..=600).contains(&request.stop_timeout_seconds))
    {
        return Err("The container to stop is invalid.".into());
    }
    if request.part_urls.len() > MAX_URLS_PER_REQUEST
        || request
            .part_urls
            .iter()
            .any(|part| !(1..=MAX_PARTS).contains(&part.part_number) || !valid_url(&part.url))
    {
        return Err("A part URL is invalid.".into());
    }
    Ok(())
}

fn add_urls(backup: &mut Backup, request: &VolumeBackupRequest) {
    for part in &request.part_urls {
        // Parts that are uploaded need no URL any more.
        if part.part_number >= backup.next_part.max(1) {
            backup.urls.insert(part.part_number, part.url.clone());
        }
    }
}

fn backup_snapshot(backup: &Backup) -> VolumeBackupResult {
    VolumeBackupResult {
        state: backup.state.as_str().into(),
        used_bytes: backup.used_bytes,
        part_size_bytes: backup.part_size,
        next_part_number: if backup.state == State::Running {
            backup.next_part
        } else {
            0
        },
        parts: backup.parts.clone(),
        bytes_done: backup.bytes_done,
        archive_bytes: backup.archive_bytes,
        sha256: backup.sha256.clone(),
        error: backup.error.clone(),
    }
}

/// The part size for a volume: the used size in [`PLANNED_PARTS`] parts,
/// rounded up to a MiB, within the S3 limits.
fn part_size(used_bytes: u64) -> u64 {
    used_bytes
        .div_ceil(PLANNED_PARTS)
        .div_ceil(MIB)
        .saturating_mul(MIB)
        .clamp(PART_SIZE_MIN, PART_SIZE_MAX)
}

pub(crate) fn backup(
    podman: &Path,
    request: &VolumeBackupRequest,
) -> Result<VolumeBackupResult, String> {
    validate_backup(request)?;
    let existing = BACKUPS
        .lock()
        .map_err(|_| "The backup state is unavailable.")?
        .get(&request.backup_id)
        .cloned();
    if let Some(shared) = existing {
        let (lock, signal) = &*shared;
        let mut backup = lock
            .lock()
            .map_err(|_| "The backup state is unavailable.")?;
        if backup.volume_name != request.volume_name
            || backup.stop_container != request.stop_container
        {
            return Err("The backup ID is already used for another volume.".into());
        }
        add_urls(&mut backup, request);
        if request.abort && backup.state == State::Running {
            backup.abort = true;
        }
        signal.notify_all();
        return Ok(backup_snapshot(&backup));
    }
    if request.abort {
        return Ok(VolumeBackupResult {
            state: State::Failed.as_str().into(),
            error: "The backup is not running.".into(),
            ..Default::default()
        });
    }

    let mount = PathBuf::from(mountpoint(podman, &request.volume_name)?);
    let mut backup = Backup {
        volume_name: request.volume_name.clone(),
        stop_container: request.stop_container.clone(),
        state: State::Running,
        used_bytes: 0,
        part_size: 0,
        next_part: 1,
        urls: BTreeMap::new(),
        parts: Vec::new(),
        bytes_done: 0,
        archive_bytes: 0,
        sha256: String::new(),
        error: String::new(),
        abort: false,
        finished_at: None,
    };
    add_urls(&mut backup, request);
    let snapshot = backup_snapshot(&backup);
    let shared: SharedBackup = Arc::new((Mutex::new(backup), Condvar::new()));
    {
        let mut backups = BACKUPS
            .lock()
            .map_err(|_| "The backup state is unavailable.")?;
        prune(&mut backups, |shared| {
            shared.0.lock().ok().and_then(|backup| backup.finished_at)
        });
        backups.insert(request.backup_id.clone(), shared.clone());
    }
    let podman = podman.to_path_buf();
    let container = request.stop_container.clone();
    let stop_timeout = request.stop_timeout_seconds;
    let backup_id = request.backup_id.clone();
    std::thread::spawn(move || {
        run_backup(&podman, &mount, &container, stop_timeout, &shared);
        if let Ok(backup) = shared.0.lock()
            && backup.state == State::Failed
        {
            tracing::warn!(backup_id, error = %backup.error, "a volume backup failed");
        }
    });
    Ok(snapshot)
}

fn run_backup(
    podman: &Path,
    mount: &Path,
    container: &str,
    stop_timeout: u32,
    shared: &SharedBackup,
) {
    let used = used_bytes(mount);
    let size = part_size(used);
    if let Ok(mut backup) = shared.0.lock() {
        backup.used_bytes = used;
        backup.part_size = size;
    }
    let stopped = if container.is_empty() {
        Ok(false)
    } else {
        stop_if_running(podman, container, stop_timeout)
    };
    let mut outcome = match &stopped {
        Ok(_) => upload_archive(mount, size, shared),
        Err(error) => Err(error.clone()),
    };
    if matches!(stopped, Ok(true))
        && let Err(error) = start_container(podman, container)
    {
        outcome = Err(match outcome {
            Ok(_) => error,
            Err(earlier) => format!("{earlier} {error}"),
        });
    }
    let (lock, signal) = &**shared;
    if let Ok(mut backup) = lock.lock() {
        match outcome {
            Ok((archive_bytes, sha256)) => {
                backup.state = State::Succeeded;
                backup.archive_bytes = archive_bytes;
                backup.sha256 = sha256;
            }
            Err(error) => {
                backup.state = State::Failed;
                backup.error = truncate(&error);
            }
        }
        backup.urls.clear();
        backup.finished_at = Some(Instant::now());
    }
    signal.notify_all();
}

/// Stops the container when it runs. Returns whether it was stopped.
fn stop_if_running(podman: &Path, name: &str, timeout: u32) -> Result<bool, String> {
    let output = output_with_timeout(
        Command::new(podman).args([
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            name,
        ]),
        PODMAN_TIMEOUT,
    )
    .map_err(|_| "Podman could not inspect the container.".to_string())?;
    if !output.status.success() {
        // A container that does not exist does not run.
        return Ok(false);
    }
    if String::from_utf8_lossy(&output.stdout).trim() != "true" {
        return Ok(false);
    }
    let output = output_with_timeout(
        Command::new(podman).args(["stop", "--time", &timeout.to_string(), name]),
        PODMAN_TIMEOUT + Duration::from_secs(u64::from(timeout)),
    )
    .map_err(|_| "Podman could not stop the container.".to_string())?;
    if !output.status.success() {
        return Err(format!(
            "The container could not be stopped: {}",
            truncate(String::from_utf8_lossy(&output.stderr).trim())
        ));
    }
    tracing::info!(container = %name, "stopped the container for a volume backup");
    Ok(true)
}

fn start_container(podman: &Path, name: &str) -> Result<(), String> {
    let output = output_with_timeout(Command::new(podman).args(["start", name]), PODMAN_TIMEOUT)
        .map_err(|_| "Podman could not start the container again.".to_string())?;
    if !output.status.success() {
        return Err(format!(
            "The container could not be started again: {}",
            truncate(String::from_utf8_lossy(&output.stderr).trim())
        ));
    }
    tracing::info!(container = %name, "started the container after a volume backup");
    Ok(())
}

/// Reads up to `size` bytes; fewer only at the end of the stream.
fn read_part(reader: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    reader
        .take(size)
        .read_to_end(&mut buffer)
        .map_err(|_| "The archive could not be read.".to_string())?;
    Ok(buffer)
}

/// Streams `tar | zstd` of the volume as parts of `size` bytes. Returns the
/// size and the SHA-256 of the archive.
fn upload_archive(mount: &Path, size: u64, shared: &SharedBackup) -> Result<(u64, String), String> {
    let (runtime, client) = http_client()?;
    let mut tar = spawn(
        Command::new("tar")
            .args(TAR_FLAGS)
            .args(["-cf", "-", "-C"])
            .arg(mount)
            .arg(".")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        "tar",
    )?;
    let tar_errors = drain(tar.stderr.take());
    let Some(tar_output) = tar.stdout.take() else {
        kill(&mut tar);
        return Err("tar could not be started.".into());
    };
    let mut zstd = match spawn(
        Command::new("zstd")
            .args(["-q", "-3", "-T0", "-c"])
            .stdin(Stdio::from(tar_output))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        "zstd",
    ) {
        Ok(zstd) => zstd,
        Err(error) => {
            kill(&mut tar);
            return Err(error);
        }
    };
    let zstd_errors = drain(zstd.stderr.take());
    let mut archive = zstd.stdout.take();

    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let uploaded = (|| -> Result<(), String> {
        let archive = archive
            .as_mut()
            .ok_or("zstd could not be started.".to_string())?;
        for part_number in 1..=MAX_PARTS {
            let buffer = read_part(archive, size)?;
            if buffer.is_empty() {
                if part_number == 1 {
                    return Err("The archive is empty.".into());
                }
                return Ok(());
            }
            let last = (buffer.len() as u64) < size;
            hasher.update(&buffer);
            let etag = upload_part(&runtime, &client, shared, part_number, buffer.clone())?;
            total += buffer.len() as u64;
            if let Ok(mut backup) = shared.0.lock() {
                backup.parts.push(VolumeBackupPart {
                    part_number,
                    etag,
                    size_bytes: buffer.len() as u64,
                });
                backup.bytes_done = total;
                backup.next_part = part_number + 1;
                backup.urls.retain(|number, _| *number > part_number);
            }
            if last {
                return Ok(());
            }
        }
        // The stream goes on after the last part S3 allows.
        if read_part(archive, 1)?.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "The archive needs more than {MAX_PARTS} parts of {} MiB.",
                size / MIB
            ))
        }
    })();
    drop(archive);
    if uploaded.is_err() {
        kill(&mut tar);
        kill(&mut zstd);
    }
    let tar_status = tar.wait();
    let zstd_status = zstd.wait();
    let tar_errors = tar_errors.join().unwrap_or_default();
    let zstd_errors = zstd_errors.join().unwrap_or_default();
    uploaded?;
    // GNU tar exits with 1 when a file changed while it was read. The archive
    // is still valid: the backup of a running container is crash-consistent.
    if !tar_status.is_ok_and(|status| matches!(status.code(), Some(0 | 1))) {
        return Err(format!("tar failed: {tar_errors}"));
    }
    if !zstd_status.is_ok_and(|status| status.success()) {
        return Err(format!("zstd failed: {zstd_errors}"));
    }
    Ok((total, hex(&hasher.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn wait_for_url(shared: &SharedBackup, part_number: u32) -> Result<String, String> {
    let (lock, signal) = &**shared;
    let deadline = Instant::now() + URL_WAIT;
    let mut backup = lock
        .lock()
        .map_err(|_| "The backup state is unavailable.")?;
    loop {
        if backup.abort {
            return Err("The backup was stopped.".into());
        }
        if let Some(url) = backup.urls.remove(&part_number) {
            return Ok(url);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "Coolify sent no upload URL for part {part_number} in time."
            ));
        }
        backup = signal
            .wait_timeout(backup, deadline - now)
            .map_err(|_| "The backup state is unavailable.")?
            .0;
    }
}

/// Uploads one part and returns its ETag. A failed attempt waits for a new
/// URL, because Coolify signs new URLs on every poll.
fn upload_part(
    runtime: &tokio::runtime::Runtime,
    client: &reqwest::Client,
    shared: &SharedBackup,
    part_number: u32,
    buffer: Vec<u8>,
) -> Result<String, String> {
    let mut last_error = String::new();
    for attempt in 1..=PART_ATTEMPTS {
        let url = wait_for_url(shared, part_number)?;
        let length = buffer.len();
        let body = buffer.clone();
        let outcome = runtime.block_on(async {
            let response = client
                .put(url)
                .header(reqwest::header::CONTENT_LENGTH, length)
                .timeout(PART_TIMEOUT)
                .body(body)
                .send()
                .await
                .map_err(http_error)?;
            if !response.status().is_success() {
                return Err(rejected(response, &format!("part {part_number}")).await);
            }
            response
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .map(str::to_string)
                .ok_or_else(|| format!("The S3 storage returned no ETag for part {part_number}."))
        });
        match outcome {
            Ok(etag) => return Ok(etag),
            Err(error) => {
                last_error = error;
                if attempt < PART_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(2 * u64::from(attempt)));
                }
            }
        }
    }
    Err(last_error)
}

// ---------------------------------------------------------------------------
// volume.restore.v1

struct Restore {
    volume_name: String,
    sha256: String,
    state: State,
    bytes_total: u64,
    bytes_done: u64,
    error: String,
    finished_at: Option<Instant>,
    /// A failure was returned to Coolify; the next request starts again.
    failure_reported: bool,
}

type SharedRestore = Arc<Mutex<Restore>>;

static RESTORES: Mutex<BTreeMap<String, SharedRestore>> = Mutex::new(BTreeMap::new());

pub(crate) fn validate_restore(request: &VolumeRestoreRequest) -> Result<(), String> {
    if !valid_id(&request.restore_id) {
        return Err("The restore ID is invalid.".into());
    }
    if !valid_volume_name(&request.volume_name) {
        return Err("The volume name is invalid.".into());
    }
    match request.step.as_str() {
        "download" => {
            if !valid_url(&request.url) {
                return Err("The download URL is invalid.".into());
            }
            if !valid_sha256(&request.sha256) {
                return Err("The checksum is invalid.".into());
            }
            Ok(())
        }
        "switch" => {
            if !valid_volume_name(&request.target_volume_name)
                || request.target_volume_name == request.volume_name
            {
                return Err("The target volume name is invalid.".into());
            }
            Ok(())
        }
        _ => Err("The restore step is invalid.".into()),
    }
}

fn restore_snapshot(restore: &mut Restore) -> VolumeRestoreResult {
    if restore.state == State::Failed {
        restore.failure_reported = true;
    }
    VolumeRestoreResult {
        state: restore.state.as_str().into(),
        bytes_total: restore.bytes_total,
        bytes_done: restore.bytes_done,
        error: restore.error.clone(),
    }
}

pub(crate) fn restore(
    podman: &Path,
    request: &VolumeRestoreRequest,
) -> Result<VolumeRestoreResult, String> {
    validate_restore(request)?;
    if request.step == "switch" {
        switch(podman, request)?;
        return Ok(VolumeRestoreResult {
            state: State::Succeeded.as_str().into(),
            ..Default::default()
        });
    }

    let mut restores = RESTORES
        .lock()
        .map_err(|_| "The restore state is unavailable.")?;
    prune(&mut restores, |restore| {
        restore.lock().ok().and_then(|restore| restore.finished_at)
    });
    if let Some(existing) = restores.get(&request.restore_id) {
        let mut restore = existing
            .lock()
            .map_err(|_| "The restore state is unavailable.")?;
        if restore.volume_name != request.volume_name || restore.sha256 != request.sha256 {
            return Err("The restore ID is already used for another volume.".into());
        }
        if !(restore.state == State::Failed && restore.failure_reported) {
            return Ok(restore_snapshot(&mut restore));
        }
    }
    // The download empties the volume, so it never writes into live data.
    let users = containers_using(podman, &request.volume_name, true)?;
    if !users.is_empty() {
        return Err(format!(
            "The volume is used by the container {}.",
            users.join(", ")
        ));
    }
    ensure_volumes(podman, [request.volume_name.as_str()])?;
    let mount = PathBuf::from(mountpoint(podman, &request.volume_name)?);
    let shared: SharedRestore = Arc::new(Mutex::new(Restore {
        volume_name: request.volume_name.clone(),
        sha256: request.sha256.clone(),
        state: State::Running,
        bytes_total: request.archive_bytes,
        bytes_done: 0,
        error: String::new(),
        finished_at: None,
        failure_reported: false,
    }));
    restores.insert(request.restore_id.clone(), shared.clone());
    drop(restores);

    let url = request.url.clone();
    let sha256 = request.sha256.clone();
    let archive_bytes = request.archive_bytes;
    let restore_id = request.restore_id.clone();
    let snapshot = shared
        .lock()
        .map(|mut restore| restore_snapshot(&mut restore))
        .map_err(|_| "The restore state is unavailable.")?;
    std::thread::spawn(move || {
        let outcome = download(&mount, &url, &sha256, archive_bytes, &shared);
        if outcome.is_err() {
            let _ = empty_directory(&mount);
        }
        if let Err(error) = &outcome {
            tracing::warn!(restore_id, %error, "a volume restore failed");
        }
        if let Ok(mut restore) = shared.lock() {
            match outcome {
                Ok(()) => restore.state = State::Succeeded,
                Err(error) => {
                    restore.state = State::Failed;
                    restore.error = truncate(&error);
                }
            }
            restore.finished_at = Some(Instant::now());
        }
    });
    Ok(snapshot)
}

/// Downloads the archive into the empty volume through `zstd -d | tar -x` and
/// checks its size and SHA-256 at the end.
fn download(
    mount: &Path,
    url: &str,
    sha256: &str,
    archive_bytes: u64,
    shared: &SharedRestore,
) -> Result<(), String> {
    empty_directory(mount)?;
    let (runtime, client) = http_client()?;
    let mut zstd = spawn(
        Command::new("zstd")
            .args(["-d", "-q", "-c"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        "zstd",
    )?;
    let zstd_errors = drain(zstd.stderr.take());
    let Some(zstd_output) = zstd.stdout.take() else {
        kill(&mut zstd);
        return Err("zstd could not be started.".into());
    };
    let mut tar = match spawn(
        Command::new("tar")
            .args(TAR_FLAGS)
            .args(["-xf", "-", "-C"])
            .arg(mount)
            .stdin(Stdio::from(zstd_output))
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
        "tar",
    ) {
        Ok(tar) => tar,
        Err(error) => {
            kill(&mut zstd);
            return Err(error);
        }
    };
    let tar_errors = drain(tar.stderr.take());
    let mut input = zstd.stdin.take();

    let mut hasher = Sha256::new();
    let downloaded = runtime.block_on(async {
        let input = input
            .as_mut()
            .ok_or("zstd could not be started.".to_string())?;
        let mut response = client.get(url).send().await.map_err(http_error)?;
        if !response.status().is_success() {
            return Err(rejected(response, "the download").await);
        }
        if let Some(length) = response.content_length()
            && let Ok(mut restore) = shared.lock()
        {
            restore.bytes_total = length;
        }
        let mut done = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(http_error)? {
            hasher.update(&chunk);
            input
                .write_all(&chunk)
                .map_err(|_| "The archive could not be unpacked.".to_string())?;
            done += chunk.len() as u64;
            if let Ok(mut restore) = shared.lock() {
                restore.bytes_done = done;
            }
        }
        Ok(done)
    });
    drop(input);
    if downloaded.is_err() {
        kill(&mut zstd);
        kill(&mut tar);
    }
    let zstd_status = zstd.wait();
    let tar_status = tar.wait();
    let zstd_errors = zstd_errors.join().unwrap_or_default();
    let tar_errors = tar_errors.join().unwrap_or_default();
    let done = downloaded?;
    if archive_bytes > 0 && done != archive_bytes {
        return Err(format!(
            "The archive has {done} bytes, but the backup recorded {archive_bytes}."
        ));
    }
    if hex(&hasher.finalize()) != sha256 {
        return Err("The checksum of the archive does not match the backup.".into());
    }
    if !zstd_status.is_ok_and(|status| status.success()) {
        return Err(format!("zstd failed: {zstd_errors}"));
    }
    if !tar_status.is_ok_and(|status| status.success()) {
        return Err(format!("tar failed: {tar_errors}"));
    }
    Ok(())
}

/// Exchanges the data directories of two volumes on the same file system, so
/// `target_volume_name` gets the restored data and `volume_name` the old data.
/// Each step can run again after a crash: the marker file in the target
/// volume records that the target has the restored data.
fn switch(podman: &Path, request: &VolumeRestoreRequest) -> Result<(), String> {
    for name in [&request.volume_name, &request.target_volume_name] {
        let users = containers_using(podman, name, false)?;
        if !users.is_empty() {
            return Err(format!(
                "The volume {name} is used by the running container {}.",
                users.join(", ")
            ));
        }
    }
    let source = PathBuf::from(mountpoint(podman, &request.volume_name)?);
    let target = PathBuf::from(mountpoint(podman, &request.target_volume_name)?);
    let target_volume = target
        .parent()
        .filter(|_| target.file_name().is_some_and(|name| name == "_data"))
        .ok_or("The target volume has an unexpected mountpoint.")?;
    let marker = target_volume.join(format!("restored-{}", request.restore_id));
    let parked = target_volume.join(format!("_data.restore-{}", request.restore_id));
    let rename = |from: &Path, to: &Path| {
        std::fs::rename(from, to).map_err(|_| "The volume data could not be switched.".to_string())
    };

    if !marker.exists() {
        if !parked.exists() {
            if !source.exists() {
                return Err("The restored volume has no data.".into());
            }
            rename(&target, &parked)?;
        }
        if !target.exists() {
            rename(&source, &target)?;
        }
        std::fs::File::create(&marker)
            .and_then(|file| file.sync_all())
            .map_err(|_| "The volume switch could not be recorded.".to_string())?;
    }
    if parked.exists() {
        if source.exists() {
            return Err("The restored volume still has data.".into());
        }
        rename(&parked, &source)?;
    }
    Ok(())
}
