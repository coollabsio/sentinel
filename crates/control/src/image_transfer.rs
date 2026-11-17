//! Local image moves between Nodes (decision 0030 of Coolify). The source Node
//! exports one image with `podman save --format oci-dir --uncompressed` and
//! serves the export read-only with the OCI distribution API on its WireGuard
//! address (`image.serve.v1`). The target Node pulls it with `podman pull`
//! (`image.fetch.v1`). The layers of the export are uncompressed, so their
//! digests are the DiffIDs, and Podman skips each layer that it already has.
//! The image ID stays the same; the manifest digest does not.
//!
//! Like the volume transfer (`volume_transfer.rs`), both keep their state in
//! memory only, because the requests hold the transfer secret, and they share
//! its port range and its nftables sets. On start Sentinel removes the
//! exports and files that an earlier process left behind.
//!
//! The server speaks plain HTTP/1.1, one request per connection, and only
//! `GET` and `HEAD`. The WireGuard link encrypts it, and only the target Node
//! can reach the port. It asks for HTTP Basic auth (user `coolify`, password
//! the secret) and also takes the secret as a Bearer token.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use sentinel_protocol::control::v1::{
    ImageFetchRequest, ImageFetchResult, ImageServeRequest, ImageServeResult,
};

use crate::commands::{PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::output_with_timeout;
use crate::registry::stderr_or;
use crate::volume_transfer::{
    ERROR_MAX_CHARS, Mesh, PORTS, PassState, allow_peer, allow_source, digest, now_millis,
    revoke_peer, revoke_source, valid_secret, valid_transfer_id,
};

/// One export per transfer. On disk, not on the `/run` tmpfs: an export is as
/// large as the uncompressed image.
const EXPORT_DIR: &str = "var/lib/coolify/image-transfer";
/// The pull login of one fetch, on the host `/run` (tmpfs).
const FETCH_DIR: &str = "run/coolify-image-fetch";
const TRANSFER_USER: &str = "coolify";
const REPOSITORY_PREFIX: &str = "coolify-transfer/";
/// Below the 10 minutes that Flux waits for `image.serve`.
const SAVE_TIMEOUT: Duration = Duration::from_secs(9 * 60);
const PULL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
/// A finished fetch stays readable this long.
const FETCH_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const FETCH_MAX_ENTRIES: usize = 256;
/// Podman pulls at most 6 layers at a time.
const MAX_CONNECTIONS: usize = 16;
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// For each write; a stalled client fails after this.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_REQUEST_HEAD: usize = 16 * 1024;
const ACCEPT_POLL: Duration = Duration::from_millis(100);
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    })
}

/// A registry repository name must be lowercase.
fn repository_of(transfer_id: &str) -> String {
    format!("{REPOSITORY_PREFIX}{}", transfer_id.to_ascii_lowercase())
}

fn valid_repository(value: &str) -> bool {
    value.strip_prefix(REPOSITORY_PREFIX).is_some_and(|id| {
        valid_transfer_id(id) && !id.chars().any(|character| character.is_ascii_uppercase())
    })
}

fn export_dir(root: &Path, transfer_id: &str) -> PathBuf {
    root.join(EXPORT_DIR).join(transfer_id)
}

/// Free disk that the export must leave, so that the Node keeps working.
const EXPORT_RESERVE_BYTES: u64 = 1024 * 1024 * 1024;

/// The uncompressed size of a local image, as `podman save --uncompressed`
/// writes it.
fn image_size(podman: &Path, image: &str) -> Option<u64> {
    let output = output_with_timeout(
        Command::new(podman).args(["image", "inspect", "--format", "{{.Size}}", image]),
        PODMAN_QUERY_TIMEOUT,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// The free bytes of the file system of `path`: the disk with the longest
/// mount point that contains it.
fn available_bytes(path: &Path) -> Option<u64> {
    sysinfo::Disks::new_with_refreshed_list()
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
}

fn ensure_free_space(image_bytes: u64, available_bytes: u64) -> Result<(), String> {
    let needed = image_bytes.saturating_add(EXPORT_RESERVE_BYTES);
    if available_bytes >= needed {
        return Ok(());
    }
    Err(format!(
        "The server has {} free, but the copy of the image needs {} (the uncompressed image and 1 GiB that stays free). Free disk space, then try again.",
        human_bytes(available_bytes),
        human_bytes(needed)
    ))
}

#[allow(clippy::cast_precision_loss)]
fn human_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.0} MiB", bytes as f64 / MIB)
    }
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| "The transfer directory could not be created.".into())
}

fn remove_dir(path: &Path) {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%error, "could not remove an image transfer directory"),
    }
}

/// Removes the exports and pull logins of an earlier Sentinel process. Runs
/// once when Sentinel starts, after `volume_transfer::remove_leftovers`
/// flushed the shared firewall sets.
pub(crate) fn remove_leftovers(root: &Path) {
    for directory in [root.join(EXPORT_DIR), root.join(FETCH_DIR)] {
        if let Ok(entries) = std::fs::read_dir(&directory) {
            for entry in entries.flatten() {
                remove_dir(&entry.path());
            }
        }
    }
}

/// Adds the firewall elements of the running transfers again after the
/// `coolify_cluster` table was replaced.
pub(crate) fn restore_firewall() {
    let serves = SERVES
        .lock()
        .map(|serves| {
            serves
                .values()
                .filter(|serve| serve.root == Path::new("/"))
                .map(|serve| (serve.interface.clone(), serve.peer_ip, serve.port))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (interface, peer, port) in serves {
        if let Err(error) = allow_peer(&interface, peer, port) {
            tracing::warn!(%error, port, "could not restore an image transfer firewall rule");
        }
    }
    let fetches = FETCHES
        .lock()
        .map(|fetches| {
            fetches
                .values()
                .filter(|fetch| {
                    fetch.host
                        && fetch
                            .progress
                            .lock()
                            .is_ok_and(|progress| progress.state == PassState::Running)
                })
                .map(|fetch| (fetch.interface.clone(), fetch.source))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (interface, (source, port)) in fetches {
        if let Err(error) = allow_source(&interface, source, port) {
            tracing::warn!(%error, port, "could not restore an image transfer firewall rule");
        }
    }
}

// ---------------------------------------------------------------------------
// image.serve.v1

/// A served export. Its worker thread owns the listener and removes the
/// export and the firewall element when it stops.
struct Serve {
    generation: u64,
    root: PathBuf,
    image: String,
    peer_ip: Ipv4Addr,
    secret: [u8; 32],
    interface: String,
    address: Ipv4Addr,
    port: u16,
    repository: String,
    digest: String,
    image_id: String,
    deadline: Arc<AtomicI64>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

static SERVES: Mutex<BTreeMap<String, Serve>> = Mutex::new(BTreeMap::new());
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// The ports of the running image serves.
pub(crate) fn serving_ports() -> HashSet<u16> {
    SERVES
        .lock()
        .map(|serves| serves.values().map(|serve| serve.port).collect())
        .unwrap_or_default()
}

pub(crate) fn validate_serve(request: &ImageServeRequest) -> Result<(), String> {
    if !valid_transfer_id(&request.transfer_id) {
        return Err("The transfer ID is invalid.".into());
    }
    if request.stop {
        return Ok(());
    }
    if !crate::builder::valid_local_image(&request.image) {
        return Err("The image must be a localhost/ image.".into());
    }
    if request.peer_ip.parse::<Ipv4Addr>().is_err() {
        return Err("The peer address is invalid.".into());
    }
    if !valid_secret(&request.secret) {
        return Err("The transfer secret is invalid.".into());
    }
    if request.expires_at_unix_ms <= now_millis() {
        return Err("The transfer has expired.".into());
    }
    Ok(())
}

fn stop_serve(transfer_id: &str) {
    let serve = SERVES
        .lock()
        .ok()
        .and_then(|mut serves| serves.remove(transfer_id));
    if let Some(mut serve) = serve {
        serve.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = serve.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) fn serve(
    root: &Path,
    podman: &Path,
    request: &ImageServeRequest,
) -> Result<ImageServeResult, String> {
    validate_serve(request)?;
    if request.stop {
        stop_serve(&request.transfer_id);
        remove_dir(&export_dir(root, &request.transfer_id));
        return Ok(ImageServeResult::default());
    }
    let peer_ip: Ipv4Addr = request
        .peer_ip
        .parse()
        .map_err(|_| "The peer address is invalid.")?;
    let secret = digest(&request.secret);
    {
        let serves = SERVES
            .lock()
            .map_err(|_| "The transfer state is unavailable.")?;
        if let Some(serve) = serves.get(&request.transfer_id) {
            if serve.image != request.image || serve.peer_ip != peer_ip || serve.secret != secret {
                return Err("The transfer ID is already used for another image.".into());
            }
            serve
                .deadline
                .fetch_max(request.expires_at_unix_ms, Ordering::SeqCst);
            return Ok(ImageServeResult {
                address: serve.address.to_string(),
                port: u32::from(serve.port),
                repository: serve.repository.clone(),
                digest: serve.digest.clone(),
                image_id: serve.image_id.clone(),
            });
        }
    }
    start_serve(root, podman, request, peer_ip, secret)
}

fn start_serve(
    root: &Path,
    podman: &Path,
    request: &ImageServeRequest,
    peer_ip: Ipv4Addr,
    secret: [u8; 32],
) -> Result<ImageServeResult, String> {
    let mesh = Mesh::read(root)?;
    mesh.peer_node(&request.peer_ip)?;
    let Some(image_id) = crate::builder::image_id(podman, &request.image) else {
        return Err("The image is not on this Node anymore.".into());
    };
    let directory = export_dir(root, &request.transfer_id);
    remove_dir(&directory);
    // The export is a full uncompressed copy of the image: check the disk
    // first, so that a transfer never fills it.
    if let (Some(size), Some(available)) = (
        image_size(podman, &request.image),
        available_bytes(&directory),
    ) {
        ensure_free_space(size, available)?;
    }
    create_private_dir(&directory)?;
    let started = (|| {
        let oci = directory.join("oci");
        let output = output_with_timeout(
            Command::new(podman)
                .args(["save", "--format", "oci-dir", "--uncompressed", "--output"])
                .arg(&oci)
                .arg(&request.image),
            SAVE_TIMEOUT,
        )
        .map_err(|error| podman_failure(&error))?;
        if !output.status.success() {
            return Err(stderr_or(
                &output.stderr,
                "Podman could not export the image.",
            ));
        }
        let export = Export::read(oci, repository_of(&request.transfer_id))?;
        let listener = bind(mesh.address)?;
        Ok((export, listener))
    })();
    let (export, listener) = match started {
        Ok(started) => started,
        Err(message) => {
            remove_dir(&directory);
            return Err(message);
        }
    };
    let port = listener
        .local_addr()
        .map(|address| address.port())
        .unwrap_or(0);
    if root == Path::new("/")
        && let Err(message) = allow_peer(&mesh.interface, peer_ip, port)
    {
        remove_dir(&directory);
        return Err(message);
    }
    let result = ImageServeResult {
        address: mesh.address.to_string(),
        port: u32::from(port),
        repository: export.repository.clone(),
        digest: export.manifest_digest.clone(),
        image_id,
    };

    let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
    let deadline = Arc::new(AtomicI64::new(request.expires_at_unix_ms));
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let (deadline, stop) = (deadline.clone(), stop.clone());
        let transfer_id = request.transfer_id.clone();
        let root = root.to_path_buf();
        std::thread::spawn(move || {
            run_server(listener, Arc::new(export), secret, &deadline, &stop);
            tracing::info!(transfer_id, "image transfer stopped");
            if root == Path::new("/") {
                revoke_peer(peer_ip, port);
            }
            if let Ok(mut serves) = SERVES.lock()
                && serves
                    .get(&transfer_id)
                    .is_some_and(|serve| serve.generation == generation)
            {
                serves.remove(&transfer_id);
            }
            remove_dir(&export_dir(&root, &transfer_id));
        })
    };
    SERVES
        .lock()
        .map_err(|_| "The transfer state is unavailable.")?
        .insert(
            request.transfer_id.clone(),
            Serve {
                generation,
                root: root.to_path_buf(),
                image: request.image.clone(),
                peer_ip,
                secret,
                interface: mesh.interface,
                address: mesh.address,
                port,
                repository: result.repository.clone(),
                digest: result.digest.clone(),
                image_id: result.image_id.clone(),
                deadline,
                stop,
                worker: Some(worker),
            },
        );
    Ok(result)
}

/// Binds the first free transfer port that no volume or image transfer of
/// this process uses.
fn bind(address: Ipv4Addr) -> Result<TcpListener, String> {
    let mut used = serving_ports();
    used.extend(crate::volume_transfer::serving_ports());
    for port in PORTS.filter(|port| !used.contains(port)) {
        match TcpListener::bind((address, port)) {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(_) => return Err("The image transfer server could not be started.".into()),
        }
    }
    Err("No transfer port is free.".into())
}

/// The OCI layout that `podman save --format oci-dir` wrote, with one image.
struct Export {
    dir: PathBuf,
    repository: String,
    manifest_digest: String,
    manifest_media_type: String,
    /// The config and the layers.
    blobs: HashSet<String>,
}

impl Export {
    fn read(dir: PathBuf, repository: String) -> Result<Self, String> {
        let invalid = || "Podman wrote an invalid image export.".to_string();
        let read_json = |path: PathBuf| -> Result<serde_json::Value, String> {
            std::fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or_else(invalid)
        };
        let index = read_json(dir.join("index.json"))?;
        let entry = index
            .get("manifests")
            .and_then(serde_json::Value::as_array)
            .and_then(|manifests| manifests.first())
            .ok_or_else(invalid)?;
        let manifest_digest = entry
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| valid_sha256(digest))
            .ok_or_else(invalid)?
            .to_string();
        let manifest = read_json(blob_path(&dir, &manifest_digest).ok_or_else(invalid)?)?;
        let manifest_media_type = manifest
            .get("mediaType")
            .or_else(|| entry.get("mediaType"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(OCI_MANIFEST)
            .to_string();
        if manifest_media_type != OCI_MANIFEST {
            return Err(invalid());
        }
        let config = manifest.get("config").into_iter();
        let layers = manifest
            .get("layers")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten();
        let mut blobs = HashSet::new();
        for descriptor in config.chain(layers) {
            let digest = descriptor
                .get("digest")
                .and_then(serde_json::Value::as_str)
                .filter(|digest| valid_sha256(digest))
                .ok_or_else(invalid)?;
            if !blob_path(&dir, digest).is_some_and(|path| path.is_file()) {
                return Err(invalid());
            }
            blobs.insert(digest.to_string());
        }
        Ok(Self {
            dir,
            repository,
            manifest_digest,
            manifest_media_type,
            blobs,
        })
    }
}

fn blob_path(dir: &Path, digest: &str) -> Option<PathBuf> {
    valid_sha256(digest).then(|| dir.join("blobs/sha256").join(&digest["sha256:".len()..]))
}

/// The open connections of one server, so a stop can end them: the firewall
/// accepts established connections after the element is gone.
#[derive(Default)]
struct Connections {
    next: u64,
    open: HashMap<u64, TcpStream>,
}

fn run_server(
    listener: TcpListener,
    export: Arc<Export>,
    secret: [u8; 32],
    deadline: &AtomicI64,
    stop: &AtomicBool,
) {
    let connections = Arc::new(Mutex::new(Connections::default()));
    let active = Arc::new(AtomicUsize::new(0));
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    loop {
        if stop.load(Ordering::SeqCst) || deadline.load(Ordering::SeqCst) <= now_millis() {
            break;
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, "the image transfer server could not accept a connection");
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS
            || stream.set_nonblocking(false).is_err()
        {
            continue;
        }
        let id = {
            let Ok(mut connections) = connections.lock() else {
                continue;
            };
            let Ok(clone) = stream.try_clone() else {
                continue;
            };
            let id = connections.next;
            connections.next += 1;
            connections.open.insert(id, clone);
            id
        };
        active.fetch_add(1, Ordering::SeqCst);
        let (export, connections, active) = (export.clone(), connections.clone(), active.clone());
        std::thread::spawn(move || {
            handle_connection(stream, &export, &secret);
            if let Ok(mut connections) = connections.lock() {
                connections.open.remove(&id);
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    drop(listener);
    if let Ok(connections) = connections.lock() {
        for stream in connections.open.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn handle_connection(mut stream: TcpStream, export: &Export, secret: &[u8; 32]) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let head = match read_head(&mut stream) {
        Head::Http(head) => head,
        // `podman pull --tls-verify=false` tries HTTPS first and uses HTTP
        // when the handshake fails, so it must fail at once.
        Head::Tls => {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        Head::Invalid => String::new(),
    };
    let response = match parse_request(&head) {
        Some(request) => {
            let authorized = request
                .authorization
                .is_some_and(|value| authorized(value, secret));
            route(export, request.method, request.path, authorized)
        }
        None => Response::error(400, "UNSUPPORTED", "The request is invalid."),
    };
    let head_only = response.head_only;
    let _ = write_response(&mut stream, response, head_only);
    let _ = stream.shutdown(Shutdown::Both);
}

enum Head {
    Http(String),
    /// A TLS ClientHello: a handshake record starts with 0x16.
    Tls,
    Invalid,
}

fn read_head(stream: &mut impl Read) -> Head {
    let mut head = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return Head::Invalid,
            Ok(read) => read,
        };
        head.extend_from_slice(&buffer[..read]);
        if head.first() == Some(&0x16) {
            return Head::Tls;
        }
        if let Some(end) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            head.truncate(end);
            return String::from_utf8(head).map_or(Head::Invalid, Head::Http);
        }
        if head.len() > MAX_REQUEST_HEAD {
            return Head::Invalid;
        }
    }
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    authorization: Option<&'a str>,
}

fn parse_request(head: &str) -> Option<Request<'_>> {
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?;
    let target = request_line.next()?;
    if !request_line.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let path = target.split(['?', '#']).next().unwrap_or_default();
    let authorization = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("authorization")
            .then(|| value.trim())
    });
    Some(Request {
        method,
        path,
        authorization,
    })
}

/// `Basic base64(coolify:<secret>)` or `Bearer <secret>`.
fn authorized(header: &str, secret: &[u8; 32]) -> bool {
    let Some((scheme, value)) = header.split_once(' ') else {
        return false;
    };
    let password = if scheme.eq_ignore_ascii_case("basic") {
        let Some(credentials) = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
        else {
            return false;
        };
        match credentials.split_once(':') {
            Some((TRANSFER_USER, password)) => password.to_string(),
            _ => return false,
        }
    } else if scheme.eq_ignore_ascii_case("bearer") {
        value.trim().to_string()
    } else {
        return false;
    };
    let given = digest(&password);
    given
        .iter()
        .zip(secret)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

enum Body {
    Bytes(Vec<u8>),
    File(PathBuf),
}

struct Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Body,
    head_only: bool,
}

impl Response {
    fn error(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "application/json".into())],
            body: Body::Bytes(
                serde_json::to_vec(&serde_json::json!({
                    "errors": [{ "code": code, "message": message }],
                }))
                .unwrap_or_default(),
            ),
            head_only: false,
        }
    }

    fn blob(path: PathBuf, media_type: &str, digest: &str) -> Self {
        Self {
            status: 200,
            headers: vec![
                ("Content-Type", media_type.into()),
                ("Docker-Content-Digest", digest.into()),
            ],
            body: Body::File(path),
            head_only: false,
        }
    }
}

fn route(export: &Export, method: &str, path: &str, authorized: bool) -> Response {
    let mut response = route_get(export, method, path, authorized);
    response.head_only = method == "HEAD";
    response
}

fn route_get(export: &Export, method: &str, path: &str, authorized: bool) -> Response {
    if method != "GET" && method != "HEAD" {
        let mut response = Response::error(405, "UNSUPPORTED", "Only GET and HEAD are allowed.");
        response.headers.push(("Allow", "GET, HEAD".into()));
        return response;
    }
    if !authorized {
        let mut response = Response::error(401, "UNAUTHORIZED", "Authentication is required.");
        response.headers.push((
            "WWW-Authenticate",
            "Basic realm=\"coolify-image-transfer\"".into(),
        ));
        return response;
    }
    if path == "/v2/" || path == "/v2" {
        return Response {
            status: 200,
            headers: vec![("Content-Type", "application/json".into())],
            body: Body::Bytes(b"{}".to_vec()),
            head_only: false,
        };
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return Response::error(404, "NOT_FOUND", "Not found.");
    };
    if let Some((repository, reference)) = rest.rsplit_once("/manifests/") {
        if repository != export.repository {
            return Response::error(404, "NAME_UNKNOWN", "The repository is unknown.");
        }
        if reference != export.manifest_digest && reference != "latest" {
            return Response::error(404, "MANIFEST_UNKNOWN", "The manifest is unknown.");
        }
        return match blob_path(&export.dir, &export.manifest_digest) {
            Some(path) => {
                Response::blob(path, &export.manifest_media_type, &export.manifest_digest)
            }
            None => Response::error(404, "MANIFEST_UNKNOWN", "The manifest is unknown."),
        };
    }
    if let Some((repository, digest)) = rest.rsplit_once("/blobs/") {
        if repository != export.repository {
            return Response::error(404, "NAME_UNKNOWN", "The repository is unknown.");
        }
        return match blob_path(&export.dir, digest).filter(|_| export.blobs.contains(digest)) {
            Some(path) => Response::blob(path, "application/octet-stream", digest),
            None => Response::error(404, "BLOB_UNKNOWN", "The blob is unknown."),
        };
    }
    Response::error(404, "NOT_FOUND", "Not found.")
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    }
}

fn write_response(
    stream: &mut TcpStream,
    response: Response,
    head_only: bool,
) -> std::io::Result<()> {
    let mut file = match &response.body {
        Body::File(path) => std::fs::File::open(path).ok(),
        Body::Bytes(_) => None,
    };
    let mut response = if matches!(response.body, Body::File(_)) && file.is_none() {
        Response::error(404, "BLOB_UNKNOWN", "The blob is unknown.")
    } else {
        response
    };
    let length = match (&response.body, &file) {
        (Body::Bytes(bytes), _) => bytes.len() as u64,
        (Body::File(_), Some(file)) => file.metadata()?.len(),
        (Body::File(_), None) => 0,
    };
    response
        .headers
        .push(("Docker-Distribution-API-Version", "registry/2.0".into()));
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {length}\r\nConnection: close\r\n\r\n"
    ));
    stream.write_all(head.as_bytes())?;
    if head_only {
        return stream.flush();
    }
    match (response.body, file.as_mut()) {
        (Body::Bytes(bytes), _) => stream.write_all(&bytes)?,
        (Body::File(_), Some(file)) => {
            std::io::copy(file, stream)?;
        }
        (Body::File(_), None) => {}
    }
    stream.flush()
}

// ---------------------------------------------------------------------------
// image.fetch.v1

struct Progress {
    state: PassState,
    error: String,
    image_id: String,
    finished_at: Option<Instant>,
    /// A failure was returned to Coolify; the next request starts again.
    failure_reported: bool,
}

struct Fetch {
    source: (Ipv4Addr, u16),
    interface: String,
    /// Runs on the host, so the output allow is in the host firewall.
    host: bool,
    repository: String,
    digest: String,
    image: String,
    image_id: String,
    secret: [u8; 32],
    progress: Arc<Mutex<Progress>>,
}

static FETCHES: Mutex<BTreeMap<String, Fetch>> = Mutex::new(BTreeMap::new());

pub(crate) fn validate_fetch(request: &ImageFetchRequest) -> Result<(), String> {
    if !valid_transfer_id(&request.transfer_id) {
        return Err("The transfer ID is invalid.".into());
    }
    if request.source_address.parse::<Ipv4Addr>().is_err() {
        return Err("The source address is invalid.".into());
    }
    if !PORTS.contains(&u16::try_from(request.source_port).unwrap_or(0)) {
        return Err("The source port is invalid.".into());
    }
    if !valid_secret(&request.secret) {
        return Err("The transfer secret is invalid.".into());
    }
    if !valid_repository(&request.repository) {
        return Err("The transfer repository is invalid.".into());
    }
    if !valid_sha256(&request.digest) {
        return Err("The manifest digest is invalid.".into());
    }
    if !crate::builder::valid_local_image(&request.image) {
        return Err("The image must be a localhost/ image.".into());
    }
    if !valid_sha256(&request.image_id) {
        return Err("The image ID is invalid.".into());
    }
    Ok(())
}

fn snapshot(progress: &Mutex<Progress>) -> ImageFetchResult {
    let Ok(mut progress) = progress.lock() else {
        return ImageFetchResult {
            state: PassState::Failed.as_str().into(),
            error: "The transfer state is unavailable.".into(),
            ..Default::default()
        };
    };
    if progress.state == PassState::Failed {
        progress.failure_reported = true;
    }
    ImageFetchResult {
        state: progress.state.as_str().into(),
        bytes_done: 0,
        error: progress.error.clone(),
        image_id: progress.image_id.clone(),
    }
}

fn prune(fetches: &mut BTreeMap<String, Fetch>) {
    let finished = |fetch: &Fetch| {
        fetch
            .progress
            .lock()
            .ok()
            .and_then(|progress| progress.finished_at)
    };
    fetches.retain(|_, fetch| finished(fetch).is_none_or(|at| at.elapsed() < FETCH_RETENTION));
    while fetches.len() > FETCH_MAX_ENTRIES {
        let oldest = fetches
            .iter()
            .filter_map(|(key, fetch)| finished(fetch).map(|at| (at, key.clone())))
            .min_by_key(|(at, _)| *at)
            .map(|(_, key)| key);
        match oldest {
            Some(key) => {
                fetches.remove(&key);
            }
            None => break,
        }
    }
}

fn podman_run(podman: &Path, arguments: &[&str], fallback: &str) -> Result<String, String> {
    let output = output_with_timeout(Command::new(podman).args(arguments), PODMAN_QUERY_TIMEOUT)
        .map_err(|error| podman_failure(&error))?;
    if !output.status.success() {
        return Err(stderr_or(&output.stderr, fallback));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub(crate) fn fetch(
    root: &Path,
    podman: &Path,
    request: &ImageFetchRequest,
) -> Result<ImageFetchResult, String> {
    validate_fetch(request)?;
    let source_address: Ipv4Addr = request
        .source_address
        .parse()
        .map_err(|_| "The source address is invalid.")?;
    let source_port =
        u16::try_from(request.source_port).map_err(|_| "The source port is invalid.")?;
    let source = (source_address, source_port);
    let secret = digest(&request.secret);

    let mut fetches = FETCHES
        .lock()
        .map_err(|_| "The transfer state is unavailable.")?;
    prune(&mut fetches);
    if let Some(existing) = fetches.get(&request.transfer_id) {
        if existing.source != source
            || existing.repository != request.repository
            || existing.digest != request.digest
            || existing.image != request.image
            || existing.image_id != request.image_id
            || existing.secret != secret
        {
            return Err("The transfer ID is already used for another image.".into());
        }
        let restart = existing
            .progress
            .lock()
            .map(|progress| progress.state == PassState::Failed && progress.failure_reported)
            .unwrap_or(true);
        if !restart {
            return Ok(snapshot(&existing.progress));
        }
    }
    let hex_id = &request.image_id["sha256:".len()..];
    if crate::builder::image_id(podman, hex_id).as_deref() == Some(request.image_id.as_str()) {
        podman_run(
            podman,
            &["tag", hex_id, &request.image],
            "Podman could not tag the image.",
        )?;
        fetches.remove(&request.transfer_id);
        return Ok(ImageFetchResult {
            state: PassState::Succeeded.as_str().into(),
            bytes_done: 0,
            error: String::new(),
            image_id: request.image_id.clone(),
        });
    }
    let mesh = Mesh::read(root)?;
    mesh.peer_node(&request.source_address)?;
    let host = root == Path::new("/");
    let progress = Arc::new(Mutex::new(Progress {
        state: PassState::Running,
        error: String::new(),
        image_id: String::new(),
        finished_at: None,
        failure_reported: false,
    }));
    fetches.insert(
        request.transfer_id.clone(),
        Fetch {
            source,
            interface: mesh.interface.clone(),
            host,
            repository: request.repository.clone(),
            digest: request.digest.clone(),
            image: request.image.clone(),
            image_id: request.image_id.clone(),
            secret,
            progress: progress.clone(),
        },
    );
    drop(fetches);
    if host && let Err(error) = allow_source(&mesh.interface, source_address, source_port) {
        if let Ok(mut progress) = progress.lock() {
            progress.state = PassState::Failed;
            progress.error = error.clone();
            progress.finished_at = Some(Instant::now());
        }
        return Err(error);
    }

    let worker_progress = progress.clone();
    let (root, podman, request) = (root.to_path_buf(), podman.to_path_buf(), request.clone());
    std::thread::spawn(move || {
        let outcome = pull(&root, &podman, &request);
        if host {
            revoke_source(source_address, source_port);
        }
        if let Err(error) = &outcome {
            tracing::warn!(transfer_id = request.transfer_id, %error, "an image fetch failed");
        }
        if let Ok(mut progress) = worker_progress.lock() {
            match outcome {
                Ok(()) => {
                    progress.state = PassState::Succeeded;
                    progress.image_id = request.image_id.clone();
                }
                Err(error) => {
                    progress.state = PassState::Failed;
                    progress.error = error;
                }
            }
            progress.finished_at = Some(Instant::now());
        }
    });
    Ok(snapshot(&progress))
}

/// The pull login of one fetch. Dropping it deletes it.
struct FetchDir(PathBuf);

impl Drop for FetchDir {
    fn drop(&mut self) {
        remove_dir(&self.0);
    }
}

fn redact(message: &str, secret: &str) -> String {
    message
        .replace(secret, "[redacted]")
        .chars()
        .take(ERROR_MAX_CHARS)
        .collect()
}

/// Pulls the served image, checks its ID, tags it as `image`, and removes the
/// transfer reference.
fn pull(root: &Path, podman: &Path, request: &ImageFetchRequest) -> Result<(), String> {
    let source = format!("{}:{}", request.source_address, request.source_port);
    let reference = format!("{source}/{}@{}", request.repository, request.digest);
    let dir = FetchDir(root.join(FETCH_DIR).join(&request.transfer_id));
    remove_dir(&dir.0);
    create_private_dir(&dir.0)?;
    let auth = dir.0.join("auth.json");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&auth)
        .and_then(|mut file| {
            file.write_all(&crate::registry::login_auth_file(
                &source,
                TRANSFER_USER,
                &request.secret,
            ))
        })
        .map_err(|_| "The transfer login could not be written.".to_string())?;
    let output = output_with_timeout(
        Command::new(podman)
            .args(["pull", "--quiet", "--tls-verify=false", "--authfile"])
            .arg(&auth)
            .arg(&reference),
        PULL_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    drop(dir);
    if !output.status.success() {
        return Err(redact(
            &stderr_or(&output.stderr, "Podman could not pull the image."),
            &request.secret,
        ));
    }
    let pulled = crate::builder::image_id(podman, &reference);
    if pulled.as_deref() != Some(request.image_id.as_str()) {
        let _ = podman_run(podman, &["rmi", &reference], "");
        return Err(format!(
            "The fetched image has the ID {}, not {}.",
            pulled.as_deref().unwrap_or("unknown"),
            request.image_id
        ));
    }
    let hex_id = &request.image_id["sha256:".len()..];
    podman_run(
        podman,
        &["tag", hex_id, &request.image],
        "Podman could not tag the image.",
    )?;
    if let Err(error) = podman_run(
        podman,
        &["untag", hex_id, &reference],
        "Podman could not remove the transfer reference.",
    ) {
        tracing::warn!(%error, "could not remove the transfer reference of a fetched image");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdefABCDEF0123456789";

    /// A change of a valid request and the error it causes.
    type Case<T> = (fn(&mut T), &'static str);

    fn sha(hex: char) -> String {
        format!("sha256:{}", hex.to_string().repeat(64))
    }

    fn serve_request() -> ImageServeRequest {
        ImageServeRequest {
            transfer_id: "move-1".into(),
            image: "localhost/api:b1".into(),
            peer_ip: "10.240.0.3".into(),
            secret: SECRET.into(),
            expires_at_unix_ms: now_millis() + 60_000,
            stop: false,
        }
    }

    fn fetch_request() -> ImageFetchRequest {
        ImageFetchRequest {
            transfer_id: "move-1".into(),
            source_address: "10.240.0.2".into(),
            source_port: 7800,
            secret: SECRET.into(),
            repository: "coolify-transfer/move-1".into(),
            digest: sha('a'),
            image: "localhost/api:b1".into(),
            image_id: sha('b'),
        }
    }

    #[test]
    fn validates_a_serve_request() {
        assert_eq!(validate_serve(&serve_request()), Ok(()));
        let stop = ImageServeRequest {
            transfer_id: "move-1".into(),
            stop: true,
            ..Default::default()
        };
        assert_eq!(validate_serve(&stop), Ok(()));
        let cases: [Case<ImageServeRequest>; 6] = [
            (
                |r| r.transfer_id = "a/b".into(),
                "The transfer ID is invalid.",
            ),
            (
                |r| r.image = "ghcr.io/acme/api:b1".into(),
                "The image must be a localhost/ image.",
            ),
            (
                |r| r.image = "localhost/api".into(),
                "The image must be a localhost/ image.",
            ),
            (
                |r| r.peer_ip = "node-2".into(),
                "The peer address is invalid.",
            ),
            (
                |r| r.secret = "short".into(),
                "The transfer secret is invalid.",
            ),
            (|r| r.expires_at_unix_ms = 1, "The transfer has expired."),
        ];
        for (change, error) in cases {
            let mut request = serve_request();
            change(&mut request);
            assert_eq!(validate_serve(&request), Err(error.into()));
        }
    }

    #[test]
    fn validates_a_fetch_request() {
        assert_eq!(validate_fetch(&fetch_request()), Ok(()));
        let cases: [Case<ImageFetchRequest>; 9] = [
            (
                |r| r.transfer_id = String::new(),
                "The transfer ID is invalid.",
            ),
            (
                |r| r.source_address = "::1".into(),
                "The source address is invalid.",
            ),
            (|r| r.source_port = 5443, "The source port is invalid."),
            (
                |r| r.secret = "a-b".repeat(20),
                "The transfer secret is invalid.",
            ),
            (
                |r| r.repository = "coolify-transfer/Move-1".into(),
                "The transfer repository is invalid.",
            ),
            (
                |r| r.repository = "library/nginx".into(),
                "The transfer repository is invalid.",
            ),
            (
                |r| r.digest = "sha256:abc".into(),
                "The manifest digest is invalid.",
            ),
            (
                |r| r.image = "localhost/api:b1 --tls-verify=false".into(),
                "The image must be a localhost/ image.",
            ),
            (|r| r.image_id = sha('B'), "The image ID is invalid."),
        ];
        for (change, error) in cases {
            let mut request = fetch_request();
            change(&mut request);
            assert_eq!(validate_fetch(&request), Err(error.into()));
        }
    }

    #[test]
    fn needs_the_image_and_a_reserve_of_free_disk() {
        let gib = 1024 * 1024 * 1024;
        assert!(ensure_free_space(2 * gib, 3 * gib).is_ok());
        let error = ensure_free_space(2 * gib, 3 * gib - 1).unwrap_err();
        assert!(
            error.contains("3.0 GiB free") || error.contains("needs 3.0 GiB"),
            "{error}"
        );
        assert!(ensure_free_space(u64::MAX, u64::MAX - 1).is_err());
    }

    #[test]
    fn names_the_repository_in_lowercase() {
        assert_eq!(repository_of("Move-1"), "coolify-transfer/move-1");
        assert!(valid_repository(&repository_of("Move-1")));
    }

    #[test]
    fn accepts_only_the_transfer_secret() {
        let secret = digest(SECRET);
        let basic = |credentials: &str| {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(credentials)
            )
        };
        assert!(authorized(&basic(&format!("coolify:{SECRET}")), &secret));
        assert!(authorized(&format!("Bearer {SECRET}"), &secret));
        assert!(authorized(&format!("bearer {SECRET}"), &secret));
        assert!(!authorized(&basic(&format!("root:{SECRET}")), &secret));
        assert!(!authorized(&basic("coolify:wrong"), &secret));
        assert!(!authorized("Bearer wrong", &secret));
        assert!(!authorized(SECRET, &secret));
        assert!(!authorized("Basic !!!", &secret));
    }

    #[test]
    fn redacts_the_secret_from_errors() {
        assert_eq!(
            redact(&format!("unauthorized: {SECRET} rejected"), SECRET),
            "unauthorized: [redacted] rejected"
        );
    }

    /// An OCI layout like the one of `podman save --format oci-dir`.
    fn write_export(dir: &Path) -> (String, String) {
        let blobs = dir.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        let write_blob = |contents: &[u8]| {
            let hex = crate::network::hash(contents);
            std::fs::write(blobs.join(&hex), contents).unwrap();
            format!("sha256:{hex}")
        };
        let config = write_blob(b"{\"rootfs\":{}}");
        let layer = write_blob(b"layer tar");
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 13 },
            "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer, "size": 9 }],
        });
        let manifest = write_blob(&serde_json::to_vec(&manifest).unwrap());
        std::fs::write(
            dir.join("index.json"),
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{ "mediaType": OCI_MANIFEST, "digest": manifest, "size": 1 }],
            }))
            .unwrap(),
        )
        .unwrap();
        (manifest, layer)
    }

    fn get(address: std::net::SocketAddr, method: &str, path: &str, auth: bool) -> String {
        let mut stream = TcpStream::connect(address).unwrap();
        let authorization = if auth {
            format!("Authorization: Bearer {SECRET}\r\n")
        } else {
            String::new()
        };
        write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: test\r\n{authorization}\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn serves_only_the_exported_image_to_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let (manifest, layer) = write_export(dir.path());
        std::fs::write(dir.path().join("blobs/sha256").join("c".repeat(64)), b"x").unwrap();
        let export = Export::read(dir.path().into(), repository_of("move-1")).unwrap();
        assert_eq!(export.manifest_digest, manifest);
        assert_eq!(export.blobs.len(), 2);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let deadline = Arc::new(AtomicI64::new(now_millis() + 60_000));
        let stop = Arc::new(AtomicBool::new(false));
        let server = {
            let (deadline, stop) = (deadline.clone(), stop.clone());
            std::thread::spawn(move || {
                run_server(listener, Arc::new(export), digest(SECRET), &deadline, &stop)
            })
        };

        let ping = get(address, "GET", "/v2/", false);
        assert!(ping.starts_with("HTTP/1.1 401 "), "{ping}");
        assert!(ping.contains("WWW-Authenticate: Basic realm=\"coolify-image-transfer\""));
        assert!(get(address, "GET", "/v2/", true).starts_with("HTTP/1.1 200 "));

        let path = format!("/v2/coolify-transfer/move-1/manifests/{manifest}");
        let response = get(address, "GET", &path, true);
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
        assert!(response.contains(&format!("Content-Type: {OCI_MANIFEST}\r\n")));
        assert!(response.contains(&format!("Docker-Content-Digest: {manifest}\r\n")));
        let body = std::fs::read(dir.path().join("blobs/sha256").join(&manifest[7..])).unwrap();
        assert!(
            response.ends_with(&*String::from_utf8_lossy(&body)),
            "{response}"
        );

        let path = format!("/v2/coolify-transfer/move-1/blobs/{layer}");
        let head = get(address, "HEAD", &path, true);
        assert!(head.contains("Content-Length: 9\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "{head}");
        assert!(get(address, "GET", &path, true).ends_with("\r\n\r\nlayer tar"));

        for (method, path, status) in [
            (
                "GET",
                format!("/v2/coolify-transfer/move-1/blobs/{}", sha('c')),
                404,
            ),
            (
                "GET",
                "/v2/coolify-transfer/move-1/blobs/sha256:../index.json".into(),
                404,
            ),
            (
                "GET",
                format!("/v2/coolify-transfer/other/blobs/{layer}"),
                404,
            ),
            (
                "GET",
                "/v2/coolify-transfer/move-1/manifests/v1".into(),
                404,
            ),
            (
                "PUT",
                format!("/v2/coolify-transfer/move-1/blobs/{layer}"),
                405,
            ),
        ] {
            let response = get(address, method, &path, true);
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} ")),
                "{method} {path}: {response}"
            );
        }

        // A TLS ClientHello gets no answer and no wait for more bytes.
        let started = Instant::now();
        let mut tls = TcpStream::connect(address).unwrap();
        tls.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05]).unwrap();
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer);
        assert!(answer.is_empty());
        assert!(started.elapsed() < READ_TIMEOUT);

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
        assert!(TcpStream::connect(address).is_err());
    }

    #[test]
    fn stops_serving_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        write_export(dir.path());
        let export = Export::read(dir.path().into(), repository_of("move-1")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let deadline = AtomicI64::new(now_millis() + 200);
        let started = Instant::now();
        run_server(
            listener,
            Arc::new(export),
            digest(SECRET),
            &deadline,
            &AtomicBool::new(false),
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn rejects_an_export_with_a_missing_layer() {
        let dir = tempfile::tempdir().unwrap();
        let (_, layer) = write_export(dir.path());
        std::fs::remove_file(dir.path().join("blobs/sha256").join(&layer[7..])).unwrap();
        assert_eq!(
            Export::read(dir.path().into(), repository_of("move-1")).err(),
            Some("Podman wrote an invalid image export.".into())
        );
    }
}
