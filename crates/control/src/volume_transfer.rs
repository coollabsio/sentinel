//! Volume moves between Nodes (decision 0007). The source Node serves its
//! volumes read-only with a temporary `rsync --daemon` on its WireGuard
//! address (`volume.serve.v1`); the target Node copies them into local volumes
//! with the `rsync` client (`volume.receive.v1`).
//!
//! Both keep their state in memory only: the requests hold the transfer
//! secret, so they are never journaled. On start Sentinel removes the daemons,
//! files and firewall elements that an earlier process left behind.
//!
//! The `coolify_cluster` input chain drops all traffic from the cluster CIDR
//! except a few fixed ports. A transfer port is opened with an element
//! `<peer_ip> . <port>` in the set `volume_transfers` of that table, matched by
//! one rule at the top of the input chain. A firewall reconcile replaces the
//! whole table, so it calls [`restore_firewall`] to add the set, the rule and
//! the elements of the running transfers again.
//!
//! The output chain drops all traffic to the cluster CIDR as well, so the
//! target Node opens its connection to the source with an element
//! `<source_ip> . <port>` in the set `volume_transfer_sources`, matched by one
//! rule at the top of the output chain, while a receive pass runs.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use sentinel_protocol::control::v1::{
    VolumeReceiveRequest, VolumeReceiveResult, VolumeServeRequest, VolumeServeResult, VolumeUsage,
};
use sha2::{Digest, Sha256};

use crate::network::{COOLIFY_NFT_TABLE, ipv4_in_cidr, output_with_timeout, read_applied_network};
use crate::volumes::{ensure_volumes, mountpoint, validate_names};

const RUNTIME_DIR: &str = "run/coolify-volume-transfer";
const PORTS: std::ops::RangeInclusive<u16> = 7800..=7899;
const NFT_SET: &str = "volume_transfers";
const NFT_SOURCE_SET: &str = "volume_transfer_sources";
const RSYNC_USER: &str = "coolify";
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(5);
const NFT_TIMEOUT: Duration = Duration::from_secs(30);
/// A finished receive pass stays readable this long.
const RECEIVE_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const RECEIVE_MAX_ENTRIES: usize = 256;
const ERROR_MAX_CHARS: usize = 2_000;
/// The longest checksum check of one volume. It reads all data on both Nodes.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);

fn valid_transfer_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn valid_secret(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn ensure_rsync() -> Result<(), String> {
    match output_with_timeout(
        Command::new("rsync").arg("--version"),
        Duration::from_secs(10),
    ) {
        Ok(output) if output.status.success() => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err("rsync is not installed on this Node.".into())
        }
        _ => Err("rsync is not usable on this Node.".into()),
    }
}

/// This Node's place in the cluster mesh, from the applied network state.
struct Mesh {
    interface: String,
    address: Ipv4Addr,
    peer_cidrs: Vec<String>,
    workload_cidrs: Vec<String>,
}

impl Mesh {
    fn read(root: &Path) -> Result<Self, String> {
        let applied = read_applied_network(root);
        let firewall = applied
            .firewall
            .ok_or("The cluster firewall is not applied on this Node.")?;
        let wireguard = applied
            .wireguard
            .into_iter()
            .find(|wireguard| wireguard.interface == firewall.wireguard_interface)
            .ok_or("The cluster WireGuard interface is not applied on this Node.")?;
        let address = wireguard
            .address
            .strip_suffix("/32")
            .and_then(|address| address.parse().ok())
            .ok_or("The cluster WireGuard address is invalid.")?;
        Ok(Self {
            interface: firewall.wireguard_interface,
            address,
            peer_cidrs: wireguard.peer_addresses,
            workload_cidrs: firewall.workload_cidrs,
        })
    }

    /// The address of another Node: routed to a WireGuard peer, and not a
    /// workload address.
    fn peer_node(&self, value: &str) -> Result<Ipv4Addr, String> {
        let address: Ipv4Addr = value
            .parse()
            .map_err(|_| "The peer address is invalid.".to_string())?;
        if address == self.address
            || !self.peer_cidrs.iter().any(|cidr| ipv4_in_cidr(value, cidr))
            || self
                .workload_cidrs
                .iter()
                .any(|cidr| ipv4_in_cidr(value, cidr))
        {
            return Err("The peer address is not a Node of this cluster.".into());
        }
        Ok(address)
    }
}

fn nft(arguments: &[&str]) -> Result<std::process::Output, String> {
    output_with_timeout(Command::new("nft").args(arguments), NFT_TIMEOUT)
        .map_err(|_| "nftables is unavailable.".to_string())
}

fn nft_run(arguments: &[&str], fallback: &str) -> Result<(), String> {
    let output = nft(arguments)?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if message.is_empty() {
        fallback.into()
    } else {
        message.chars().take(ERROR_MAX_CHARS).collect()
    })
}

/// Adds the set and its rule to the `coolify_cluster` table when they are missing.
fn ensure_firewall_set(interface: &str) -> Result<(), String> {
    nft_run(
        &[
            "add",
            "set",
            "inet",
            COOLIFY_NFT_TABLE,
            NFT_SET,
            "{ type ipv4_addr . inet_service ; }",
        ],
        "The volume transfer firewall set could not be added.",
    )?;
    let chain = nft(&["list", "chain", "inet", COOLIFY_NFT_TABLE, "input"])?;
    if !chain.status.success() {
        return Err("The Coolify firewall table is not active.".into());
    }
    if String::from_utf8_lossy(&chain.stdout).contains(&format!("@{NFT_SET}")) {
        return Ok(());
    }
    let interface = format!("\"{interface}\"");
    let set = format!("@{NFT_SET}");
    nft_run(
        &[
            "insert",
            "rule",
            "inet",
            COOLIFY_NFT_TABLE,
            "input",
            "iifname",
            &interface,
            "ip",
            "saddr",
            ".",
            "tcp",
            "dport",
            &set,
            "accept",
        ],
        "The volume transfer firewall rule could not be added.",
    )
}

/// Adds the source set and its output rule to the `coolify_cluster` table when they are missing.
fn ensure_source_set(interface: &str) -> Result<(), String> {
    nft_run(
        &[
            "add",
            "set",
            "inet",
            COOLIFY_NFT_TABLE,
            NFT_SOURCE_SET,
            "{ type ipv4_addr . inet_service ; }",
        ],
        "The volume transfer firewall set could not be added.",
    )?;
    let chain = nft(&["list", "chain", "inet", COOLIFY_NFT_TABLE, "output"])?;
    if !chain.status.success() {
        return Err("The Coolify firewall table is not active.".into());
    }
    if String::from_utf8_lossy(&chain.stdout).contains(&format!("@{NFT_SOURCE_SET}")) {
        return Ok(());
    }
    let interface = format!("\"{interface}\"");
    let set = format!("@{NFT_SOURCE_SET}");
    nft_run(
        &[
            "insert",
            "rule",
            "inet",
            COOLIFY_NFT_TABLE,
            "output",
            "oifname",
            &interface,
            "ip",
            "daddr",
            ".",
            "tcp",
            "dport",
            &set,
            "accept",
        ],
        "The volume transfer firewall rule could not be added.",
    )
}

fn allow_source(interface: &str, source: Ipv4Addr, port: u16) -> Result<(), String> {
    ensure_source_set(interface)?;
    nft_run(
        &[
            "add",
            "element",
            "inet",
            COOLIFY_NFT_TABLE,
            NFT_SOURCE_SET,
            &firewall_element(source, port),
        ],
        "The volume transfer firewall rule could not be added.",
    )
}

fn revoke_source(source: Ipv4Addr, port: u16) {
    let _ = nft(&[
        "delete",
        "element",
        "inet",
        COOLIFY_NFT_TABLE,
        NFT_SOURCE_SET,
        &firewall_element(source, port),
    ]);
}

fn firewall_element(peer: Ipv4Addr, port: u16) -> String {
    format!("{{ {peer} . {port} }}")
}

fn allow_peer(interface: &str, peer: Ipv4Addr, port: u16) -> Result<(), String> {
    ensure_firewall_set(interface)?;
    nft_run(
        &[
            "add",
            "element",
            "inet",
            COOLIFY_NFT_TABLE,
            NFT_SET,
            &firewall_element(peer, port),
        ],
        "The volume transfer firewall rule could not be added.",
    )
}

fn revoke_peer(peer: Ipv4Addr, port: u16) {
    let _ = nft(&[
        "delete",
        "element",
        "inet",
        COOLIFY_NFT_TABLE,
        NFT_SET,
        &firewall_element(peer, port),
    ]);
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
            tracing::warn!(%error, port, "could not restore a volume transfer firewall rule");
        }
    }
    let receives = RECEIVES
        .lock()
        .map(|receives| {
            receives
                .values()
                .filter(|receive| {
                    receive.host
                        && receive
                            .progress
                            .lock()
                            .is_ok_and(|progress| progress.state == PassState::Running)
                })
                .map(|receive| (receive.interface.clone(), receive.source))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (interface, (source, port)) in receives {
        if let Ok(port) = u16::try_from(port)
            && let Err(error) = allow_source(&interface, source, port)
        {
            tracing::warn!(%error, port, "could not restore a volume transfer firewall rule");
        }
    }
}

fn runtime_dir(root: &Path) -> PathBuf {
    root.join(RUNTIME_DIR)
}

fn kill_group(pid: u32) {
    let _ = output_with_timeout(
        Command::new("kill").args(["-s", "KILL", "--", &format!("-{pid}")]),
        Duration::from_secs(10),
    );
}

/// Removes what an earlier Sentinel process left behind: rsync daemons, their
/// files and the firewall elements. Runs once when Sentinel starts.
pub(crate) fn remove_leftovers(root: &Path) {
    let directory = runtime_dir(root);
    if let Ok(entries) = std::fs::read_dir(&directory) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid) = std::fs::read_to_string(path.join("pid"))
                .ok()
                .and_then(|pid| pid.trim().parse::<u32>().ok())
            {
                let config = path.join("rsyncd.conf");
                let ours = std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
                    String::from_utf8_lossy(&cmdline).contains(&config.display().to_string())
                });
                if ours {
                    kill_group(pid);
                }
            }
            let _ = std::fs::remove_dir_all(&path);
        }
    }
    if root == Path::new("/") {
        let _ = nft(&["flush", "set", "inet", COOLIFY_NFT_TABLE, NFT_SET]);
        let _ = nft(&["flush", "set", "inet", COOLIFY_NFT_TABLE, NFT_SOURCE_SET]);
    }
}

/// A running rsync daemon. Its worker thread owns the process and removes the
/// daemon, its files and its firewall element when it stops.
struct Serve {
    generation: u64,
    root: PathBuf,
    names: Vec<String>,
    peer_ip: Ipv4Addr,
    secret: [u8; 32],
    interface: String,
    address: Ipv4Addr,
    port: u16,
    deadline: Arc<AtomicI64>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}

static SERVES: Mutex<BTreeMap<String, Serve>> = Mutex::new(BTreeMap::new());
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub(crate) fn validate_serve(request: &VolumeServeRequest) -> Result<(), String> {
    if !valid_transfer_id(&request.transfer_id) {
        return Err("The transfer ID is invalid.".into());
    }
    if request.stop {
        return Ok(());
    }
    validate_names(&request.names)?;
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
        let _ = serve.stop.send(());
        if let Some(worker) = serve.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) fn serve(
    root: &Path,
    podman: &Path,
    request: &VolumeServeRequest,
) -> Result<VolumeServeResult, String> {
    validate_serve(request)?;
    if request.stop {
        stop_serve(&request.transfer_id);
        let _ = std::fs::remove_dir_all(runtime_dir(root).join(&request.transfer_id));
        return Ok(VolumeServeResult::default());
    }
    let peer_ip: Ipv4Addr = request
        .peer_ip
        .parse()
        .map_err(|_| "The peer address is invalid.")?;
    let mut names = request.names.clone();
    names.sort();
    let secret = digest(&request.secret);

    let running = {
        let serves = SERVES
            .lock()
            .map_err(|_| "The transfer state is unavailable.")?;
        match serves.get(&request.transfer_id) {
            Some(serve)
                if serve.names != names || serve.peer_ip != peer_ip || serve.secret != secret =>
            {
                return Err("The transfer ID is already used for other volumes.".into());
            }
            Some(serve) => {
                serve
                    .deadline
                    .fetch_max(request.expires_at_unix_ms, Ordering::SeqCst);
                Some((serve.address, serve.port))
            }
            None => None,
        }
    };
    let mountpoints = names
        .iter()
        .map(|name| mountpoint(podman, name).map(|path| (name.clone(), path)))
        .collect::<Result<Vec<_>, _>>()?;
    let (address, port) = match running {
        Some(running) => running,
        None => start_serve(root, request, peer_ip, names, secret, &mountpoints)?,
    };
    Ok(VolumeServeResult {
        address: address.to_string(),
        port: u32::from(port),
        volumes: mountpoints
            .iter()
            .map(|(name, path)| VolumeUsage {
                name: name.clone(),
                used_bytes: used_bytes(Path::new(path)),
            })
            .collect(),
    })
}

fn start_serve(
    root: &Path,
    request: &VolumeServeRequest,
    peer_ip: Ipv4Addr,
    names: Vec<String>,
    secret: [u8; 32],
    mountpoints: &[(String, String)],
) -> Result<(Ipv4Addr, u16), String> {
    ensure_rsync()?;
    let mesh = Mesh::read(root)?;
    mesh.peer_node(&request.peer_ip)?;
    let used_ports: HashSet<u16> = SERVES
        .lock()
        .map(|serves| serves.values().map(|serve| serve.port).collect())
        .unwrap_or_default();
    let directory = runtime_dir(root).join(&request.transfer_id);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .map_err(|_| "The transfer directory could not be created.")?;
    let result = (|| {
        write_private(
            &directory.join("secrets"),
            format!("{RSYNC_USER}:{}\n", request.secret).as_bytes(),
        )?;
        let mut last_error = "No transfer port is free.".to_string();
        for port in PORTS.filter(|port| !used_ports.contains(port)) {
            let config = rsyncd_config(&directory, mesh.address, port, peer_ip, mountpoints);
            write_private(&directory.join("rsyncd.conf"), config.as_bytes())?;
            match start_daemon(&directory, mesh.address, port) {
                Ok(child) => return Ok((port, child)),
                Err(DaemonError::PortInUse) => continue,
                Err(DaemonError::Failed(message)) => {
                    last_error = message;
                    break;
                }
            }
        }
        Err(last_error)
    })();
    let (port, mut child) = match result {
        Ok(started) => started,
        Err(message) => {
            let _ = std::fs::remove_dir_all(&directory);
            return Err(message);
        }
    };
    if root == Path::new("/")
        && let Err(message) = allow_peer(&mesh.interface, peer_ip, port)
    {
        kill_group(child.id());
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&directory);
        return Err(message);
    }

    let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
    let deadline = Arc::new(AtomicI64::new(request.expires_at_unix_ms));
    let (stop, stopped) = mpsc::channel();
    let worker = {
        let deadline = deadline.clone();
        let transfer_id = request.transfer_id.clone();
        let root = root.to_path_buf();
        std::thread::spawn(move || {
            loop {
                let remaining = deadline.load(Ordering::SeqCst) - now_millis();
                if remaining <= 0 {
                    tracing::info!(transfer_id, "volume transfer expired");
                    break;
                }
                match stopped.recv_timeout(Duration::from_millis(remaining.clamp(1, 1_000) as u64))
                {
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    _ => break,
                }
                if child.try_wait().ok().flatten().is_some() {
                    tracing::warn!(transfer_id, "the volume transfer daemon exited");
                    break;
                }
            }
            kill_group(child.id());
            let _ = child.wait();
            if root == Path::new("/") {
                revoke_peer(peer_ip, port);
            }
            if let Ok(mut serves) = SERVES.lock()
                && serves
                    .get(&transfer_id)
                    .is_some_and(|serve| serve.generation == generation)
            {
                serves.remove(&transfer_id);
                let _ = std::fs::remove_dir_all(runtime_dir(&root).join(&transfer_id));
            }
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
                names,
                peer_ip,
                secret,
                interface: mesh.interface,
                address: mesh.address,
                port,
                deadline,
                stop,
                worker: Some(worker),
            },
        );
    Ok((mesh.address, port))
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .map_err(|_| "A transfer file could not be written.".into())
}

fn rsyncd_config(
    directory: &Path,
    address: Ipv4Addr,
    port: u16,
    peer_ip: Ipv4Addr,
    mountpoints: &[(String, String)],
) -> String {
    let mut config = format!(
        "address = {address}\nport = {port}\nuse chroot = yes\nread only = yes\nnumeric ids = yes\nuid = 0\ngid = 0\nreverse lookup = no\nlog file = {}\n",
        directory.join("rsyncd.log").display()
    );
    let secrets = directory.join("secrets");
    for (name, path) in mountpoints {
        config.push_str(&format!(
            "\n[{name}]\npath = {path}\nauth users = {RSYNC_USER}\nsecrets file = {}\nhosts allow = {peer_ip}\nhosts deny = *\n",
            secrets.display()
        ));
    }
    config
}

enum DaemonError {
    PortInUse,
    Failed(String),
}

/// `/proc/net/tcp` prints an IPv4 address as the hex of its bytes read as a
/// little-endian number, and the port in hex.
fn listening(address: Ipv4Addr, port: u16) -> bool {
    let local = format!("{:08X}:{port:04X}", u32::from_le_bytes(address.octets()));
    std::fs::read_to_string("/proc/net/tcp").is_ok_and(|table| {
        table.lines().skip(1).any(|line| {
            let mut fields = line.split_whitespace();
            fields.nth(1) == Some(local.as_str()) && fields.nth(1) == Some("0A")
        })
    })
}

fn start_daemon(directory: &Path, address: Ipv4Addr, port: u16) -> Result<Child, DaemonError> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(directory.join("rsyncd.log"))
        .map_err(|_| DaemonError::Failed("The transfer log could not be opened.".into()))?;
    let mut child = Command::new("rsync")
        .arg("--daemon")
        .arg("--no-detach")
        .arg(format!(
            "--config={}",
            directory.join("rsyncd.conf").display()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        // Its own process group, so a stop also ends the per-connection children.
        .process_group(0)
        .spawn()
        .map_err(|error| {
            DaemonError::Failed(if error.kind() == std::io::ErrorKind::NotFound {
                "rsync is not installed on this Node.".into()
            } else {
                "The rsync daemon could not be started.".into()
            })
        })?;
    let _ = std::fs::write(directory.join("pid"), child.id().to_string());
    let started = Instant::now();
    while started.elapsed() < DAEMON_START_TIMEOUT {
        if child.try_wait().ok().flatten().is_some() {
            let log = std::fs::read_to_string(directory.join("rsyncd.log")).unwrap_or_default();
            let _ = std::fs::remove_file(directory.join("rsyncd.log"));
            return Err(if log.contains("Address already in use") {
                DaemonError::PortInUse
            } else {
                DaemonError::Failed(tail(&log, "The rsync daemon exited."))
            });
        }
        if listening(address, port) {
            return Ok(child);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    kill_group(child.id());
    let _ = child.wait();
    Err(DaemonError::Failed(
        "The rsync daemon did not start in time.".into(),
    ))
}

fn tail(text: &str, fallback: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        return fallback.into();
    }
    let characters = text.chars().count();
    text.chars()
        .skip(characters.saturating_sub(ERROR_MAX_CHARS))
        .collect()
}

/// The apparent size of the files under `path`, like `du -sb`: a hard-linked
/// file counts once, and symbolic links are not followed.
fn used_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut seen = HashSet::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            }
            if metadata.nlink() > 1
                && !metadata.is_dir()
                && !seen.insert((metadata.dev(), metadata.ino()))
            {
                continue;
            }
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PassState {
    Running,
    Succeeded,
    Failed,
}

impl PassState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

struct Progress {
    state: PassState,
    bytes_total: u64,
    bytes_done: u64,
    error: String,
    finished_at: Option<Instant>,
    /// A failure was returned to Coolify; the next request starts the pass again.
    failure_reported: bool,
}

struct Receive {
    source: (Ipv4Addr, u32),
    /// The WireGuard interface of the output allow.
    interface: String,
    /// Runs on the host, so the output allow is in the host firewall.
    host: bool,
    names: Vec<String>,
    secret: [u8; 32],
    progress: Arc<Mutex<Progress>>,
}

static RECEIVES: Mutex<BTreeMap<(String, String), Receive>> = Mutex::new(BTreeMap::new());

pub(crate) fn validate_receive(request: &VolumeReceiveRequest) -> Result<(), String> {
    if !valid_transfer_id(&request.transfer_id) {
        return Err("The transfer ID is invalid.".into());
    }
    if !matches!(request.pass.as_str(), "warm" | "final" | "verify") {
        return Err("The transfer pass is invalid.".into());
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
    validate_names(&request.names)
}

fn snapshot(progress: &Mutex<Progress>) -> VolumeReceiveResult {
    let Ok(mut progress) = progress.lock() else {
        return VolumeReceiveResult {
            state: PassState::Failed.as_str().into(),
            error: "The transfer state is unavailable.".into(),
            ..Default::default()
        };
    };
    if progress.state == PassState::Failed {
        progress.failure_reported = true;
    }
    VolumeReceiveResult {
        state: progress.state.as_str().into(),
        bytes_total: progress.bytes_total,
        bytes_done: progress.bytes_done,
        error: progress.error.clone(),
    }
}

fn prune(receives: &mut BTreeMap<(String, String), Receive>) {
    let finished = |receive: &Receive| {
        receive
            .progress
            .lock()
            .ok()
            .and_then(|progress| progress.finished_at)
    };
    receives
        .retain(|_, receive| finished(receive).is_none_or(|at| at.elapsed() < RECEIVE_RETENTION));
    while receives.len() > RECEIVE_MAX_ENTRIES {
        let oldest = receives
            .iter()
            .filter_map(|(key, receive)| finished(receive).map(|at| (at, key.clone())))
            .min_by_key(|(at, _)| *at)
            .map(|(_, key)| key);
        match oldest {
            Some(key) => {
                receives.remove(&key);
            }
            None => break,
        }
    }
}

pub(crate) fn receive(
    root: &Path,
    podman: &Path,
    request: &VolumeReceiveRequest,
) -> Result<VolumeReceiveResult, String> {
    validate_receive(request)?;
    let source_address: Ipv4Addr = request
        .source_address
        .parse()
        .map_err(|_| "The source address is invalid.")?;
    let source = (source_address, request.source_port);
    let mut names = request.names.clone();
    names.sort();
    let secret = digest(&request.secret);
    let key = (request.transfer_id.clone(), request.pass.clone());

    let mut receives = RECEIVES
        .lock()
        .map_err(|_| "The transfer state is unavailable.")?;
    prune(&mut receives);
    if let Some(existing) = receives.get(&key) {
        if existing.source != source || existing.names != names || existing.secret != secret {
            return Err("The transfer ID is already used for other volumes.".into());
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
    if receives.iter().any(|((transfer_id, pass), receive)| {
        *transfer_id == request.transfer_id
            && *pass != request.pass
            && receive
                .progress
                .lock()
                .is_ok_and(|progress| progress.state == PassState::Running)
    }) {
        return Err("Another pass of this transfer is still running.".into());
    }
    ensure_rsync()?;
    let mesh = Mesh::read(root)?;
    mesh.peer_node(&request.source_address)?;
    let source_port =
        u16::try_from(request.source_port).map_err(|_| "The source port is invalid.")?;
    let host = root == Path::new("/");
    ensure_volumes(podman, names.iter().map(String::as_str))?;
    let mountpoints = names
        .iter()
        .map(|name| mountpoint(podman, name).map(|path| (name.clone(), path)))
        .collect::<Result<Vec<_>, _>>()?;

    let progress = Arc::new(Mutex::new(Progress {
        state: PassState::Running,
        bytes_total: 0,
        bytes_done: 0,
        error: String::new(),
        finished_at: None,
        failure_reported: false,
    }));
    receives.insert(
        key,
        Receive {
            source,
            interface: mesh.interface.clone(),
            host,
            names,
            secret,
            progress: progress.clone(),
        },
    );
    drop(receives);
    if host && let Err(error) = allow_source(&mesh.interface, source_address, source_port) {
        if let Ok(mut progress) = progress.lock() {
            progress.state = PassState::Failed;
            progress.error = error.clone();
            progress.finished_at = Some(Instant::now());
        }
        return Err(error);
    }

    let worker_progress = progress.clone();
    let warm = request.pass == "warm";
    let verify = request.pass == "verify";
    let password = request.secret.clone();
    let transfer_id = request.transfer_id.clone();
    std::thread::spawn(move || {
        let outcome = if verify {
            verify_volumes(source, &password, &mountpoints)
        } else {
            copy_volumes(source, &password, &mountpoints, warm, &worker_progress)
        };
        if host {
            revoke_source(source_address, source_port);
        }
        if let Err(error) = &outcome {
            tracing::warn!(transfer_id, %error, "a volume transfer pass failed");
        }
        if let Ok(mut progress) = worker_progress.lock() {
            match outcome {
                Ok(()) => {
                    progress.state = PassState::Succeeded;
                    progress.bytes_total = progress.bytes_total.max(progress.bytes_done);
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

/// Compares every file of each volume with the source by checksum, without
/// changing anything. It fails when rsync would copy, change, or delete any
/// file, so a move switches only to an exact copy.
fn verify_volumes(
    (address, port): (Ipv4Addr, u32),
    password: &str,
    mountpoints: &[(String, String)],
) -> Result<(), String> {
    for (name, path) in mountpoints {
        let output = output_with_timeout(
            Command::new("rsync")
                .args([
                    "-aHAX",
                    "--numeric-ids",
                    "--checksum",
                    "--dry-run",
                    "--delete",
                    "--itemize-changes",
                    "--no-inc-recursive",
                    "--contimeout=30",
                    "--timeout=600",
                ])
                .arg(format!("rsync://{RSYNC_USER}@{address}:{port}/{name}/"))
                .arg(format!("{path}/"))
                .env_clear()
                .env(
                    "PATH",
                    std::env::var_os("PATH")
                        .unwrap_or_else(|| "/usr/sbin:/usr/bin:/sbin:/bin".into()),
                )
                .env("LC_ALL", "C")
                .env("RSYNC_PASSWORD", password)
                .stdin(Stdio::null()),
            VERIFY_TIMEOUT,
        )
        .map_err(|_| format!("The check of the volume {name} did not finish."))?;
        if !output.status.success() {
            return Err(tail(
                &String::from_utf8_lossy(&output.stderr),
                &format!("rsync could not check the volume {name}."),
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let differences: Vec<&str> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        if !differences.is_empty() {
            return Err(format!(
                "The copy of the volume {name} differs from the source in {} entries, for example: {}",
                differences.len(),
                differences.iter().take(5).copied().collect::<Vec<_>>().join("; ")
            )
            .chars()
            .take(ERROR_MAX_CHARS)
            .collect());
        }
    }
    Ok(())
}

/// Copies the volumes one after another. `bytes_done` and `bytes_total` add up
/// all volumes; the total of the volume being copied is estimated from the
/// rsync percentage, so it grows while the pass runs.
fn copy_volumes(
    (address, port): (Ipv4Addr, u32),
    password: &str,
    mountpoints: &[(String, String)],
    warm: bool,
    progress: &Mutex<Progress>,
) -> Result<(), String> {
    let mut finished_bytes = 0u64;
    for (name, path) in mountpoints {
        let mut child = Command::new("rsync")
            .args([
                "-aHAX",
                "--numeric-ids",
                "--sparse",
                "--delete",
                "--info=progress2",
                "--no-inc-recursive",
                "--contimeout=30",
                "--timeout=600",
            ])
            .arg(format!("rsync://{RSYNC_USER}@{address}:{port}/{name}/"))
            .arg(format!("{path}/"))
            .env_clear()
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| "/usr/sbin:/usr/bin:/sbin:/bin".into()),
            )
            .env("LC_ALL", "C")
            .env("RSYNC_PASSWORD", password)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    "rsync is not installed on this Node.".to_string()
                } else {
                    "rsync could not be started.".to_string()
                }
            })?;
        let stderr = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                let mut output = Vec::new();
                let _ = stderr.read_to_end(&mut output);
                output
            })
        });
        let mut volume_done = 0u64;
        if let Some(mut stdout) = child.stdout.take() {
            let mut buffer = [0u8; 4096];
            let mut line = Vec::new();
            while let Ok(read) = stdout.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                for &byte in &buffer[..read] {
                    if byte != b'\r' && byte != b'\n' {
                        if line.len() < 512 {
                            line.push(byte);
                        }
                        continue;
                    }
                    if let Some((done, percent)) = parse_progress(&String::from_utf8_lossy(&line)) {
                        volume_done = done;
                        if let Ok(mut progress) = progress.lock() {
                            progress.bytes_done = finished_bytes.saturating_add(done);
                            let volume_total =
                                done.saturating_mul(100).checked_div(percent).unwrap_or(0);
                            progress.bytes_total =
                                finished_bytes.saturating_add(volume_total.max(done));
                        }
                    }
                    line.clear();
                }
            }
        }
        let status = child
            .wait()
            .map_err(|_| "rsync did not finish.".to_string())?;
        let stderr = stderr
            .and_then(|reader| reader.join().ok())
            .map(|output| String::from_utf8_lossy(&output).into_owned())
            .unwrap_or_default();
        // 24: source files vanished while the source still ran; the final pass copies them.
        if !status.success() && !(warm && status.code() == Some(24)) {
            return Err(tail(
                &stderr,
                &format!("rsync failed for the volume {name}."),
            ));
        }
        finished_bytes = finished_bytes.saturating_add(volume_done);
        if let Ok(mut progress) = progress.lock() {
            progress.bytes_done = finished_bytes;
            progress.bytes_total = finished_bytes;
        }
    }
    Ok(())
}

/// Parses an `--info=progress2` line such as
/// `  1,234,567  45%   10.00MB/s    0:00:10 (xfr#1, to-chk=0/3)`.
fn parse_progress(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_whitespace();
    let done = fields.next()?.replace(',', "").parse().ok()?;
    let percent = fields.next()?.strip_suffix('%')?.parse().ok()?;
    Some((done, percent))
}
