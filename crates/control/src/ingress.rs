//! Thin HTTP ingress: Caddy on port 80 of every ingress Node, with the
//! cluster-wide route table in Corrosion.
//!
//! Coolify writes routes (host to workload and port) and internal names (DNS
//! label to workload) through `ingress.reconcile.v1`, sent to every Node.
//! Workloads are identified by their `coolify.workload` container label, so a
//! domain or name change needs no redeploy. Every ingress Node then renders its
//! own Caddy configuration from its local Corrosion: the routes plus the live
//! workload endpoints that the Sentinels publish. A Node therefore keeps
//! routing, and follows workload moves, while Coolify is unavailable.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sentinel_protocol::control::v1::{
    IngressReconcileRequest, IngressReconcileResult, IngressRoute, WorkloadName,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use tokio::sync::{Notify, watch};

use crate::network::{
    atomic_write, run as run_command, state_path, valid_discovery_label, write_if_changed,
};

/// The tested Caddy release. Coolify must request exactly this version.
pub(crate) const CADDY_VERSION: &str = "v2.11.7";
/// SHA-512 of `caddy_2.11.7_linux_amd64.tar.gz`, from
/// <https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_checksums.txt>.
const CADDY_SHA512_LINUX_AMD64: &str = "a7a433a1b133efc3c8d10eb0b99d52a24b5ef5c322dc77f5282182b1c0402139ab83f3a99f0c52409df77d20123fb0b523edad8a66d8f5e49136197bf61ef0e7";
/// SHA-512 of `caddy_2.11.7_linux_arm64.tar.gz`, from the same checksums file.
const CADDY_SHA512_LINUX_ARM64: &str = "3db36ba90c7a6e8dda40ee3dd71fa08844c76b5fb08f61b31e5e78d2ed38e71c51dc7baed875e50d1ca1279196e84302967237386ae87c91ae9f2aaceada682e";

pub(crate) const MAX_ROUTES: usize = 10_000;
pub(crate) const MAX_NAMES: usize = 10_000;
pub(crate) const RENDER_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const INGRESS_UNIT: &str = "coolify-ingress.service";
pub(crate) const INGRESS_UNIT_FILE: &str = "etc/systemd/system/coolify-ingress.service";
/// Outside `/etc/coolify`, which is root-only: the unprivileged Caddy user
/// reads this file when it starts.
pub(crate) const INGRESS_CONFIG_FILE: &str = "etc/coolify-ingress/caddy.json";
const INGRESS_CONFIG_DIR: &str = "etc/coolify-ingress";
const INGRESS_STATE_FILE: &str = "ingress.state";
const ADMIN_SOCKET: &str = "/run/coolify-ingress/admin.sock";
const CADDY_BINARY: &str = "/usr/local/bin/caddy";
const CADDY_VERSION_FILE: &str = "/usr/local/bin/caddy.version";
const INGRESS_USER: &str = "coolify-ingress";
const INGRESS_HOME: &str = "/var/lib/coolify-ingress";
/// Endpoints in this namespace are Node WireGuard addresses, never workloads.
const NODE_NAMESPACE: &str = "nodes";
const NO_UPSTREAM_BODY: &str = "No healthy upstream\n";
const NOT_FOUND_BODY: &str = "Not Found\n";

/// Serializes the renderer with the ingress command and cluster leave, so a
/// render cannot re-create the configuration after ingress was removed.
static INGRESS: Mutex<()> = Mutex::new(());

pub(crate) fn ingress_lock() -> MutexGuard<'static, ()> {
    INGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(crate) fn state_file(root: &Path) -> PathBuf {
    state_path(root, INGRESS_STATE_FILE)
}

pub(crate) fn enabled(root: &Path) -> bool {
    state_file(root).exists()
}

/// A lowercase RFC 1123 hostname with at least two labels. IP addresses,
/// wildcards and a trailing dot are rejected.
pub(crate) fn valid_ingress_host(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || !host.contains('.')
        || host.ends_with('.')
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let labels = host.split('.').collect::<Vec<_>>();
    // An all-numeric top-level label is an IP address in disguise (RFC 3696).
    if labels
        .last()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Validates the routes, names and revision. The Caddy version is checked by
/// [`validate_request`] so that a version mismatch gets a specific error.
pub(crate) fn validate_routes(request: &IngressReconcileRequest) -> Result<(), String> {
    // Revision 0 only disables Caddy: it carries no tables to write.
    let has_tables = request.enabled || !request.routes.is_empty() || !request.names.is_empty();
    if request.revision > i64::MAX as u64 || (has_tables && request.revision == 0) {
        return Err("The ingress revision is invalid.".into());
    }
    if request.routes.len() > MAX_ROUTES {
        return Err(format!("At most {MAX_ROUTES} ingress routes are allowed."));
    }
    let mut hosts = HashSet::with_capacity(request.routes.len());
    for route in &request.routes {
        if !valid_ingress_host(&route.host) {
            return Err("An ingress route host is invalid.".into());
        }
        if !valid_discovery_label(&route.workload_id)
            || !valid_discovery_label(&route.namespace)
            || route.namespace == NODE_NAMESPACE
        {
            return Err("An ingress route workload is invalid.".into());
        }
        if route.port == 0 || route.port > 65_535 {
            return Err("An ingress route port is invalid.".into());
        }
        if !hosts.insert(route.host.as_str()) {
            return Err("Ingress route hosts must be unique.".into());
        }
    }
    if request.names.len() > MAX_NAMES {
        return Err(format!("At most {MAX_NAMES} internal names are allowed."));
    }
    let mut names = HashSet::with_capacity(request.names.len());
    for name in &request.names {
        if !valid_discovery_label(&name.name)
            || !valid_discovery_label(&name.workload_id)
            || !valid_discovery_label(&name.namespace)
            || name.namespace == NODE_NAMESPACE
        {
            return Err("An internal name is invalid.".into());
        }
        if !names.insert((name.namespace.as_str(), name.name.as_str())) {
            return Err("Internal names must be unique.".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_request(request: &IngressReconcileRequest) -> Result<(), String> {
    validate_routes(request)?;
    // Disabling must keep working after a Sentinel upgrade changed the pin.
    let version_accepted = request.caddy_version == CADDY_VERSION
        || (!request.enabled && request.caddy_version.is_empty());
    if !version_accepted {
        return Err(format!(
            "Ingress must use the tested Caddy version {CADDY_VERSION}."
        ));
    }
    Ok(())
}

/// One `ingress_routes` row, without bookkeeping columns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StoredRoute {
    pub(crate) host: String,
    pub(crate) workload_id: String,
    pub(crate) namespace: String,
    pub(crate) port: u32,
}

impl From<&IngressRoute> for StoredRoute {
    fn from(route: &IngressRoute) -> Self {
        Self {
            host: route.host.clone(),
            workload_id: route.workload_id.clone(),
            namespace: route.namespace.clone(),
            port: route.port,
        }
    }
}

/// One `workload_names` row, without bookkeeping columns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StoredName {
    pub(crate) namespace: String,
    pub(crate) name: String,
    pub(crate) workload_id: String,
}

impl From<&WorkloadName> for StoredName {
    fn from(name: &WorkloadName) -> Self {
        Self {
            namespace: name.namespace.clone(),
            name: name.name.clone(),
            workload_id: name.workload_id.clone(),
        }
    }
}

/// The routes and names at the highest stored revision of each table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StoredRoutes {
    pub(crate) revision: Option<u64>,
    pub(crate) routes: Vec<StoredRoute>,
    pub(crate) names_revision: Option<u64>,
    pub(crate) names: Vec<StoredName>,
}

#[derive(Debug, PartialEq)]
pub(crate) enum RouteWrite {
    /// Corrosion already holds exactly this revision.
    Unchanged,
    Write(Vec<Value>),
}

pub(crate) fn routes_query_sql() -> &'static str {
    "SELECT host, workload_id, namespace, port, revision FROM ingress_routes WHERE revision = (SELECT MAX(revision) FROM ingress_routes) ORDER BY host"
}

pub(crate) fn names_query_sql() -> &'static str {
    "SELECT namespace, name, workload_id, revision FROM workload_names WHERE revision = (SELECT MAX(revision) FROM workload_names) ORDER BY namespace, name"
}

pub(crate) fn endpoints_query_sql() -> &'static str {
    "SELECT workload_id, namespace, owner_node_ip, container_ip FROM workload_endpoints WHERE namespace != 'nodes' AND state = 'running' AND health NOT IN ('unhealthy', 'starting') AND expires_at > unixepoch() ORDER BY namespace, workload_id, owner_node_ip, container_ip"
}

/// Whether a table must be written to reach `revision`. An older request is a
/// stale writer and fails; the same revision must carry the same rows.
fn table_needs_write<T: Ord + Clone>(
    table: &str,
    stored_revision: Option<u64>,
    stored: &[T],
    mut requested: Vec<T>,
    revision: u64,
) -> Result<bool, String> {
    let Some(stored_revision) = stored_revision else {
        return Ok(true);
    };
    if stored_revision > revision {
        return Err(format!(
            "The {table} are stale: revision {revision} is older than the stored revision {stored_revision}."
        ));
    }
    if stored_revision < revision {
        return Ok(true);
    }
    let mut existing = stored.to_vec();
    existing.sort();
    requested.sort();
    if requested == existing {
        return Ok(false);
    }
    Err(format!(
        "Revision {revision} is already stored with different {table}."
    ))
}

/// Decides how to bring the route and name tables in Corrosion to the
/// requested revision.
pub(crate) fn plan_route_write(
    stored: &StoredRoutes,
    request: &IngressReconcileRequest,
    now: i64,
) -> Result<RouteWrite, String> {
    let write_routes = table_needs_write(
        "ingress routes",
        stored.revision,
        &stored.routes,
        request.routes.iter().map(StoredRoute::from).collect(),
        request.revision,
    )?;
    let write_names = table_needs_write(
        "internal names",
        stored.names_revision,
        &stored.names,
        request.names.iter().map(StoredName::from).collect(),
        request.revision,
    )?;
    let mut transaction = Vec::new();
    if write_routes {
        transaction.extend(route_transaction(request, now)?);
    }
    if write_names {
        transaction.extend(name_transaction(request, now)?);
    }
    if transaction.is_empty() {
        return Ok(RouteWrite::Unchanged);
    }
    Ok(RouteWrite::Write(transaction))
}

/// Upserts every name at the request revision, then deletes names of older
/// revisions, like [`route_transaction`].
pub(crate) fn name_transaction(
    request: &IngressReconcileRequest,
    now: i64,
) -> Result<Vec<Value>, String> {
    validate_routes(request)?;
    let revision = i64::try_from(request.revision)
        .map_err(|_| "The ingress revision is invalid.".to_string())?;
    let mut names = request.names.iter().collect::<Vec<_>>();
    names
        .sort_by(|left, right| (&left.namespace, &left.name).cmp(&(&right.namespace, &right.name)));
    let mut transaction = Vec::with_capacity(names.len() + 1);
    for name in names {
        transaction.push(json!([
            "INSERT INTO workload_names (namespace, name, workload_id, revision, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (namespace, name) DO UPDATE SET workload_id = excluded.workload_id, revision = excluded.revision, updated_at = excluded.updated_at WHERE excluded.revision >= workload_names.revision",
            [name.namespace, name.name, name.workload_id, revision, now]
        ]));
    }
    transaction.push(json!([
        "DELETE FROM workload_names WHERE revision < ?",
        [revision]
    ]));
    Ok(transaction)
}

/// Upserts every route at the request revision, then deletes routes of older
/// revisions, in one Corrosion transaction. The upsert never moves a row back
/// to an older revision, so a concurrent stale writer cannot undo a newer one.
pub(crate) fn route_transaction(
    request: &IngressReconcileRequest,
    now: i64,
) -> Result<Vec<Value>, String> {
    validate_routes(request)?;
    let revision = i64::try_from(request.revision)
        .map_err(|_| "The ingress revision is invalid.".to_string())?;
    let mut routes = request.routes.iter().collect::<Vec<_>>();
    routes.sort_by(|left, right| left.host.cmp(&right.host));
    let mut transaction = Vec::with_capacity(routes.len() + 1);
    for route in routes {
        transaction.push(json!([
            "INSERT INTO ingress_routes (host, workload_id, namespace, port, revision, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (host) DO UPDATE SET workload_id = excluded.workload_id, namespace = excluded.namespace, port = excluded.port, revision = excluded.revision, updated_at = excluded.updated_at WHERE excluded.revision >= ingress_routes.revision",
            [
                route.host,
                route.workload_id,
                route.namespace,
                route.port,
                revision,
                now
            ]
        ]));
    }
    transaction.push(json!([
        "DELETE FROM ingress_routes WHERE revision < ?",
        [revision]
    ]));
    Ok(transaction)
}

/// Parses the NDJSON event stream of Corrosion's `POST /v1/queries` into rows.
/// A stream without its end-of-query event is incomplete and fails, so a cut
/// connection never looks like an empty table.
pub(crate) fn parse_query_events(output: &[u8]) -> Result<Vec<Vec<Value>>, String> {
    let mut rows = Vec::new();
    let mut finished = false;
    for value in serde_json::Deserializer::from_slice(output).into_iter::<Value>() {
        let value = value.map_err(|_| "Corrosion returned invalid query data.".to_string())?;
        if let Some(error) = value.get("error") {
            let message = error
                .as_str()
                .unwrap_or("unknown error")
                .chars()
                .take(500)
                .collect::<String>();
            return Err(format!("Corrosion could not run the query: {message}"));
        }
        if let Some(row) = value.get("row") {
            let cells = row
                .get(1)
                .and_then(Value::as_array)
                .ok_or("Corrosion returned an invalid query row.")?;
            rows.push(cells.clone());
        } else if value.get("eoq").is_some() {
            finished = true;
        }
    }
    if !finished {
        return Err("Corrosion returned an incomplete query result.".into());
    }
    Ok(rows)
}

pub(crate) fn parse_stored_routes(rows: &[Vec<Value>]) -> Result<StoredRoutes, String> {
    let mut stored = StoredRoutes::default();
    for row in rows {
        let text = |index: usize| row.get(index).and_then(Value::as_str).map(str::to_string);
        let (Some(host), Some(workload_id), Some(namespace)) = (text(0), text(1), text(2)) else {
            return Err("Corrosion returned an invalid ingress route.".into());
        };
        let port = row
            .get(3)
            .and_then(Value::as_u64)
            .and_then(|port| u32::try_from(port).ok())
            .ok_or("Corrosion returned an invalid ingress route.")?;
        let revision = row
            .get(4)
            .and_then(Value::as_u64)
            .ok_or("Corrosion returned an invalid ingress route.")?;
        stored.revision = Some(
            stored
                .revision
                .map_or(revision, |known| known.max(revision)),
        );
        stored.routes.push(StoredRoute {
            host,
            workload_id,
            namespace,
            port,
        });
    }
    Ok(stored)
}

pub(crate) fn parse_stored_names(
    rows: &[Vec<Value>],
    stored: &mut StoredRoutes,
) -> Result<(), String> {
    for row in rows {
        let text = |index: usize| row.get(index).and_then(Value::as_str).map(str::to_string);
        let (Some(namespace), Some(name), Some(workload_id)) = (text(0), text(1), text(2)) else {
            return Err("Corrosion returned an invalid internal name.".into());
        };
        let revision = row
            .get(3)
            .and_then(Value::as_u64)
            .ok_or("Corrosion returned an invalid internal name.")?;
        stored.names_revision = Some(
            stored
                .names_revision
                .map_or(revision, |known| known.max(revision)),
        );
        stored.names.push(StoredName {
            namespace,
            name,
            workload_id,
        });
    }
    Ok(())
}

/// A live workload endpoint that may receive ingress traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveEndpoint {
    pub(crate) workload_id: String,
    pub(crate) namespace: String,
    pub(crate) owner_node_ip: String,
    pub(crate) container_ip: Ipv4Addr,
}

/// Keeps only well-formed rows whose address can be a workload. Loopback and
/// other host-local addresses are never proxied to.
pub(crate) fn parse_live_endpoints(rows: &[Vec<Value>]) -> Vec<LiveEndpoint> {
    rows.iter()
        .filter_map(|row| {
            let text = |index: usize| row.get(index).and_then(Value::as_str);
            let workload_id = text(0).filter(|value| valid_discovery_label(value))?;
            let namespace =
                text(1).filter(|value| valid_discovery_label(value) && *value != NODE_NAMESPACE)?;
            let owner_node_ip = text(2)?.parse::<Ipv4Addr>().ok()?;
            let container_ip = text(3)?.parse::<Ipv4Addr>().ok().filter(|address| {
                !(address.is_unspecified()
                    || address.is_loopback()
                    || address.is_link_local()
                    || address.is_multicast()
                    || address.is_broadcast())
            })?;
            Some(LiveEndpoint {
                workload_id: workload_id.into(),
                namespace: namespace.into(),
                owner_node_ip: owner_node_ip.to_string(),
                container_ip,
            })
        })
        .collect()
}

fn static_response(status: u16, body: &str) -> Value {
    json!({
        "handler": "static_response",
        "status_code": status,
        "headers": {"Content-Type": ["text/plain; charset=utf-8"]},
        "body": body,
    })
}

/// Renders the complete Caddy JSON configuration. The output is deterministic:
/// routes are sorted by host, and upstreams list this Node's endpoints first,
/// then the others, each by address.
///
/// `reverse_proxy` passes the client's Host header through unchanged.
pub(crate) fn render_caddy_config(
    routes: &[StoredRoute],
    endpoints: &[LiveEndpoint],
    local_node_ip: &str,
) -> Vec<u8> {
    let mut upstreams = BTreeMap::<(&str, &str), Vec<(bool, Ipv4Addr)>>::new();
    for endpoint in endpoints {
        upstreams
            .entry((endpoint.namespace.as_str(), endpoint.workload_id.as_str()))
            .or_default()
            .push((
                endpoint.owner_node_ip != local_node_ip,
                endpoint.container_ip,
            ));
    }
    for addresses in upstreams.values_mut() {
        addresses.sort();
        addresses.dedup_by(|right, left| right.1 == left.1);
    }

    let mut sorted = routes.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.host.cmp(&right.host));
    sorted.dedup_by(|right, left| right.host == left.host);
    let mut rendered = sorted
        .into_iter()
        .map(|route| {
            let dials = upstreams
                .get(&(route.namespace.as_str(), route.workload_id.as_str()))
                .map(|addresses| {
                    addresses
                        .iter()
                        .map(|(_, address)| json!({"dial": format!("{address}:{}", route.port)}))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let handler = if dials.is_empty() {
                static_response(502, NO_UPSTREAM_BODY)
            } else {
                json!({
                    "handler": "reverse_proxy",
                    "upstreams": dials,
                    "load_balancing": {
                        "selection_policy": {"policy": "first"},
                        "try_duration": "5s",
                        "try_interval": "250ms",
                    },
                    "health_checks": {
                        "passive": {"fail_duration": "30s", "max_fails": 1},
                    },
                })
            };
            json!({
                "match": [{"host": [route.host]}],
                "handle": [handler],
                "terminal": true,
            })
        })
        .collect::<Vec<_>>();
    rendered.push(json!({
        "handle": [static_response(404, NOT_FOUND_BODY)],
        "terminal": true,
    }));

    let config = json!({
        "admin": {
            "listen": format!("unix/{ADMIN_SOCKET}"),
            "config": {"persist": false},
        },
        "apps": {
            "http": {
                "servers": {
                    "ingress": {
                        "listen": [":80"],
                        "automatic_https": {"disable": true},
                        "routes": rendered,
                    },
                },
            },
        },
    });
    let mut output = serde_json::to_vec_pretty(&config).unwrap_or_default();
    output.push(b'\n');
    output
}

/// The configuration Caddy starts with before the first render: no routes.
pub(crate) fn bootstrap_config() -> Vec<u8> {
    render_caddy_config(&[], &[], "")
}

pub(crate) fn ingress_unit() -> String {
    format!(
        "[Unit]\nDescription=Coolify HTTP ingress\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n[Service]\nExecStart={CADDY_BINARY} run --config /{INGRESS_CONFIG_FILE}\nUser={INGRESS_USER}\nGroup={INGRESS_USER}\nEnvironment=HOME={INGRESS_HOME} XDG_CONFIG_HOME={INGRESS_HOME} XDG_DATA_HOME={INGRESS_HOME}\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nStateDirectory=coolify-ingress\nRuntimeDirectory=coolify-ingress\nReadWritePaths={INGRESS_HOME} /run/coolify-ingress\nLimitNOFILE=1048576\nRestart=always\nRestartSec=2s\n[Install]\nWantedBy=multi-user.target\n"
    )
}

fn caddy_download(architecture: &str) -> Result<(String, &'static str), String> {
    let (target, checksum) = match architecture.trim() {
        "x86_64" => ("amd64", CADDY_SHA512_LINUX_AMD64),
        "aarch64" => ("arm64", CADDY_SHA512_LINUX_ARM64),
        _ => return Err("The host architecture is not supported by Caddy.".into()),
    };
    let version = CADDY_VERSION.trim_start_matches('v');
    Ok((
        format!(
            "https://github.com/caddyserver/caddy/releases/download/{CADDY_VERSION}/caddy_{version}_linux_{target}.tar.gz"
        ),
        checksum,
    ))
}

pub(crate) fn sha512_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|_| "The Caddy archive could not be read.")?;
    let mut hasher = Sha512::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "The Caddy archive could not be read.")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Installs the pinned Caddy release after verifying its pinned SHA-512.
/// Returns whether the binary changed.
fn install_caddy() -> Result<bool, String> {
    if fs::read_to_string(CADDY_VERSION_FILE)
        .ok()
        .is_some_and(|installed| installed.trim() == CADDY_VERSION)
        && Path::new(CADDY_BINARY).exists()
    {
        return Ok(false);
    }
    let architecture = Command::new("uname")
        .arg("-m")
        .output()
        .map_err(|_| "The host architecture could not be detected.")?;
    let (url, checksum) = caddy_download(&String::from_utf8_lossy(&architecture.stdout))?;
    let directory = PathBuf::from(format!(
        "/var/lib/coolify/downloads/caddy-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory)
        .map_err(|_| "The Caddy download directory could not be created.")?;
    let result = (|| {
        let archive = directory.join("caddy.tar.gz");
        run_command(
            Command::new("curl")
                .args(["-fsSL", "--retry", "3", "--max-time", "120", "-o"])
                .arg(&archive)
                .arg(&url),
            "Caddy could not be downloaded.",
        )?;
        if sha512_file(&archive)? != checksum {
            return Err("The Caddy download does not match its pinned SHA-512 checksum.".into());
        }
        run_command(
            Command::new("tar")
                .arg("-xzf")
                .arg(&archive)
                .arg("-C")
                .arg(&directory)
                .arg("caddy"),
            "Caddy could not be extracted.",
        )?;
        run_command(
            Command::new("install")
                .args(["-m", "0755"])
                .arg(directory.join("caddy"))
                .arg(CADDY_BINARY),
            "Caddy could not be installed.",
        )?;
        atomic_write(
            Path::new(CADDY_VERSION_FILE),
            format!("{CADDY_VERSION}\n").as_bytes(),
            0o644,
        )
    })();
    let _ = fs::remove_dir_all(&directory);
    result.map(|()| true)
}

fn ensure_ingress_user() -> Result<(), String> {
    if Command::new("id")
        .args(["-u", INGRESS_USER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return Ok(());
    }
    run_command(
        Command::new("useradd").args([
            "--system",
            "--home",
            INGRESS_HOME,
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            INGRESS_USER,
        ]),
        "The Coolify ingress service user could not be created.",
    )
}

/// Whether Caddy runs and answers on its admin socket. `systemctl is-active`
/// alone also reports a crash-looping unit as active between restarts.
fn caddy_answers() -> bool {
    Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--output",
            "/dev/null",
            "--max-time",
            "2",
            "--unix-socket",
            ADMIN_SOCKET,
            "http://localhost/config/",
        ])
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Waits up to ten seconds for Caddy to answer, so a unit that cannot start
/// fails the command instead of being reported as active.
fn wait_until_caddy_answers() -> Result<(), String> {
    for _ in 0..20 {
        if caddy_answers() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "The Coolify ingress did not start. Check `journalctl -u {INGRESS_UNIT}` on the Node."
    ))
}

/// Creates the configuration directory readable by the Caddy service user.
fn ensure_config_dir(root: &Path) -> Result<(), String> {
    let directory = root.join(INGRESS_CONFIG_DIR);
    fs::create_dir_all(&directory)
        .and_then(|()| {
            fs::set_permissions(
                &directory,
                <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
            )
        })
        .map_err(|_| "The ingress configuration directory could not be created.".to_string())
}

fn read_stored_routes(owner_node_ip: &str) -> Result<StoredRoutes, String> {
    let query = |sql: &str| {
        crate::discovery::corrosion_api(
            owner_node_ip,
            "queries",
            &serde_json::to_vec(sql).unwrap_or_default(),
        )
        .and_then(|output| parse_query_events(&output))
    };
    let mut stored = parse_stored_routes(&query(routes_query_sql())?)?;
    parse_stored_names(&query(names_query_sql())?, &mut stored)?;
    Ok(stored)
}

/// Applies `ingress.reconcile.v1`.
pub(crate) fn reconcile(
    root: &Path,
    request: &IngressReconcileRequest,
) -> Result<IngressReconcileResult, String> {
    validate_request(request)?;
    let _ingress = ingress_lock();
    let identity = crate::discovery::read_identity(root)?;
    if request.enabled && identity.is_none() {
        return Err("This Node is not in a cluster, so it cannot serve ingress.".into());
    }
    let host = root == Path::new("/");
    // Every cluster Node writes the tables, so names resolve without an ingress Node.
    if let Some(identity) = &identity
        && request.revision > 0
    {
        crate::network::ensure_corrosion_schema(root)?;
        if host {
            let stored = read_stored_routes(&identity.owner_node_ip)?;
            if let RouteWrite::Write(transaction) =
                plan_route_write(&stored, request, crate::network::unix_seconds())?
            {
                crate::discovery::post_transaction(&identity.owner_node_ip, &transaction)?;
            }
        }
    }
    if !request.enabled {
        remove(root)?;
        return Ok(IngressReconcileResult {
            enabled: false,
            caddy_version: request.caddy_version.clone(),
            active: false,
            revision: request.revision,
            route_count: request.routes.len() as u64,
            name_count: request.names.len() as u64,
        });
    }

    let binary_changed = if host { install_caddy()? } else { false };
    if host {
        ensure_ingress_user()?;
    }
    let unit_changed = write_if_changed(
        &root.join(INGRESS_UNIT_FILE),
        ingress_unit().as_bytes(),
        0o644,
    )?;
    ensure_config_dir(root)?;
    let config_path = root.join(INGRESS_CONFIG_FILE);
    if !config_path.exists() {
        atomic_write(&config_path, &bootstrap_config(), 0o644)?;
    }
    if host {
        if unit_changed {
            run_command(
                Command::new("systemctl").arg("daemon-reload"),
                "Systemd could not reload the ingress unit.",
            )?;
        }
        run_command(
            Command::new("systemctl").args(["enable", "--now", INGRESS_UNIT]),
            "The Coolify ingress could not start.",
        )?;
        if unit_changed || binary_changed {
            run_command(
                Command::new("systemctl").args(["restart", INGRESS_UNIT]),
                "The Coolify ingress could not restart.",
            )?;
        }
        wait_until_caddy_answers()?;
    }
    atomic_write(
        &state_file(root),
        format!("enabled {CADDY_VERSION}\n").as_bytes(),
        0o600,
    )?;

    Ok(IngressReconcileResult {
        enabled: true,
        caddy_version: CADDY_VERSION.into(),
        active: host,
        revision: request.revision,
        route_count: request.routes.len() as u64,
        name_count: request.names.len() as u64,
    })
}

/// Stops and removes the ingress unit, configuration and state. Corrosion
/// routes stay: other Nodes still serve them. The caller holds `ingress_lock`.
pub(crate) fn remove(root: &Path) -> Result<(), String> {
    let host = root == Path::new("/");
    if host {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", INGRESS_UNIT])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let config_path = root.join(INGRESS_CONFIG_FILE);
    let mut staged = config_path.as_os_str().to_os_string();
    staged.push(".tmp");
    for path in [
        root.join(INGRESS_UNIT_FILE),
        config_path,
        PathBuf::from(staged),
        state_file(root),
    ] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("A managed ingress file could not be removed.".into()),
        }
    }
    let _ = fs::remove_dir(root.join(INGRESS_CONFIG_DIR));
    if host {
        run_command(
            Command::new("systemctl").arg("daemon-reload"),
            "Systemd could not reload after the ingress was removed.",
        )?;
        let _ = Command::new("systemctl")
            .args(["reset-failed", INGRESS_UNIT])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    Ok(())
}

/// What a render did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RenderOutcome {
    Skipped(&'static str),
    /// The configuration is current; `loaded` tells whether Caddy runs it.
    Rendered {
        written: bool,
        loaded: bool,
    },
}

/// How Caddy took a configuration.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LoadOutcome {
    Loaded,
    /// Caddy is not running; systemd starts it with the file.
    NotRunning,
}

/// Renderer memory between passes: the hash of the configuration Caddy last
/// accepted from this Sentinel.
#[derive(Debug, Default)]
pub(crate) struct RenderState {
    loaded: Option<String>,
}

/// Writes `config` only when it changed, and loads it into Caddy until Caddy
/// accepted it once. A failed load keeps the file and is retried next pass.
pub(crate) fn apply_config(
    root: &Path,
    config: &[u8],
    state: &mut RenderState,
    load: impl FnOnce(&[u8]) -> Result<LoadOutcome, String>,
) -> Result<RenderOutcome, String> {
    let written = write_if_changed(&root.join(INGRESS_CONFIG_FILE), config, 0o644)?;
    let digest = crate::network::hash(config);
    if !written && state.loaded.as_deref() == Some(digest.as_str()) {
        return Ok(RenderOutcome::Rendered {
            written,
            loaded: true,
        });
    }
    state.loaded = None;
    match load(config)? {
        LoadOutcome::Loaded => {
            state.loaded = Some(digest);
            Ok(RenderOutcome::Rendered {
                written,
                loaded: true,
            })
        }
        LoadOutcome::NotRunning => Ok(RenderOutcome::Rendered {
            written,
            loaded: false,
        }),
    }
}

/// Loads a configuration through Caddy's admin socket.
fn load_into_caddy(config: &[u8]) -> Result<LoadOutcome, String> {
    if !Path::new(ADMIN_SOCKET).exists() {
        return Ok(LoadOutcome::NotRunning);
    }
    let mut child = Command::new("curl")
        .args([
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--unix-socket",
            ADMIN_SOCKET,
            "--max-time",
            "30",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "http://localhost/load",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "curl is unavailable.".to_string())?;
    let written = child
        .stdin
        .take()
        .ok_or("curl input is unavailable.")
        .and_then(|mut stdin| {
            std::io::Write::write_all(&mut stdin, config)
                .map_err(|_| "The ingress configuration could not be sent.")
        });
    let output = child
        .wait_with_output()
        .map_err(|_| "Caddy could not load the ingress configuration.".to_string())?;
    if output.status.success() {
        written?;
        return Ok(LoadOutcome::Loaded);
    }
    // curl exit 7: the socket refused the connection, so Caddy is stopping.
    if output.status.code() == Some(7) {
        return Ok(LoadOutcome::NotRunning);
    }
    let message = [output.stdout.as_slice(), output.stderr.as_slice()]
        .iter()
        .map(|part| String::from_utf8_lossy(part).trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect::<String>();
    Err(if message.is_empty() {
        "Caddy could not load the ingress configuration.".into()
    } else {
        format!("Caddy could not load the ingress configuration: {message}")
    })
}

/// Renders the Caddy configuration from the local Corrosion. A Corrosion read
/// error keeps the last configuration; it never renders an empty one.
pub(crate) fn render_once(root: &Path, state: &mut RenderState) -> Result<RenderOutcome, String> {
    let _ingress = ingress_lock();
    if !enabled(root) {
        state.loaded = None;
        return Ok(RenderOutcome::Skipped(
            "ingress is not enabled on this Node",
        ));
    }
    let Some(identity) = crate::discovery::read_identity(root)? else {
        return Ok(RenderOutcome::Skipped("this Node is not in a cluster"));
    };
    if root != Path::new("/") {
        return Ok(RenderOutcome::Skipped(
            "ingress rendering only runs against the host root",
        ));
    }
    let owner = identity.owner_node_ip.as_str();
    let routes = read_stored_routes(owner)?;
    let endpoints = crate::discovery::corrosion_api(
        owner,
        "queries",
        &serde_json::to_vec(endpoints_query_sql()).unwrap_or_default(),
    )
    .and_then(|output| parse_query_events(&output))
    .map(|rows| parse_live_endpoints(&rows))?;
    let config = render_caddy_config(&routes.routes, &endpoints, owner);
    apply_config(root, &config, state, load_into_caddy)
}

/// Renders whenever `trigger` fires and every `RENDER_INTERVAL`, until shutdown.
pub(crate) async fn run(root: PathBuf, trigger: Arc<Notify>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(RENDER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state = RenderState::default();
    let mut last_error: Option<String> = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
            _ = trigger.notified() => {}
        }
        let render_root = root.clone();
        let (returned, result) = tokio::task::spawn_blocking(move || {
            let result = render_once(&render_root, &mut state);
            (state, result)
        })
        .await
        .unwrap_or_else(|_| {
            (
                RenderState::default(),
                Err("The ingress renderer task failed.".into()),
            )
        });
        state = returned;
        match result {
            Ok(RenderOutcome::Rendered { written, loaded }) => {
                if last_error.take().is_some() {
                    tracing::info!("ingress rendering recovered");
                }
                if written {
                    tracing::info!(loaded, "rendered a new ingress configuration");
                }
            }
            Ok(RenderOutcome::Skipped(reason)) => {
                last_error = None;
                tracing::trace!(reason, "skipped ingress rendering");
            }
            Err(error) => {
                if last_error.as_deref() == Some(error.as_str()) {
                    tracing::debug!(%error, "ingress rendering still failing");
                } else {
                    tracing::warn!(%error, "could not render the ingress configuration; the last configuration stays active");
                }
                last_error = Some(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, workload_id: &str, port: u32) -> IngressRoute {
        IngressRoute {
            host: host.into(),
            workload_id: workload_id.into(),
            namespace: "default".into(),
            port,
        }
    }

    fn request(revision: u64, routes: Vec<IngressRoute>) -> IngressReconcileRequest {
        IngressReconcileRequest {
            enabled: true,
            caddy_version: CADDY_VERSION.into(),
            revision,
            routes,
            names: vec![],
        }
    }

    fn name(name: &str, workload_id: &str) -> WorkloadName {
        WorkloadName {
            name: name.into(),
            workload_id: workload_id.into(),
            namespace: "default".into(),
        }
    }

    fn named(revision: u64, names: Vec<WorkloadName>) -> IngressReconcileRequest {
        IngressReconcileRequest {
            names,
            ..request(revision, vec![])
        }
    }

    fn endpoint(workload_id: &str, owner: &str, ip: &str) -> LiveEndpoint {
        LiveEndpoint {
            workload_id: workload_id.into(),
            namespace: "default".into(),
            owner_node_ip: owner.into(),
            container_ip: ip.parse().unwrap(),
        }
    }

    fn stored(host: &str, workload_id: &str, port: u32) -> StoredRoute {
        StoredRoute::from(&route(host, workload_id, port))
    }

    fn config(routes: &[StoredRoute], endpoints: &[LiveEndpoint]) -> Value {
        serde_json::from_slice(&render_caddy_config(routes, endpoints, "10.240.0.2")).unwrap()
    }

    #[test]
    fn hosts_must_be_lowercase_dotted_hostnames() {
        for host in [
            "app.example.com",
            "a.b",
            "xn--bcher-kva.example",
            "my-app.example.com",
            "1.example.com",
            &format!("{}.com", ["a".repeat(63)].join(".")),
        ] {
            assert!(valid_ingress_host(host), "{host} should be valid");
        }
        for host in [
            "",
            "localhost",
            "App.example.com",
            "*.example.com",
            "app.example.com.",
            ".example.com",
            "app..example.com",
            "-app.example.com",
            "app-.example.com",
            "app_1.example.com",
            "app.example.com:80",
            "10.0.0.1",
            "::1",
            "fe80::1",
            "1.2.3",
            "999.1.1.1",
            &format!("{}.com", "a".repeat(64)),
            &format!("{}.com", vec!["a".repeat(60); 5].join(".")),
        ] {
            assert!(!valid_ingress_host(host), "{host} should be invalid");
        }
        assert!(!valid_ingress_host(&"a.".repeat(127)));
        let longest = format!("{}.ab", vec!["a".repeat(62); 4].join("."));
        assert_eq!(longest.len(), 254);
        assert!(!valid_ingress_host(&longest));
        assert!(valid_ingress_host(&longest[1..]));
    }

    #[test]
    fn validation_rejects_bad_routes_versions_and_sizes() {
        assert!(validate_request(&request(1, vec![route("app.example.com", "web", 3000)])).is_ok());
        assert!(validate_request(&request(1, vec![])).is_ok());

        let invalid = [
            ("revision zero", request(0, vec![])),
            ("revision too large", request(u64::MAX, vec![])),
            (
                "IP host",
                request(1, vec![route("192.168.1.10", "web", 3000)]),
            ),
            (
                "duplicate hosts",
                request(
                    1,
                    vec![
                        route("app.example.com", "web", 3000),
                        route("app.example.com", "api", 4000),
                    ],
                ),
            ),
            (
                "workload label",
                request(1, vec![route("app.example.com", "web.app", 3000)]),
            ),
            (
                "empty workload",
                request(1, vec![route("app.example.com", "", 3000)]),
            ),
            (
                "port zero",
                request(1, vec![route("app.example.com", "web", 0)]),
            ),
            (
                "port too large",
                request(1, vec![route("app.example.com", "web", 65_536)]),
            ),
        ];
        for (name, request) in invalid {
            assert!(validate_request(&request).is_err(), "{name} must fail");
        }

        let mut bad_namespace = request(1, vec![route("app.example.com", "web", 3000)]);
        bad_namespace.routes[0].namespace = "Default!".into();
        assert!(validate_request(&bad_namespace).is_err());
        // Node endpoints are WireGuard addresses and must never be proxied to.
        bad_namespace.routes[0].namespace = "nodes".into();
        assert!(validate_request(&bad_namespace).is_err());

        let too_many = (0..=MAX_ROUTES)
            .map(|index| route(&format!("app-{index}.example.com"), "web", 80))
            .collect::<Vec<_>>();
        assert!(validate_request(&request(1, too_many[..MAX_ROUTES].to_vec())).is_ok());
        assert!(validate_request(&request(1, too_many)).is_err());

        let mut wrong_version = request(1, vec![]);
        wrong_version.caddy_version = "v2.10.0".into();
        let message = validate_request(&wrong_version).unwrap_err();
        assert!(message.contains(CADDY_VERSION));
        wrong_version.caddy_version = String::new();
        assert!(validate_request(&wrong_version).is_err());
        // Disabling accepts the pinned or an empty version, with any revision.
        wrong_version.enabled = false;
        wrong_version.revision = 0;
        assert!(validate_request(&wrong_version).is_ok());
        wrong_version.caddy_version = "v2.10.0".into();
        assert!(validate_request(&wrong_version).is_err());
    }

    #[test]
    fn transaction_upserts_sorted_routes_then_deletes_older_revisions() {
        let request = request(
            7,
            vec![
                route("b.example.com", "api", 4000),
                route("a.example.com", "web", 3000),
            ],
        );

        let transaction = route_transaction(&request, 1_700_000_000).unwrap();

        assert_eq!(transaction.len(), 3);
        for statement in &transaction[..2] {
            assert_eq!(
                statement[0],
                "INSERT INTO ingress_routes (host, workload_id, namespace, port, revision, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (host) DO UPDATE SET workload_id = excluded.workload_id, namespace = excluded.namespace, port = excluded.port, revision = excluded.revision, updated_at = excluded.updated_at WHERE excluded.revision >= ingress_routes.revision"
            );
        }
        assert_eq!(
            transaction[0][1],
            json!(["a.example.com", "web", "default", 3000, 7, 1_700_000_000])
        );
        assert_eq!(
            transaction[1][1],
            json!(["b.example.com", "api", "default", 4000, 7, 1_700_000_000])
        );
        assert_eq!(
            transaction[2],
            json!(["DELETE FROM ingress_routes WHERE revision < ?", [7]])
        );

        // An empty route set clears every older route.
        assert_eq!(
            route_transaction(&self::request(8, vec![]), 1).unwrap(),
            vec![json!([
                "DELETE FROM ingress_routes WHERE revision < ?",
                [8]
            ])]
        );
    }

    #[test]
    fn route_writes_reject_stale_revisions_and_are_idempotent() {
        let routes = vec![
            route("a.example.com", "web", 3000),
            route("b.example.com", "api", 4000),
        ];
        let current = StoredRoutes {
            revision: Some(5),
            routes: vec![
                stored("b.example.com", "api", 4000),
                stored("a.example.com", "web", 3000),
            ],
            names_revision: Some(5),
            names: vec![],
        };

        // Nothing stored yet: write.
        assert!(matches!(
            plan_route_write(&StoredRoutes::default(), &request(1, routes.clone()), 10).unwrap(),
            RouteWrite::Write(_)
        ));
        // A newer revision: write.
        assert!(matches!(
            plan_route_write(&current, &request(6, vec![]), 10).unwrap(),
            RouteWrite::Write(_)
        ));
        // The same revision and routes, in any order: no write.
        let mut reversed = routes.clone();
        reversed.reverse();
        assert_eq!(
            plan_route_write(&current, &request(5, reversed), 10).unwrap(),
            RouteWrite::Unchanged
        );
        // The same revision with other routes conflicts.
        assert!(
            plan_route_write(
                &current,
                &request(5, vec![route("a.example.com", "web", 3001)]),
                10
            )
            .unwrap_err()
            .contains("different ingress routes")
        );
        // An older revision is a stale writer.
        let stale = plan_route_write(&current, &request(4, routes), 10).unwrap_err();
        assert!(stale.contains("stale"), "{stale}");
    }

    #[test]
    fn names_are_validated_like_routes() {
        assert!(validate_request(&named(1, vec![name("api", "uuid-api")])).is_ok());
        // Revision 0 may only disable Caddy, without tables.
        let mut disable = named(0, vec![]);
        disable.enabled = false;
        assert!(validate_request(&disable).is_ok());
        disable.names = vec![name("api", "uuid-api")];
        assert!(validate_request(&disable).is_err());

        let invalid = [
            ("name label", vec![name("api.v1", "uuid-api")]),
            ("empty name", vec![name("", "uuid-api")]),
            ("workload label", vec![name("api", "uuid_api")]),
            (
                "duplicate names",
                vec![name("api", "uuid-api"), name("api", "uuid-web")],
            ),
        ];
        for (label, names) in invalid {
            assert!(
                validate_request(&named(1, names)).is_err(),
                "{label} must fail"
            );
        }
        // Node names are endpoint rows of their own, never mapped names.
        let mut node = named(1, vec![name("worker-1", "uuid-api")]);
        node.names[0].namespace = "nodes".into();
        assert!(validate_request(&node).is_err());
        // Two names may point at one workload.
        assert!(
            validate_request(&named(
                1,
                vec![name("api", "uuid-api"), name("backend", "uuid-api")]
            ))
            .is_ok()
        );

        let too_many = (0..=MAX_NAMES)
            .map(|index| name(&format!("app-{index}"), "uuid-api"))
            .collect::<Vec<_>>();
        assert!(validate_request(&named(1, too_many[..MAX_NAMES].to_vec())).is_ok());
        assert!(validate_request(&named(1, too_many)).is_err());
    }

    #[test]
    fn name_writes_are_revisioned_independently_of_routes() {
        let request = IngressReconcileRequest {
            names: vec![name("web", "uuid-web"), name("api", "uuid-api")],
            ..self::request(5, vec![route("a.example.com", "uuid-web", 3000)])
        };
        let routes_only = StoredRoutes {
            revision: Some(5),
            routes: vec![stored("a.example.com", "uuid-web", 3000)],
            ..StoredRoutes::default()
        };

        // The routes are current, so only the names are written: sorted, then
        // older revisions are deleted.
        let RouteWrite::Write(transaction) = plan_route_write(&routes_only, &request, 10).unwrap()
        else {
            panic!("the names must be written");
        };
        assert_eq!(transaction.len(), 3);
        assert_eq!(
            transaction[0],
            json!([
                "INSERT INTO workload_names (namespace, name, workload_id, revision, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (namespace, name) DO UPDATE SET workload_id = excluded.workload_id, revision = excluded.revision, updated_at = excluded.updated_at WHERE excluded.revision >= workload_names.revision",
                ["default", "api", "uuid-api", 5, 10]
            ])
        );
        assert_eq!(
            transaction[1][1],
            json!(["default", "web", "uuid-web", 5, 10])
        );
        assert_eq!(
            transaction[2],
            json!(["DELETE FROM workload_names WHERE revision < ?", [5]])
        );

        // Both tables current: nothing to write.
        let current = StoredRoutes {
            names_revision: Some(5),
            names: request.names.iter().rev().map(StoredName::from).collect(),
            ..routes_only.clone()
        };
        assert_eq!(
            plan_route_write(&current, &request, 10).unwrap(),
            RouteWrite::Unchanged
        );
        // A rename at the same revision conflicts; an older revision is stale.
        let mut renamed = request.clone();
        renamed.names[0].name = "frontend".into();
        assert!(
            plan_route_write(&current, &renamed, 10)
                .unwrap_err()
                .contains("different internal names")
        );
        let stale = StoredRoutes {
            names_revision: Some(6),
            ..current
        };
        assert!(
            plan_route_write(&stale, &request, 10)
                .unwrap_err()
                .contains("internal names are stale")
        );

        let mut parsed = StoredRoutes::default();
        parse_stored_names(
            &[
                vec![json!("default"), json!("api"), json!("uuid-api"), json!(4)],
                vec![json!("default"), json!("web"), json!("uuid-web"), json!(4)],
            ],
            &mut parsed,
        )
        .unwrap();
        assert_eq!(parsed.names_revision, Some(4));
        assert_eq!(parsed.names[1], StoredName::from(&name("web", "uuid-web")));
        assert!(parse_stored_names(&[vec![json!("default")]], &mut parsed).is_err());
    }

    #[test]
    fn query_events_parse_rows_and_reject_errors_or_truncation() {
        let output = br#"{"columns":["host","workload_id","namespace","port","revision"]}
{"row":[1,["a.example.com","web","default",3000,7]]}
{"row":[2,["b.example.com","api","default",4000,7]]}
{"eoq":{"time":0.001}}
"#;
        let rows = parse_query_events(output).unwrap();
        let parsed = parse_stored_routes(&rows).unwrap();
        assert_eq!(parsed.revision, Some(7));
        assert_eq!(
            parsed.routes,
            vec![
                stored("a.example.com", "web", 3000),
                stored("b.example.com", "api", 4000)
            ]
        );

        let empty = parse_query_events(b"{\"columns\":[]}\n{\"eoq\":{\"time\":0.0}}\n").unwrap();
        assert_eq!(
            parse_stored_routes(&empty).unwrap(),
            StoredRoutes::default()
        );

        assert!(parse_query_events(b"{\"columns\":[]}\n{\"row\":[1,[\"a\"]]}\n").is_err());
        assert!(
            parse_query_events(b"{\"error\":\"no such table: ingress_routes\"}\n")
                .unwrap_err()
                .contains("no such table")
        );
        assert!(parse_query_events(b"not json").is_err());
        assert!(parse_stored_routes(&[vec![json!("a.example.com"), json!(1)]]).is_err());
    }

    #[test]
    fn live_endpoints_skip_node_rows_and_host_local_addresses() {
        let rows = vec![
            vec![
                json!("web"),
                json!("default"),
                json!("10.240.0.2"),
                json!("100.64.0.5"),
            ],
            vec![
                json!("worker-1"),
                json!("nodes"),
                json!("10.240.0.2"),
                json!("10.240.0.2"),
            ],
            vec![
                json!("web"),
                json!("default"),
                json!("10.240.0.3"),
                json!("127.0.0.1"),
            ],
            vec![
                json!("web"),
                json!("default"),
                json!("10.240.0.3"),
                json!("169.254.1.1"),
            ],
            vec![
                json!("web"),
                json!("default"),
                json!("10.240.0.3"),
                json!("not-an-ip"),
            ],
            vec![
                json!("web.bad"),
                json!("default"),
                json!("10.240.0.3"),
                json!("100.64.1.5"),
            ],
            vec![json!("web"), json!("default")],
        ];

        assert_eq!(
            parse_live_endpoints(&rows),
            vec![endpoint("web", "10.240.0.2", "100.64.0.5")]
        );
    }

    #[test]
    fn endpoint_query_selects_only_live_running_workloads() {
        let sql = endpoints_query_sql();
        assert!(sql.contains("state = 'running'"));
        assert!(sql.contains("health NOT IN ('unhealthy', 'starting')"));
        assert!(sql.contains("expires_at > unixepoch()"));
        assert!(sql.contains("namespace != 'nodes'"));
        assert!(
            routes_query_sql()
                .contains("WHERE revision = (SELECT MAX(revision) FROM ingress_routes)")
        );
    }

    #[test]
    fn renders_local_upstreams_first_with_passive_health_and_first_policy() {
        let rendered = config(
            &[stored("app.example.com", "web", 3000)],
            &[
                endpoint("web", "10.240.0.4", "100.64.2.9"),
                endpoint("web", "10.240.0.3", "100.64.1.7"),
                endpoint("web", "10.240.0.2", "100.64.0.8"),
                endpoint("web", "10.240.0.2", "100.64.0.10"),
                endpoint("web", "10.240.0.3", "100.64.1.7"),
                endpoint("api", "10.240.0.2", "100.64.0.11"),
            ],
        );

        let server = &rendered["apps"]["http"]["servers"]["ingress"];
        assert_eq!(server["listen"], json!([":80"]));
        assert_eq!(server["automatic_https"], json!({"disable": true}));
        let routes = server["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["match"], json!([{"host": ["app.example.com"]}]));
        assert_eq!(routes[0]["terminal"], json!(true));
        let proxy = &routes[0]["handle"][0];
        assert_eq!(proxy["handler"], "reverse_proxy");
        assert_eq!(
            proxy["upstreams"],
            json!([
                {"dial": "100.64.0.8:3000"},
                {"dial": "100.64.0.10:3000"},
                {"dial": "100.64.1.7:3000"},
                {"dial": "100.64.2.9:3000"},
            ])
        );
        assert_eq!(
            proxy["load_balancing"],
            json!({"selection_policy": {"policy": "first"}, "try_duration": "5s", "try_interval": "250ms"})
        );
        assert_eq!(
            proxy["health_checks"],
            json!({"passive": {"fail_duration": "30s", "max_fails": 1}})
        );
        // The client Host header is passed through: no header rewrite.
        assert!(proxy.get("headers").is_none());
        assert!(
            !String::from_utf8(render_caddy_config(&[], &[], ""))
                .unwrap()
                .contains("Host")
        );
    }

    #[test]
    fn a_route_without_upstreams_returns_502_and_unknown_hosts_404() {
        let rendered = config(
            &[stored("app.example.com", "web", 3000)],
            &[endpoint("api", "10.240.0.2", "100.64.0.5")],
        );

        let routes = rendered["apps"]["http"]["servers"]["ingress"]["routes"]
            .as_array()
            .unwrap();
        assert_eq!(
            routes[0]["handle"],
            json!([{
                "handler": "static_response",
                "status_code": 502,
                "headers": {"Content-Type": ["text/plain; charset=utf-8"]},
                "body": "No healthy upstream\n",
            }])
        );
        let fallback = routes.last().unwrap();
        assert!(fallback.get("match").is_none());
        assert_eq!(fallback["handle"][0]["status_code"], 404);
        assert_eq!(fallback["terminal"], json!(true));
    }

    #[test]
    fn rendering_is_deterministic_and_keeps_the_admin_socket() {
        let routes = [
            stored("b.example.com", "api", 4000),
            stored("a.example.com", "web", 3000),
        ];
        let endpoints = [
            endpoint("web", "10.240.0.3", "100.64.1.7"),
            endpoint("api", "10.240.0.2", "100.64.0.5"),
            endpoint("web", "10.240.0.2", "100.64.0.6"),
        ];
        let mut shuffled_routes = routes.clone();
        shuffled_routes.reverse();
        let mut shuffled_endpoints = endpoints.clone();
        shuffled_endpoints.rotate_left(1);

        let first = render_caddy_config(&routes, &endpoints, "10.240.0.2");
        assert_eq!(
            first,
            render_caddy_config(&shuffled_routes, &shuffled_endpoints, "10.240.0.2")
        );
        let rendered: Value = serde_json::from_slice(&first).unwrap();
        let hosts = rendered["apps"]["http"]["servers"]["ingress"]["routes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|route| route["match"][0]["host"][0].as_str())
            .collect::<Vec<_>>();
        assert_eq!(hosts, vec!["a.example.com", "b.example.com"]);
        assert_eq!(
            rendered["admin"],
            json!({"listen": "unix//run/coolify-ingress/admin.sock", "config": {"persist": false}})
        );

        let bootstrap: Value = serde_json::from_slice(&bootstrap_config()).unwrap();
        assert_eq!(bootstrap["admin"], rendered["admin"]);
        assert_eq!(
            bootstrap["apps"]["http"]["servers"]["ingress"]["routes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn config_is_written_only_when_changed_and_loaded_until_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(INGRESS_CONFIG_FILE);
        let mut state = RenderState::default();
        let first = render_caddy_config(&[stored("a.example.com", "web", 80)], &[], "");

        // Caddy is down: the file is written and the load stays pending.
        assert_eq!(
            apply_config(temp.path(), &first, &mut state, |_| Ok(
                LoadOutcome::NotRunning
            ))
            .unwrap(),
            RenderOutcome::Rendered {
                written: true,
                loaded: false
            }
        );
        assert_eq!(fs::read(&path).unwrap(), first);
        let modified = fs::metadata(&path).unwrap().modified().unwrap();

        // Caddy rejects it: the file stays, the error surfaces.
        assert!(apply_config(temp.path(), &first, &mut state, |_| Err("rejected".into())).is_err());
        // Caddy is back: the same file is loaded once, without a rewrite.
        assert_eq!(
            apply_config(temp.path(), &first, &mut state, |config| {
                assert_eq!(config, first.as_slice());
                Ok(LoadOutcome::Loaded)
            })
            .unwrap(),
            RenderOutcome::Rendered {
                written: false,
                loaded: true
            }
        );
        assert_eq!(
            apply_config(temp.path(), &first, &mut state, |_| panic!(
                "no reload expected"
            ))
            .unwrap(),
            RenderOutcome::Rendered {
                written: false,
                loaded: true
            }
        );
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);

        // A changed configuration is written and loaded.
        let second = render_caddy_config(&[stored("b.example.com", "web", 80)], &[], "");
        assert_eq!(
            apply_config(temp.path(), &second, &mut state, |_| Ok(
                LoadOutcome::Loaded
            ))
            .unwrap(),
            RenderOutcome::Rendered {
                written: true,
                loaded: true
            }
        );
        assert_eq!(fs::read(&path).unwrap(), second);
    }

    #[test]
    fn rendering_is_skipped_until_ingress_is_enabled() {
        let temp = tempfile::tempdir().unwrap();
        let mut state = RenderState::default();
        assert_eq!(
            render_once(temp.path(), &mut state).unwrap(),
            RenderOutcome::Skipped("ingress is not enabled on this Node")
        );
        atomic_write(&state_file(temp.path()), b"enabled\n", 0o600).unwrap();
        assert_eq!(
            render_once(temp.path(), &mut state).unwrap(),
            RenderOutcome::Skipped("this Node is not in a cluster")
        );
        assert!(!temp.path().join(INGRESS_CONFIG_FILE).exists());
    }

    #[test]
    fn ingress_unit_runs_caddy_hardened_with_only_the_bind_capability() {
        let unit = ingress_unit();
        let (unit_section, service_section) = unit.split_once("[Service]").unwrap();
        assert!(unit_section.contains("StartLimitIntervalSec=0\n"));
        assert!(service_section.contains(
            "ExecStart=/usr/local/bin/caddy run --config /etc/coolify-ingress/caddy.json\n"
        ));
        for line in [
            "User=coolify-ingress",
            "Group=coolify-ingress",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "RuntimeDirectory=coolify-ingress",
            "StateDirectory=coolify-ingress",
            "Restart=always",
            "RestartSec=2s",
        ] {
            assert!(service_section.contains(&format!("{line}\n")), "{line}");
        }
        assert!(unit.ends_with("[Install]\nWantedBy=multi-user.target\n"));
        assert!(!unit.contains("--adapter"));
    }

    #[test]
    fn caddy_downloads_are_pinned_per_architecture() {
        let (url, checksum) = caddy_download("x86_64\n").unwrap();
        assert_eq!(
            url,
            "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_amd64.tar.gz"
        );
        assert_eq!(checksum, CADDY_SHA512_LINUX_AMD64);
        let (url, checksum) = caddy_download("aarch64").unwrap();
        assert!(url.ends_with("/caddy_2.11.7_linux_arm64.tar.gz"));
        assert_eq!(checksum, CADDY_SHA512_LINUX_ARM64);
        assert!(caddy_download("riscv64").is_err());
        for checksum in [CADDY_SHA512_LINUX_AMD64, CADDY_SHA512_LINUX_ARM64] {
            assert_eq!(checksum.len(), 128);
            assert!(checksum.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("archive");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha512_file(&path).unwrap(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    fn cluster_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        atomic_write(
            &temp.path().join(crate::network::CORROSION_OWNER_FILE),
            b"10.240.0.2\n",
            0o644,
        )
        .unwrap();
        atomic_write(
            &temp.path().join(crate::network::CORROSION_NODE_NAME_FILE),
            b"worker-1\n",
            0o644,
        )
        .unwrap();
        temp
    }

    #[test]
    fn enabling_requires_a_cluster_and_disabling_cleans_up_idempotently() {
        let outside = tempfile::tempdir().unwrap();
        assert!(
            reconcile(outside.path(), &request(1, vec![]))
                .unwrap_err()
                .contains("not in a cluster")
        );
        assert!(!enabled(outside.path()));

        let temp = cluster_root();
        let root = temp.path();
        let enable = request(3, vec![route("app.example.com", "web", 3000)]);

        let result = reconcile(root, &enable).unwrap();
        assert_eq!(
            result,
            IngressReconcileResult {
                enabled: true,
                caddy_version: CADDY_VERSION.into(),
                active: false,
                revision: 3,
                route_count: 1,
                name_count: 0,
            }
        );
        assert!(enabled(root));
        assert_eq!(
            fs::read_to_string(root.join(INGRESS_UNIT_FILE)).unwrap(),
            ingress_unit()
        );
        // The unprivileged Caddy user must reach its configuration: no
        // root-only directory such as `/etc/coolify` on the path.
        assert!(!INGRESS_CONFIG_FILE.starts_with("etc/coolify/"));
        let mode = |path: PathBuf| {
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(path).unwrap().permissions())
        };
        assert_eq!(mode(root.join(INGRESS_CONFIG_DIR)) & 0o777, 0o755);
        assert_eq!(mode(root.join(INGRESS_CONFIG_FILE)) & 0o777, 0o644);
        assert_eq!(
            fs::read(root.join(INGRESS_CONFIG_FILE)).unwrap(),
            bootstrap_config()
        );
        assert!(
            fs::read_to_string(root.join("etc/corrosion/schemas/coolify.sql"))
                .unwrap()
                .contains("CREATE TABLE IF NOT EXISTS ingress_routes")
        );

        // A rendered configuration survives a repeated enable.
        fs::write(root.join(INGRESS_CONFIG_FILE), b"{\"rendered\":true}\n").unwrap();
        assert_eq!(reconcile(root, &enable).unwrap(), result);
        assert_eq!(
            fs::read(root.join(INGRESS_CONFIG_FILE)).unwrap(),
            b"{\"rendered\":true}\n"
        );

        // A Node that is not an ingress Node gets the same tables.
        let disable = IngressReconcileRequest {
            enabled: false,
            names: vec![name("web", "web")],
            ..enable.clone()
        };
        for _ in 0..2 {
            assert_eq!(
                reconcile(root, &disable).unwrap(),
                IngressReconcileResult {
                    enabled: false,
                    caddy_version: CADDY_VERSION.into(),
                    active: false,
                    revision: 3,
                    route_count: 1,
                    name_count: 1,
                }
            );
            assert!(!enabled(root));
            assert!(!root.join(INGRESS_UNIT_FILE).exists());
            assert!(!root.join(INGRESS_CONFIG_FILE).exists());
            assert!(!root.join(INGRESS_CONFIG_DIR).exists());
        }
        // Cluster identity and the Corrosion schema are untouched.
        assert!(root.join(crate::network::CORROSION_OWNER_FILE).exists());
        assert!(root.join("etc/corrosion/schemas/coolify.sql").exists());
    }
}
