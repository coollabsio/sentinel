//! Sentinel-owned publication of this Node's workload endpoints into Corrosion.
//!
//! Coolify only supplies identity (the Node DNS name and the container
//! `coolify.dns_name` labels). Liveness comes from what this Sentinel observes
//! locally, so internal DNS keeps working while Coolify is unavailable.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sentinel_protocol::control::v1::ContainerObservation;
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};

use crate::network::{CORROSION_NODE_NAME_FILE, CORROSION_OWNER_FILE, valid_discovery_label};

pub(crate) const PUBLISH_INTERVAL: Duration = Duration::from_secs(15);
pub(crate) const ENDPOINT_TTL_SECONDS: i64 = 120;
const MAX_ENDPOINTS: usize = 10_000;
const MANAGED_LABEL: &str = "coolify.managed";
const DNS_NAME_LABEL: &str = "coolify.dns_name";
const WORKLOAD_NAMESPACE: &str = "default";
const NODE_NAMESPACE: &str = "nodes";
const WORKLOAD_NETWORK_PREFIX: &str = "coolify-";
const ALLOWED_STATES: [&str; 9] = [
    "configured",
    "created",
    "running",
    "paused",
    "restarting",
    "stopped",
    "exited",
    "dead",
    "removing",
];
const ALLOWED_HEALTH: [&str; 4] = ["healthy", "unhealthy", "starting", "unknown"];

/// Serializes endpoint publishing with cluster leave, so a publish cannot
/// re-create rows after leave withdrew them.
static PUBLISHER: Mutex<()> = Mutex::new(());

pub(crate) fn publisher_lock() -> MutexGuard<'static, ()> {
    PUBLISHER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One `workload_endpoints` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkloadEndpoint {
    pub(crate) workload_id: String,
    pub(crate) namespace: String,
    pub(crate) owner_node_ip: String,
    pub(crate) container_ip: String,
    pub(crate) state: String,
    pub(crate) health: String,
    pub(crate) updated_at_unix_seconds: i64,
    pub(crate) expires_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeIdentity {
    pub(crate) owner_node_ip: String,
    pub(crate) node_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InspectedContainer {
    pub(crate) ip: Option<String>,
    pub(crate) health: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    Skipped(&'static str),
    Published { endpoints: usize },
}

pub(crate) fn validate_workload_endpoint(
    endpoint: &WorkloadEndpoint,
    expected_owner: &str,
) -> Result<(), String> {
    if endpoint.owner_node_ip != expected_owner
        || !valid_discovery_label(&endpoint.workload_id)
        || !valid_discovery_label(&endpoint.namespace)
        || endpoint.owner_node_ip.parse::<Ipv4Addr>().is_err()
        || endpoint.container_ip.parse::<Ipv4Addr>().is_err()
        || !ALLOWED_STATES.contains(&endpoint.state.as_str())
        || !ALLOWED_HEALTH.contains(&endpoint.health.as_str())
        || endpoint.updated_at_unix_seconds <= 0
        || endpoint.expires_at_unix_seconds <= endpoint.updated_at_unix_seconds
        || endpoint.expires_at_unix_seconds - endpoint.updated_at_unix_seconds > 3600
    {
        return Err("A Corrosion endpoint is invalid or is not owned by this Node.".into());
    }
    Ok(())
}

/// Reads the cluster identity written by `discovery.corrosion.reconcile`.
/// Returns `Ok(None)` when this Node is not in a cluster.
pub(crate) fn read_identity(root: &Path) -> Result<Option<NodeIdentity>, String> {
    let Some(owner) = read_optional(&root.join(CORROSION_OWNER_FILE))? else {
        return Ok(None);
    };
    let Some(node_name) = read_optional(&root.join(CORROSION_NODE_NAME_FILE))? else {
        return Ok(None);
    };
    let owner = owner
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|address| !address.is_unspecified())
        .ok_or("The Corrosion owner address is invalid.")?;
    if !valid_discovery_label(&node_name) {
        return Err("The Corrosion Node DNS name is invalid.".into());
    }
    Ok(Some(NodeIdentity {
        owner_node_ip: owner.to_string(),
        node_name,
    }))
}

fn read_optional(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("The Corrosion identity could not be read.".into()),
    }
}

/// Returns the DNS label of a container that should be published.
fn published_dns_name(container: &ContainerObservation) -> Option<&str> {
    if container.labels.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
        return None;
    }
    container
        .labels
        .get(DNS_NAME_LABEL)
        .map(String::as_str)
        .filter(|name| valid_discovery_label(name))
}

/// Parses `podman inspect --format json` output into the workload IPv4 and
/// health of every container, keyed by full container ID.
pub(crate) fn parse_podman_inspect(
    output: &[u8],
) -> Result<HashMap<String, InspectedContainer>, &'static str> {
    let values: Vec<Value> =
        serde_json::from_slice(output).map_err(|_| "Podman returned invalid inspect data.")?;
    if values.len() > MAX_ENDPOINTS {
        return Err("Podman returned too many containers.");
    }
    let mut containers = HashMap::with_capacity(values.len());
    for value in &values {
        let Some(id) = value
            .get("Id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        let ip = value
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .and_then(|networks| {
                networks.iter().find_map(|(name, network)| {
                    if !name.starts_with(WORKLOAD_NETWORK_PREFIX) {
                        return None;
                    }
                    network
                        .get("IPAddress")
                        .and_then(Value::as_str)
                        .and_then(|address| address.parse::<Ipv4Addr>().ok())
                        .filter(|address| !address.is_unspecified())
                        .map(|address| address.to_string())
                })
            });
        let health = ["/State/Health/Status", "/State/Healthcheck/Status"]
            .iter()
            .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
            .filter(|status| !status.is_empty())
            .map(str::to_string);
        containers.insert(id.to_string(), InspectedContainer { ip, health });
    }
    Ok(containers)
}

fn normalize_state(state: &str) -> String {
    let state = state.trim().to_ascii_lowercase();
    if ALLOWED_STATES.contains(&state.as_str()) {
        state
    } else {
        "stopped".into()
    }
}

fn normalize_health(health: Option<&str>) -> String {
    let health = health.unwrap_or_default().trim().to_ascii_lowercase();
    if ALLOWED_HEALTH.contains(&health.as_str()) {
        health
    } else {
        "unknown".into()
    }
}

/// Builds the deduplicated endpoint snapshot of this Node: one row for the
/// Node itself plus one per published workload container with a workload IP.
pub(crate) fn endpoint_rows(
    identity: &NodeIdentity,
    containers: &[ContainerObservation],
    inspected: &HashMap<String, InspectedContainer>,
    now: i64,
) -> Vec<WorkloadEndpoint> {
    let row = |namespace: &str, workload_id: &str, ip: &str, state: String, health: String| {
        WorkloadEndpoint {
            workload_id: workload_id.into(),
            namespace: namespace.into(),
            owner_node_ip: identity.owner_node_ip.clone(),
            container_ip: ip.into(),
            state,
            health,
            updated_at_unix_seconds: now,
            expires_at_unix_seconds: now + ENDPOINT_TTL_SECONDS,
        }
    };
    let mut rows = BTreeMap::new();
    let node = row(
        NODE_NAMESPACE,
        &identity.node_name,
        &identity.owner_node_ip,
        "running".into(),
        "healthy".into(),
    );
    rows.insert(endpoint_key(&node), node);

    for container in containers {
        let Some(dns_name) = published_dns_name(container) else {
            continue;
        };
        let Some(observed) = inspected.get(&container.runtime_id) else {
            continue;
        };
        let Some(ip) = observed.ip.as_deref() else {
            continue;
        };
        let health = observed
            .health
            .as_deref()
            .or(container.health_status.as_deref());
        let endpoint = row(
            WORKLOAD_NAMESPACE,
            dns_name,
            ip,
            normalize_state(&container.state),
            normalize_health(health),
        );
        // Two containers may briefly share a name and IP during a replace;
        // prefer the running one so DNS keeps answering.
        let key = endpoint_key(&endpoint);
        match rows.get(&key) {
            Some(existing) if existing.state == "running" || endpoint.state != "running" => {}
            _ => {
                rows.insert(key, endpoint);
            }
        }
    }
    rows.into_values().collect()
}

fn endpoint_key(endpoint: &WorkloadEndpoint) -> (String, String, String, String) {
    (
        endpoint.namespace.clone(),
        endpoint.workload_id.clone(),
        endpoint.owner_node_ip.clone(),
        endpoint.container_ip.clone(),
    )
}

/// Upserts every current row and deletes this owner's rows that were not
/// refreshed in this pass, in one Corrosion transaction.
pub(crate) fn publish_transaction(
    owner_node_ip: &str,
    rows: &[WorkloadEndpoint],
    now: i64,
) -> Result<Vec<Value>, String> {
    if owner_node_ip.parse::<Ipv4Addr>().is_err() || rows.len() > MAX_ENDPOINTS || now <= 0 {
        return Err(
            "The Corrosion endpoint snapshot is invalid or is not owned by this Node.".into(),
        );
    }
    let mut transaction = Vec::with_capacity(rows.len() + 1);
    for endpoint in rows {
        validate_workload_endpoint(endpoint, owner_node_ip)?;
        transaction.push(json!([
            "INSERT INTO workload_endpoints (workload_id, namespace, owner_node_ip, container_ip, state, health, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (namespace, workload_id, owner_node_ip, container_ip) DO UPDATE SET state = excluded.state, health = excluded.health, updated_at = excluded.updated_at, expires_at = excluded.expires_at",
            [
                endpoint.workload_id,
                endpoint.namespace,
                endpoint.owner_node_ip,
                endpoint.container_ip,
                endpoint.state,
                endpoint.health,
                endpoint.updated_at_unix_seconds,
                endpoint.expires_at_unix_seconds
            ]
        ]));
    }
    transaction.push(json!([
        "DELETE FROM workload_endpoints WHERE owner_node_ip = ? AND updated_at < ?",
        [owner_node_ip, now]
    ]));
    Ok(transaction)
}

/// Removes every row owned by this Node. The caller holds `publisher_lock`.
pub(crate) fn withdraw_endpoints(owner_node_ip: &str) -> Result<(), String> {
    let owner = owner_node_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| "The Node owner address is invalid.".to_string())?;
    post_transaction(
        &owner.to_string(),
        &[json!([
            "DELETE FROM workload_endpoints WHERE owner_node_ip = ?",
            [owner.to_string()]
        ])],
    )
}

fn post_transaction(owner_node_ip: &str, transaction: &[Value]) -> Result<(), String> {
    let body = serde_json::to_vec(transaction)
        .map_err(|_| "The Corrosion endpoint transaction could not be encoded.".to_string())?;
    // The body is streamed over stdin: a single argv entry is capped at 128 KiB.
    let mut child = Command::new("curl")
        .args([
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "5",
            "--max-time",
            "20",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ])
        .arg(format!("http://{owner_node_ip}:8080/v1/transactions"))
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
            stdin
                .write_all(&body)
                .map_err(|_| "The Corrosion transaction could not be sent.")
        });
    let output = child
        .wait_with_output()
        .map_err(|_| "Corrosion could not publish the endpoint snapshot.".to_string())?;
    written?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(500)
        .collect::<String>();
    Err(if message.is_empty() {
        "Corrosion could not publish the endpoint snapshot.".into()
    } else {
        message
    })
}

/// Observes local workloads and publishes this Node's endpoint snapshot.
pub(crate) fn publish_once(root: &Path) -> Result<PublishOutcome, String> {
    let _publisher = publisher_lock();
    let Some(identity) = read_identity(root)? else {
        return Ok(PublishOutcome::Skipped("this Node is not in a cluster"));
    };
    if root != Path::new("/") {
        return Ok(PublishOutcome::Skipped(
            "endpoint publishing only runs against the host root",
        ));
    }

    let listed = match Command::new("podman")
        .args(["ps", "--all", "--no-trunc", "--format", "json"])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Ok(PublishOutcome::Skipped("Podman is unavailable")),
    };
    if !listed.status.success() {
        return Err("Podman could not list containers.".into());
    }
    let containers =
        crate::commands::parse_podman_containers(&listed.stdout).map_err(str::to_string)?;
    let ids = containers
        .iter()
        .filter(|container| published_dns_name(container).is_some())
        .map(|container| container.runtime_id.as_str())
        .collect::<Vec<_>>();
    let inspected = if ids.is_empty() {
        HashMap::new()
    } else {
        let output = Command::new("podman")
            .args(["inspect", "--format", "json"])
            .args(&ids)
            .output()
            .map_err(|_| "Podman is unavailable.".to_string())?;
        // A container removed after `ps` makes inspect exit non-zero while
        // still printing the others, so use any parseable output.
        match parse_podman_inspect(&output.stdout) {
            Ok(inspected) => inspected,
            Err(_) if !output.status.success() => {
                return Err("Podman could not inspect the managed containers.".into());
            }
            Err(message) => return Err(message.into()),
        }
    };

    let now = crate::network::unix_seconds();
    let rows = endpoint_rows(&identity, &containers, &inspected, now);
    let transaction = publish_transaction(&identity.owner_node_ip, &rows, now)?;
    post_transaction(&identity.owner_node_ip, &transaction)?;
    Ok(PublishOutcome::Published {
        endpoints: rows.len(),
    })
}

/// Publishes once at start, then every `PUBLISH_INTERVAL` and whenever
/// `trigger` is notified, until shutdown.
pub(crate) async fn run(root: PathBuf, trigger: Arc<Notify>, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(PUBLISH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
        let publish_root = root.clone();
        let result = tokio::task::spawn_blocking(move || publish_once(&publish_root))
            .await
            .unwrap_or_else(|_| Err("The endpoint publisher task failed.".into()));
        match result {
            Ok(PublishOutcome::Published { endpoints }) => {
                if last_error.take().is_some() {
                    tracing::info!(endpoints, "discovery endpoint publishing recovered");
                }
                tracing::debug!(endpoints, "published discovery endpoints");
            }
            Ok(PublishOutcome::Skipped(reason)) => {
                last_error = None;
                tracing::debug!(reason, "skipped discovery endpoint publishing");
            }
            Err(error) => {
                if last_error.as_deref() == Some(error.as_str()) {
                    tracing::debug!(%error, "discovery endpoint publishing still failing");
                } else {
                    tracing::warn!(%error, "could not publish discovery endpoints");
                }
                last_error = Some(error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> NodeIdentity {
        NodeIdentity {
            owner_node_ip: "10.240.0.2".into(),
            node_name: "worker-1".into(),
        }
    }

    fn container(id: &str, state: &str, labels: &[(&str, &str)]) -> ContainerObservation {
        ContainerObservation {
            runtime_id: id.into(),
            name: format!("container-{id}"),
            image: "docker.io/library/nginx:latest".into(),
            state: state.into(),
            labels: labels
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    fn inspected(ip: Option<&str>, health: Option<&str>) -> InspectedContainer {
        InspectedContainer {
            ip: ip.map(str::to_string),
            health: health.map(str::to_string),
        }
    }

    fn managed(dns_name: &str) -> Vec<(&'static str, String)> {
        vec![
            ("coolify.managed", "true".into()),
            ("coolify.dns_name", dns_name.into()),
        ]
    }

    fn labels<'a>(pairs: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
        pairs
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect()
    }

    #[test]
    fn inspect_parsing_uses_the_first_coolify_network_ipv4_and_health() {
        let output = br#"[
          {
            "Id": "aaa",
            "State": {"Status": "running", "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Networks": {
              "bridge": {"IPAddress": "10.88.0.5"},
              "coolify-empty": {"IPAddress": ""},
              "coolify-project": {"IPAddress": "100.64.0.7"},
              "coolify-zzz": {"IPAddress": "100.64.9.9"}
            }}
          },
          {
            "Id": "bbb",
            "State": {"Status": "exited", "Healthcheck": {"Status": "unhealthy"}},
            "NetworkSettings": {"Networks": {"coolify-project": {"IPAddress": ""}}}
          },
          {
            "Id": "ccc",
            "State": {"Status": "running"},
            "NetworkSettings": {"Networks": {
              "podman": {"IPAddress": "10.88.0.9"},
              "coolify-bad": {"IPAddress": "not-an-ip"},
              "coolify-v6": {"IPAddress": "fd00::1"}
            }}
          },
          {"State": {"Status": "running"}}
        ]"#;

        let parsed = parse_podman_inspect(output).unwrap();

        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed["aaa"],
            inspected(Some("100.64.0.7"), Some("healthy"))
        );
        assert_eq!(parsed["bbb"], inspected(None, Some("unhealthy")));
        assert_eq!(parsed["ccc"], inspected(None, None));
        assert!(parse_podman_inspect(b"not json").is_err());
        assert!(parse_podman_inspect(b"[]").unwrap().is_empty());
    }

    #[test]
    fn rows_include_the_node_and_only_published_workloads_with_an_ip() {
        let web = managed("web");
        let bad = managed("bad.name");
        let stopped = managed("stopped-app");
        let containers = vec![
            container("web", "running", &labels(&web)),
            container("bad", "running", &labels(&bad)),
            container("unmanaged", "running", &[("coolify.dns_name", "unmanaged")]),
            container(
                "not-true",
                "running",
                &[("coolify.managed", "false"), ("coolify.dns_name", "nope")],
            ),
            container("no-label", "running", &[("coolify.managed", "true")]),
            container("stopped", "exited", &labels(&stopped)),
            container("missing", "running", &labels(&managed("missing"))),
        ];
        let observed = HashMap::from([
            (
                "web".to_string(),
                inspected(Some("100.64.0.7"), Some("healthy")),
            ),
            ("bad".to_string(), inspected(Some("100.64.0.8"), None)),
            ("unmanaged".to_string(), inspected(Some("100.64.0.9"), None)),
            ("not-true".to_string(), inspected(Some("100.64.0.10"), None)),
            ("no-label".to_string(), inspected(Some("100.64.0.11"), None)),
            ("stopped".to_string(), inspected(None, None)),
        ]);

        let rows = endpoint_rows(&identity(), &containers, &observed, 1_700_000_000);

        assert_eq!(
            rows,
            vec![
                WorkloadEndpoint {
                    workload_id: "web".into(),
                    namespace: "default".into(),
                    owner_node_ip: "10.240.0.2".into(),
                    container_ip: "100.64.0.7".into(),
                    state: "running".into(),
                    health: "healthy".into(),
                    updated_at_unix_seconds: 1_700_000_000,
                    expires_at_unix_seconds: 1_700_000_120,
                },
                WorkloadEndpoint {
                    workload_id: "worker-1".into(),
                    namespace: "nodes".into(),
                    owner_node_ip: "10.240.0.2".into(),
                    container_ip: "10.240.0.2".into(),
                    state: "running".into(),
                    health: "healthy".into(),
                    updated_at_unix_seconds: 1_700_000_000,
                    expires_at_unix_seconds: 1_700_000_120,
                },
            ]
        );
    }

    #[test]
    fn rows_normalize_state_and_health() {
        let cases = [
            ("running", None, None, "running", "unknown"),
            ("Running", Some("Healthy"), None, "running", "healthy"),
            ("paused", Some(""), None, "paused", "unknown"),
            ("initialized", Some("none"), None, "stopped", "unknown"),
            ("unknown", None, Some("starting"), "stopped", "starting"),
            (
                "exited",
                Some("unhealthy"),
                Some("healthy"),
                "exited",
                "unhealthy",
            ),
        ];
        for (state, inspect_health, ps_health, expected_state, expected_health) in cases {
            let web = managed("web");
            let mut observed_container = container("web", state, &labels(&web));
            observed_container.health_status = ps_health.map(str::to_string);
            let observed = HashMap::from([(
                "web".to_string(),
                inspected(Some("100.64.0.7"), inspect_health),
            )]);

            let rows = endpoint_rows(&identity(), &[observed_container], &observed, 10);
            let workload = rows.iter().find(|row| row.namespace == "default").unwrap();

            assert_eq!(workload.state, expected_state, "state for {state}");
            assert_eq!(workload.health, expected_health, "health for {state}");
            validate_workload_endpoint(workload, "10.240.0.2").unwrap();
        }
    }

    #[test]
    fn rows_are_deduplicated_on_the_primary_key_preferring_running() {
        let web = managed("web");
        let api = managed("api");
        let containers = vec![
            container("old", "exited", &labels(&web)),
            container("new", "running", &labels(&web)),
            container("later", "created", &labels(&web)),
            container("api-1", "running", &labels(&api)),
            container("api-2", "running", &labels(&api)),
            // A workload named like the Node must not collide with the Node row.
            container("named-like-node", "running", &labels(&managed("worker-1"))),
        ];
        let observed = HashMap::from([
            ("old".to_string(), inspected(Some("100.64.0.7"), None)),
            (
                "new".to_string(),
                inspected(Some("100.64.0.7"), Some("healthy")),
            ),
            ("later".to_string(), inspected(Some("100.64.0.7"), None)),
            ("api-1".to_string(), inspected(Some("100.64.0.8"), None)),
            ("api-2".to_string(), inspected(Some("100.64.0.9"), None)),
            (
                "named-like-node".to_string(),
                inspected(Some("10.240.0.2"), None),
            ),
        ]);

        let rows = endpoint_rows(&identity(), &containers, &observed, 10);

        let keys = rows.iter().map(endpoint_key).collect::<Vec<_>>();
        let mut unique = keys.clone();
        unique.dedup();
        assert_eq!(keys, unique);
        assert_eq!(rows.len(), 5);
        let web = rows.iter().find(|row| row.workload_id == "web").unwrap();
        assert_eq!(
            (web.state.as_str(), web.health.as_str()),
            ("running", "healthy")
        );
        assert_eq!(
            rows.iter().filter(|row| row.workload_id == "api").count(),
            2
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.workload_id == "worker-1")
                .map(|row| row.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["default", "nodes"]
        );
    }

    #[test]
    fn transaction_upserts_every_row_then_deletes_stale_owned_rows() {
        let web = managed("web");
        let containers = vec![container("web", "running", &labels(&web))];
        let observed = HashMap::from([("web".to_string(), inspected(Some("100.64.0.7"), None))]);
        let rows = endpoint_rows(&identity(), &containers, &observed, 1_700_000_000);

        let transaction = publish_transaction("10.240.0.2", &rows, 1_700_000_000).unwrap();

        assert_eq!(transaction.len(), 3);
        for statement in &transaction[..2] {
            let sql = statement[0].as_str().unwrap();
            assert!(sql.starts_with("INSERT INTO workload_endpoints (workload_id, namespace, owner_node_ip, container_ip, state, health, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"));
            assert!(sql.ends_with("ON CONFLICT (namespace, workload_id, owner_node_ip, container_ip) DO UPDATE SET state = excluded.state, health = excluded.health, updated_at = excluded.updated_at, expires_at = excluded.expires_at"));
            assert!(!sql.contains("DELETE"));
        }
        assert_eq!(
            transaction[0][1],
            json!([
                "web",
                "default",
                "10.240.0.2",
                "100.64.0.7",
                "running",
                "unknown",
                1_700_000_000,
                1_700_000_120
            ])
        );
        assert_eq!(
            transaction[2],
            json!([
                "DELETE FROM workload_endpoints WHERE owner_node_ip = ? AND updated_at < ?",
                ["10.240.0.2", 1_700_000_000]
            ])
        );
    }

    #[test]
    fn transaction_rejects_foreign_invalid_or_oversized_snapshots() {
        let rows = endpoint_rows(&identity(), &[], &HashMap::new(), 10);
        assert!(publish_transaction("10.240.0.3", &rows, 10).is_err());
        assert!(publish_transaction("not-an-ip", &rows, 10).is_err());

        let mut invalid = rows.clone();
        invalid[0].health = "bogus".into();
        assert!(publish_transaction("10.240.0.2", &invalid, 10).is_err());

        let oversized = vec![rows[0].clone(); MAX_ENDPOINTS + 1];
        assert!(publish_transaction("10.240.0.2", &oversized, 10).is_err());
        assert!(publish_transaction("10.240.0.2", &rows, 10).is_ok());
    }

    #[test]
    fn identity_is_absent_until_both_cluster_files_exist() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(read_identity(temp.path()).unwrap(), None);
        assert_eq!(
            publish_once(temp.path()).unwrap(),
            PublishOutcome::Skipped("this Node is not in a cluster")
        );

        crate::network::atomic_write(
            &temp.path().join(CORROSION_OWNER_FILE),
            b"10.240.0.2\n",
            0o644,
        )
        .unwrap();
        assert_eq!(read_identity(temp.path()).unwrap(), None);

        crate::network::atomic_write(
            &temp.path().join(CORROSION_NODE_NAME_FILE),
            b"worker-1\n",
            0o644,
        )
        .unwrap();
        assert_eq!(read_identity(temp.path()).unwrap(), Some(identity()));

        crate::network::atomic_write(
            &temp.path().join(CORROSION_NODE_NAME_FILE),
            b"bad.name\n",
            0o644,
        )
        .unwrap();
        assert!(read_identity(temp.path()).is_err());
        assert!(publish_once(temp.path()).is_err());
    }

    #[tokio::test]
    async fn publisher_stops_on_shutdown() {
        let temp = tempfile::tempdir().unwrap();
        let (sender, receiver) = watch::channel(false);
        let trigger = Arc::new(Notify::new());
        let task = tokio::spawn(run(temp.path().to_path_buf(), trigger.clone(), receiver));
        trigger.notify_one();
        sender.send(true).unwrap();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
