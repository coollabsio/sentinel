use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sentinel_protocol::control::v1::{
    CorrosionEndpointReconcileRequest, CorrosionEndpointReconcileResult, CorrosionInspectResult,
    CorrosionReconcileRequest, CorrosionReconcileResult, FirewallInspectResult,
    FirewallReconcileRequest, FirewallReconcileResult, WireguardInspectResult, WireguardPeer,
    WireguardPeerState, WireguardReconcileRequest, WireguardReconcileResult, WorkloadEndpoint,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const COOLIFY_NFT_TABLE: &str = "coolify_cluster";
pub(crate) const CORROSION_VERSION: &str = "v1.0.0";

pub(crate) fn validate_interface(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    {
        return Err("The WireGuard interface is invalid.".into());
    }
    Ok(())
}

fn valid_ipv4_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    address.parse::<std::net::Ipv4Addr>().is_ok()
        && prefix.parse::<u8>().is_ok_and(|prefix| prefix <= 32)
}

fn ipv4_in_cidr(address: &str, cidr: &str) -> bool {
    let Ok(address) = address.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask == u32::from(network) & mask
}

pub(crate) fn validate_wireguard(request: &WireguardReconcileRequest) -> Result<(), String> {
    validate_interface(&request.interface)?;
    if request.listen_port == 0
        || request.revision == 0
        || !request.address.ends_with("/32")
        || request.peers.len() > 99
    {
        return Err("The WireGuard configuration is invalid.".into());
    }
    for peer in &request.peers {
        if peer.public_key.is_empty()
            || peer.endpoint.is_empty()
            || peer.allowed_ips.is_empty()
            || peer.allowed_ips.len() > 128
            || peer
                .allowed_ips
                .iter()
                .any(|allowed| !valid_ipv4_cidr(allowed))
            || peer.persistent_keepalive_seconds > 300
        {
            return Err("A WireGuard peer is invalid.".into());
        }
    }
    Ok(())
}

pub(crate) fn render_wireguard(
    request: &WireguardReconcileRequest,
    private_key: &str,
) -> Result<String, String> {
    validate_wireguard(request)?;
    if private_key.trim().is_empty() || private_key.contains('\n') {
        return Err("The WireGuard private key is invalid.".into());
    }
    let mut peers = request.peers.clone();
    peers.sort_by(|a, b| a.allowed_ips.cmp(&b.allowed_ips));
    let mut output = format!(
        "[Interface]\nAddress = {}\nListenPort = {}\nPrivateKey = {}\n\n",
        request.address,
        request.listen_port,
        private_key.trim()
    );
    for peer in peers {
        output.push_str(&render_peer(&peer));
    }
    Ok(output)
}

fn render_peer(peer: &WireguardPeer) -> String {
    format!(
        "[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {}\n\n",
        peer.public_key,
        peer.endpoint,
        peer.allowed_ips.join(", "),
        peer.persistent_keepalive_seconds
    )
}

pub(crate) fn render_firewall(request: &FirewallReconcileRequest) -> Result<String, String> {
    if request.revision == 0
        || request.wireguard_port == 0
        || !valid_ipv4_cidr(&request.cluster_cidr)
        || validate_interface(&request.wireguard_interface).is_err()
        || request.workload_cidrs.is_empty()
        || request.workload_cidrs.len() > 10_000
        || request
            .workload_cidrs
            .iter()
            .any(|cidr| !valid_ipv4_cidr(cidr))
        || request.rules.len() > 100_000
        || request.rules.iter().any(|rule| {
            rule.source_ip.parse::<std::net::Ipv4Addr>().is_err()
                || rule.destination_ip.parse::<std::net::Ipv4Addr>().is_err()
                || !matches!(rule.protocol.as_str(), "tcp" | "udp")
                || rule.port == 0
                || rule.port > 65_535
                || !request
                    .workload_cidrs
                    .iter()
                    .any(|cidr| ipv4_in_cidr(&rule.source_ip, cidr))
                || !request
                    .workload_cidrs
                    .iter()
                    .any(|cidr| ipv4_in_cidr(&rule.destination_ip, cidr))
        })
    {
        return Err("The firewall configuration is invalid.".into());
    }

    let mut workload_cidrs = request.workload_cidrs.clone();
    workload_cidrs.sort();
    workload_cidrs.dedup();
    let elements = workload_cidrs.join(", ");
    let mut rules = request.rules.clone();
    rules.sort_by(|left, right| {
        (
            &left.source_ip,
            &left.destination_ip,
            &left.protocol,
            left.port,
        )
            .cmp(&(
                &right.source_ip,
                &right.destination_ip,
                &right.protocol,
                right.port,
            ))
    });
    let allow_rules = rules
        .into_iter()
        .map(|rule| {
            format!(
                "ip saddr {} ip daddr {} {} dport {} accept;",
                rule.source_ip, rule.destination_ip, rule.protocol, rule.port
            )
        })
        .collect::<Vec<_>>()
        .join(" ");

    Ok(format!(
        "table inet {COOLIFY_NFT_TABLE} {{
 set workload_networks {{ type ipv4_addr; flags interval; elements = {{ {elements} }} }}
 chain input {{ type filter hook input priority -5; policy accept; ct state established,related accept; udp dport {} accept; ip saddr @workload_networks udp dport 53 accept; ip saddr @workload_networks tcp dport 53 accept; iifname \"{}\" ip saddr != {} ip saddr != @workload_networks drop; ip saddr @workload_networks drop; }}
 chain forward {{ type filter hook forward priority -5; policy accept; ct state established,related accept; {allow_rules} ip saddr @workload_networks ip daddr @workload_networks drop; ip saddr @workload_networks ip daddr {} drop; }}
 chain output {{ type filter hook output priority -5; policy accept; }}
}}
",
        request.wireguard_port, request.wireguard_interface, request.cluster_cidr, request.cluster_cidr
    ))
}

pub(crate) fn render_corrosion(request: &CorrosionReconcileRequest) -> Result<String, String> {
    let bind_address = request.bind_address.parse::<std::net::Ipv4Addr>().ok();
    if request.version.is_empty()
        || request.cluster_id.is_empty()
        || bind_address.is_none_or(|address| address.is_unspecified())
        || request.peers.len() > 99
        || request.peers.iter().any(|peer| {
            peer.parse::<std::net::SocketAddr>()
                .map_or(true, |address| {
                    !address.is_ipv4() || address.ip().is_unspecified() || address.port() != 8787
                })
        })
    {
        return Err("The Corrosion configuration is invalid.".into());
    }
    let peers = request
        .peers
        .iter()
        .map(|peer| format!("\"{peer}\""))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(format!(
        "# generated by Coolify; do not edit\n[db]\npath = \"/var/lib/corrosion/corrosion.db\"\nschema_paths = [\"/etc/corrosion/schemas\"]\n[gossip]\naddr = \"{}:8787\"\nbootstrap = [{}]\nplaintext = true\n[api]\naddr = \"{}:8080\"\n[admin]\npath = \"/run/corrosion/admin.sock\"\n",
        request.bind_address, peers, request.bind_address
    ))
}

fn corrosion_cluster_id(value: &str) -> Result<u16, String> {
    if value.is_empty() || value.len() > 255 {
        return Err("The Corrosion cluster ID is invalid.".into());
    }
    let digest = Sha256::digest(value.as_bytes());
    let id = u16::from_be_bytes([digest[0], digest[1]]);
    Ok(id.max(1))
}

fn valid_discovery_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn validate_workload_endpoint(
    endpoint: &WorkloadEndpoint,
    expected_owner: &str,
) -> Result<(), String> {
    if endpoint.owner_node_ip != expected_owner
        || !valid_discovery_label(&endpoint.workload_id)
        || !valid_discovery_label(&endpoint.namespace)
        || endpoint
            .owner_node_ip
            .parse::<std::net::Ipv4Addr>()
            .is_err()
        || endpoint.container_ip.parse::<std::net::Ipv4Addr>().is_err()
        || !matches!(
            endpoint.state.as_str(),
            "configured"
                | "created"
                | "running"
                | "paused"
                | "restarting"
                | "stopped"
                | "exited"
                | "dead"
                | "removing"
        )
        || !matches!(
            endpoint.health.as_str(),
            "healthy" | "unhealthy" | "starting" | "unknown"
        )
        || endpoint.updated_at_unix_seconds <= 0
        || endpoint.expires_at_unix_seconds <= endpoint.updated_at_unix_seconds
        || endpoint.expires_at_unix_seconds - endpoint.updated_at_unix_seconds > 3600
    {
        return Err("A Corrosion endpoint is invalid or is not owned by this Node.".into());
    }
    Ok(())
}

fn corrosion_endpoint_transaction(
    request: &CorrosionEndpointReconcileRequest,
    local_owner: &str,
) -> Result<Vec<Value>, String> {
    if request.owner_node_ip != local_owner
        || request.owner_node_ip.parse::<std::net::Ipv4Addr>().is_err()
        || request.endpoints.len() > 10_000
    {
        return Err(
            "The Corrosion endpoint snapshot is invalid or is not owned by this Node.".into(),
        );
    }
    let mut transaction = vec![json!([
        "DELETE FROM workload_endpoints WHERE owner_node_ip = ?",
        [local_owner]
    ])];
    for endpoint in &request.endpoints {
        validate_workload_endpoint(endpoint, local_owner)?;
        transaction.push(json!([
            "INSERT INTO workload_endpoints (workload_id, namespace, owner_node_ip, container_ip, state, health, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
    Ok(transaction)
}

pub(crate) fn validate_corrosion_endpoints(
    request: &CorrosionEndpointReconcileRequest,
) -> Result<(), String> {
    corrosion_endpoint_transaction(request, &request.owner_node_ip).map(|_| ())
}

pub(crate) fn reconcile_corrosion_endpoints(
    root: &Path,
    request: &CorrosionEndpointReconcileRequest,
) -> Result<CorrosionEndpointReconcileResult, String> {
    let owner_path = root.join("etc/corrosion/coolify-owner");
    let local_owner = fs::read_to_string(owner_path)
        .map_err(|_| "Corrosion is not configured for this Node.".to_string())?;
    let local_owner = local_owner.trim();
    let transaction = corrosion_endpoint_transaction(request, local_owner)?;

    if root == Path::new("/") {
        let body = serde_json::to_string(&transaction)
            .map_err(|_| "The Corrosion endpoint transaction could not be encoded.".to_string())?;
        run(
            Command::new("curl")
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
                ])
                .arg(body)
                .arg(format!("http://{local_owner}:8080/v1/transactions")),
            "Corrosion could not reconcile the endpoint snapshot.",
        )?;
    }

    Ok(CorrosionEndpointReconcileResult {
        owner_node_ip: local_owner.into(),
        endpoint_count: request.endpoints.len() as u64,
    })
}

pub(crate) fn ensure_key(root: &Path, interface: &str) -> Result<String, String> {
    ensure_key_with_binary(root, interface, Path::new("wg"))
}

fn ensure_key_with_binary(
    root: &Path,
    interface: &str,
    wireguard: &Path,
) -> Result<String, String> {
    validate_interface(interface)?;
    let dir = root.join("etc/coolify/network");
    fs::create_dir_all(&dir).map_err(|_| "The key directory could not be created.")?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| "The key directory permissions could not be set.")?;
    let path = dir.join(format!("{interface}.key"));
    if !path.exists() {
        let output = Command::new(wireguard)
            .arg("genkey")
            .output()
            .map_err(|_| "WireGuard is unavailable.")?;
        if !output.status.success() {
            return Err("WireGuard could not generate a key.".into());
        }
        atomic_write(&path, &output.stdout, 0o600)?;
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "The key permissions could not be set.")?;
    let private = fs::read(&path).map_err(|_| "The private key could not be read.")?;
    let mut child = Command::new(wireguard)
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "WireGuard is unavailable.")?;
    child
        .stdin
        .as_mut()
        .ok_or("WireGuard input is unavailable.")?
        .write_all(&private)
        .map_err(|_| "WireGuard key input failed.")?;
    let output = child
        .wait_with_output()
        .map_err(|_| "WireGuard public key generation failed.")?;
    if !output.status.success() {
        return Err("WireGuard public key generation failed.".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "WireGuard returned an invalid public key.".into())
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("The target path is invalid.")?;
    fs::create_dir_all(parent).map_err(|_| "The target directory could not be created.")?;
    let mut staged_name = path.as_os_str().to_os_string();
    staged_name.push(".tmp");
    let staged = PathBuf::from(staged_name);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&staged)
        .map_err(|_| "The staged file could not be created.")?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|_| "The staged file could not be written.")?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
        .map_err(|_| "The staged file permissions could not be set.")?;
    fs::rename(staged, path).map_err(|_| "The staged file could not be activated.".to_string())
}

pub(crate) fn hash(contents: &[u8]) -> String {
    format!("{:x}", Sha256::digest(contents))
}

pub(crate) fn state_path(root: &Path, name: &str) -> PathBuf {
    root.join("var/lib/coolify/network").join(name)
}

pub(crate) fn read_applied_state(root: &Path, interface: &str) -> Option<(u64, String)> {
    let contents = fs::read_to_string(state_path(root, &format!("{interface}.state"))).ok()?;
    let (revision, hash) = contents.trim().split_once(' ')?;
    Some((revision.parse().ok()?, hash.to_string()))
}

fn staged_wireguard_path(root: &Path, interface: &str) -> PathBuf {
    root.join("etc/wireguard/.coolify-stage")
        .join(format!("{interface}.conf"))
}

pub(crate) fn inspect_wireguard(
    root: &Path,
    interface: &str,
    expected_revision: u64,
    expected_hash: &str,
) -> WireguardInspectResult {
    let applied = read_applied_state(root, interface);
    let observed = if root == Path::new("/") {
        Command::new("wg")
            .args(["show", interface, "dump"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| parse_wireguard_dump(interface, &output.stdout).ok())
    } else {
        None
    };
    WireguardInspectResult {
        interface: interface.into(),
        public_key: observed
            .as_ref()
            .map_or_else(String::new, |state| state.public_key.clone()),
        listen_port: observed.as_ref().map_or(0, |state| state.listen_port),
        peers: observed.map_or_else(Vec::new, |state| state.peers),
        applied_revision: applied.as_ref().map_or(0, |state| state.0),
        configuration_hash: applied
            .as_ref()
            .map_or_else(String::new, |state| state.1.clone()),
        drifted: applied
            .as_ref()
            .is_none_or(|state| state.0 != expected_revision || state.1 != expected_hash),
    }
}

fn parse_wireguard_dump(interface: &str, dump: &[u8]) -> Result<WireguardInspectResult, String> {
    let text = std::str::from_utf8(dump).map_err(|_| "WireGuard returned invalid state.")?;
    let mut lines = text.lines();
    let interface_fields = lines
        .next()
        .ok_or("WireGuard returned no interface state.")?
        .split('\t')
        .collect::<Vec<_>>();
    if interface_fields.len() < 4 {
        return Err("WireGuard returned incomplete interface state.".into());
    }
    let public_key = interface_fields[1].to_string();
    let listen_port = interface_fields[2]
        .parse()
        .map_err(|_| "WireGuard returned an invalid listen port.")?;
    let mut peers = Vec::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 8 {
            return Err("WireGuard returned incomplete peer state.".into());
        }
        peers.push(WireguardPeerState {
            public_key: fields[0].into(),
            endpoint: fields[2].into(),
            allowed_ips: fields[3].split(',').map(str::to_string).collect(),
            latest_handshake_unix_seconds: fields[4].parse().unwrap_or(0),
        });
    }
    Ok(WireguardInspectResult {
        interface: interface.into(),
        public_key,
        listen_port,
        peers,
        applied_revision: 0,
        configuration_hash: String::new(),
        drifted: false,
    })
}

fn wireguard_state_matches(
    request: &WireguardReconcileRequest,
    observed: &WireguardInspectResult,
) -> bool {
    observed.interface == request.interface
        && !observed.public_key.is_empty()
        && observed.listen_port == request.listen_port
        && observed.peers.len() == request.peers.len()
        && request.peers.iter().all(|expected| {
            observed.peers.iter().any(|peer| {
                peer.public_key == expected.public_key && {
                    let mut observed = peer.allowed_ips.clone();
                    let mut expected = expected.allowed_ips.clone();
                    observed.sort();
                    expected.sort();
                    observed == expected
                }
            })
        })
}

fn validate_live_wireguard(request: &WireguardReconcileRequest) -> Result<(), String> {
    let output = Command::new("wg")
        .args(["show", &request.interface, "dump"])
        .output()
        .map_err(|_| "WireGuard health validation failed.".to_string())?;
    if !output.status.success() {
        return Err("WireGuard health validation failed.".into());
    }
    let observed = parse_wireguard_dump(&request.interface, &output.stdout)?;
    if !wireguard_state_matches(request, &observed) {
        return Err("WireGuard does not match the expected peer state.".into());
    }
    let address = Command::new("ip")
        .args(["-4", "-o", "address", "show", "dev", &request.interface])
        .output()
        .map_err(|_| "WireGuard address validation failed.".to_string())?;
    if !address.status.success()
        || !String::from_utf8_lossy(&address.stdout).contains(&format!("inet {}", request.address))
    {
        return Err("WireGuard does not have the expected address.".into());
    }
    Ok(())
}

pub(crate) fn reconcile_wireguard(
    root: &Path,
    request: &WireguardReconcileRequest,
) -> Result<WireguardReconcileResult, String> {
    validate_wireguard(request)?;
    let key_path = root
        .join("etc/coolify/network")
        .join(format!("{}.key", request.interface));
    let public_key = if root == Path::new("/") {
        ensure_key(root, &request.interface)?
    } else {
        String::new()
    };
    let private_key = fs::read_to_string(&key_path)
        .map_err(|_| "The WireGuard private key is missing.".to_string())?;
    let config = render_wireguard(request, private_key.trim())?;
    let configuration_hash = hash(config.as_bytes());
    let prior = read_applied_state(root, &request.interface);
    if prior
        .as_ref()
        .is_some_and(|state| state.0 == request.revision && state.1 == configuration_hash)
    {
        return Ok(WireguardReconcileResult {
            state: Some(if root == Path::new("/") {
                inspect_wireguard(
                    root,
                    &request.interface,
                    request.revision,
                    &configuration_hash,
                )
            } else {
                wireguard_state(request, public_key, configuration_hash, false)
            }),
            changed: false,
            rollback_cancelled: true,
        });
    }

    let config_path = root
        .join("etc/wireguard")
        .join(format!("{}.conf", request.interface));
    let last_good_path = state_path(root, &format!("{}.last-good.conf", request.interface));
    let had_current = config_path.exists();
    if had_current {
        let old = fs::read(&config_path)
            .map_err(|_| "The current WireGuard configuration could not be read.")?;
        atomic_write(&last_good_path, &old, 0o600)?;
    }
    let staged_path = staged_wireguard_path(root, &request.interface);
    atomic_write(&staged_path, config.as_bytes(), 0o600)?;
    if root == Path::new("/") {
        activate_wireguard(
            request,
            &staged_path,
            &config_path,
            &last_good_path,
            had_current,
        )?;
    } else {
        fs::rename(&staged_path, &config_path)
            .map_err(|_| "The staged WireGuard configuration could not be activated.")?;
    }
    atomic_write(&last_good_path, config.as_bytes(), 0o600)?;
    atomic_write(
        &state_path(root, &format!("{}.state", request.interface)),
        format!("{} {}\n", request.revision, configuration_hash).as_bytes(),
        0o600,
    )?;
    Ok(WireguardReconcileResult {
        state: Some(if root == Path::new("/") {
            inspect_wireguard(
                root,
                &request.interface,
                request.revision,
                &configuration_hash,
            )
        } else {
            wireguard_state(request, public_key, configuration_hash, false)
        }),
        changed: true,
        rollback_cancelled: true,
    })
}

fn wireguard_state(
    request: &WireguardReconcileRequest,
    public_key: String,
    configuration_hash: String,
    drifted: bool,
) -> WireguardInspectResult {
    WireguardInspectResult {
        interface: request.interface.clone(),
        public_key,
        listen_port: request.listen_port,
        peers: request
            .peers
            .iter()
            .map(|peer| WireguardPeerState {
                public_key: peer.public_key.clone(),
                endpoint: peer.endpoint.clone(),
                allowed_ips: peer.allowed_ips.clone(),
                latest_handshake_unix_seconds: 0,
            })
            .collect(),
        applied_revision: request.revision,
        configuration_hash,
        drifted,
    }
}

fn rollback_start_arguments(unit: &str) -> [&str; 3] {
    ["start", "--wait", unit]
}

fn activate_wireguard(
    request: &WireguardReconcileRequest,
    staged_path: &Path,
    config_path: &Path,
    last_good_path: &Path,
    had_current: bool,
) -> Result<(), String> {
    run(
        Command::new("wg-quick").arg("strip").arg(staged_path),
        "WireGuard validation failed.",
    )?;
    let rollback_unit = format!("coolify-network-rollback-{}", request.interface);
    let rollback_command = if had_current {
        format!(
            "cp '{}' '{}' && (wg-quick down '{}' >/dev/null 2>&1 || true) && wg-quick up '{}'",
            last_good_path.display(),
            config_path.display(),
            request.interface,
            request.interface
        )
    } else {
        format!(
            "wg-quick down '{}' >/dev/null 2>&1 || true; rm -f '{}'",
            request.interface,
            config_path.display()
        )
    };
    run(
        Command::new("systemd-run").args([
            "--unit",
            &rollback_unit,
            "--on-active=60s",
            "/bin/sh",
            "-c",
            &rollback_command,
        ]),
        "The WireGuard rollback could not be armed.",
    )?;
    fs::rename(staged_path, config_path)
        .map_err(|_| "The staged WireGuard configuration could not be activated.")?;
    let _ = Command::new("wg-quick")
        .args(["down", &request.interface])
        .status();
    let healthy = run(
        Command::new("wg-quick").args(["up", &request.interface]),
        "WireGuard activation failed.",
    )
    .and_then(|_| validate_live_wireguard(request))
    .and_then(|_| {
        if request.flux_probe_host.is_empty() {
            Ok(())
        } else {
            run(
                Command::new("ping").args(["-c", "1", "-W", "5", &request.flux_probe_host]),
                "Flux connectivity validation failed.",
            )
        }
    })
    .and_then(|_| {
        let peer_addresses = request
            .peers
            .iter()
            .filter_map(|peer| peer.allowed_ips.first().map(String::as_str))
            .collect::<Vec<_>>();
        configure_discovery_resolver(&request.interface, &request.address, &peer_addresses)
    });
    if healthy.is_err() {
        let rollback_service = format!("{rollback_unit}.service");
        let rollback = run(
            Command::new("systemctl").args(rollback_start_arguments(&rollback_service)),
            "WireGuard rollback failed.",
        )
        .and_then(|_| {
            let peer_addresses = request
                .peers
                .iter()
                .filter_map(|peer| peer.allowed_ips.first().map(String::as_str))
                .collect::<Vec<_>>();
            configure_discovery_resolver(&request.interface, &request.address, &peer_addresses)
        });
        let _ = Command::new("systemctl")
            .args(["stop", &format!("{rollback_unit}.timer")])
            .status();
        if rollback.is_err() {
            return Err("WireGuard activation and rollback failed.".into());
        }
        return Err("WireGuard activation failed and rollback was requested.".into());
    }
    run(
        Command::new("systemctl").args(["stop", &format!("{rollback_unit}.timer")]),
        "The WireGuard rollback could not be cancelled.",
    )
}

pub(crate) fn reconcile_firewall(
    root: &Path,
    request: &FirewallReconcileRequest,
) -> Result<FirewallReconcileResult, String> {
    let snapshot = render_firewall(request)?;
    let configuration_hash = hash(snapshot.as_bytes());
    let state_file = state_path(root, "firewall.state");
    let prior = read_state_file(&state_file);
    if prior
        .as_ref()
        .is_some_and(|state| state.0 == request.revision && state.1 == configuration_hash)
    {
        return Ok(FirewallReconcileResult {
            state: Some(firewall_state(request.revision, configuration_hash, false)),
            changed: false,
            rollback_cancelled: true,
        });
    }
    let snapshot_path = state_path(root, "firewall.nft");
    atomic_write(&snapshot_path, snapshot.as_bytes(), 0o600)?;
    if root == Path::new("/") {
        activate_firewall(root, &snapshot, &request.flux_probe_host)?;
    }
    atomic_write(
        &state_file,
        format!("{} {}\n", request.revision, configuration_hash).as_bytes(),
        0o600,
    )?;
    Ok(FirewallReconcileResult {
        state: Some(firewall_state(request.revision, configuration_hash, false)),
        changed: true,
        rollback_cancelled: true,
    })
}

fn nft_transaction(snapshot: &str, table_exists: bool) -> String {
    format!(
        "{}{}",
        if table_exists {
            format!("delete table inet {COOLIFY_NFT_TABLE}\n")
        } else {
            String::new()
        },
        snapshot
    )
}

fn activate_firewall(root: &Path, snapshot: &str, flux_probe_host: &str) -> Result<(), String> {
    let sysctl_path = root.join("etc/sysctl.d/90-coolify-workload-firewall.conf");
    atomic_write(
        &sysctl_path,
        b"net.ipv4.ip_forward=1\nnet.bridge.bridge-nf-call-iptables=1\n",
        0o644,
    )?;
    run(
        Command::new("modprobe").arg("br_netfilter"),
        "The bridge firewall module could not be loaded.",
    )?;
    run(
        Command::new("sysctl").arg("--load").arg(&sysctl_path),
        "The bridge firewall settings could not be activated.",
    )?;
    let current = Command::new("nft")
        .args(["list", "table", "inet", COOLIFY_NFT_TABLE])
        .output()
        .map_err(|_| "nftables is unavailable.")?;
    let table_exists = current.status.success();
    let last_good = state_path(root, "firewall.last-good.nft");
    if table_exists {
        atomic_write(&last_good, &current.stdout, 0o600)?;
    }
    let transaction_path = state_path(root, "firewall.transaction.nft");
    atomic_write(
        &transaction_path,
        nft_transaction(snapshot, table_exists).as_bytes(),
        0o600,
    )?;
    run(
        Command::new("nft")
            .args(["--check", "--file"])
            .arg(&transaction_path),
        "The firewall configuration is invalid.",
    )?;
    let rollback = if table_exists {
        format!(
            "nft delete table inet {COOLIFY_NFT_TABLE} >/dev/null 2>&1 || true; nft --file '{}'",
            last_good.display()
        )
    } else {
        format!("nft delete table inet {COOLIFY_NFT_TABLE} >/dev/null 2>&1 || true")
    };
    run(
        Command::new("systemd-run").args([
            "--unit",
            "coolify-firewall-rollback",
            "--on-active=60s",
            "/bin/sh",
            "-c",
            &rollback,
        ]),
        "The firewall rollback could not be armed.",
    )?;
    let activated = run(
        Command::new("nft").arg("--file").arg(&transaction_path),
        "The firewall configuration could not be activated.",
    )
    .and_then(|_| {
        run(
            Command::new("nft").args(["list", "table", "inet", COOLIFY_NFT_TABLE]),
            "The Coolify firewall table is not active.",
        )
    })
    .and_then(|_| {
        if flux_probe_host.is_empty() {
            Ok(())
        } else {
            run(
                Command::new("ping").args(["-c", "1", "-W", "5", flux_probe_host]),
                "Flux connectivity validation failed.",
            )
        }
    });
    if let Err(error) = activated {
        let rollback = run(
            Command::new("systemctl").args(rollback_start_arguments(
                "coolify-firewall-rollback.service",
            )),
            "Firewall rollback failed.",
        );
        let _ = Command::new("systemctl")
            .args(["stop", "coolify-firewall-rollback.timer"])
            .status();
        if rollback.is_err() {
            return Err("Firewall activation and rollback failed.".into());
        }
        return Err(error);
    }
    run(
        Command::new("systemctl").args(["stop", "coolify-firewall-rollback.timer"]),
        "The firewall rollback could not be cancelled.",
    )?;
    atomic_write(&last_good, snapshot.as_bytes(), 0o600)
}

pub(crate) fn inspect_firewall(
    root: &Path,
    expected_revision: u64,
    expected_hash: &str,
) -> FirewallInspectResult {
    let state = read_state_file(&state_path(root, "firewall.state"));
    FirewallInspectResult {
        applied_revision: state.as_ref().map_or(0, |state| state.0),
        configuration_hash: state
            .as_ref()
            .map_or_else(String::new, |state| state.1.clone()),
        drifted: state
            .as_ref()
            .is_none_or(|state| state.0 != expected_revision || state.1 != expected_hash),
        table: COOLIFY_NFT_TABLE.into(),
    }
}

fn firewall_state(
    revision: u64,
    configuration_hash: String,
    drifted: bool,
) -> FirewallInspectResult {
    FirewallInspectResult {
        applied_revision: revision,
        configuration_hash,
        drifted,
        table: COOLIFY_NFT_TABLE.into(),
    }
}

pub(crate) fn reconcile_corrosion(
    root: &Path,
    request: &CorrosionReconcileRequest,
) -> Result<CorrosionReconcileResult, String> {
    if request.version != CORROSION_VERSION {
        return Err(format!(
            "Corrosion must use the tested version {CORROSION_VERSION}."
        ));
    }
    let config = render_corrosion(request)?;
    let config_path = root.join("etc/corrosion/config.toml");
    let changed = fs::read(&config_path).ok().as_deref() != Some(config.as_bytes());
    atomic_write(&config_path, config.as_bytes(), 0o644)?;
    atomic_write(
        &root.join("etc/corrosion/schemas/coolify.sql"),
        corrosion_schema().as_bytes(),
        0o644,
    )?;
    atomic_write(
        &root.join("etc/systemd/system/corrosion.service"),
        corrosion_unit().as_bytes(),
        0o644,
    )?;
    let cluster_id = corrosion_cluster_id(&request.cluster_id)?;
    atomic_write(
        &root.join("etc/corrosion/coolify-owner"),
        format!("{}\n", request.bind_address).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &root.join("etc/corrosion/coolify-cluster-id"),
        format!("{cluster_id}\n").as_bytes(),
        0o644,
    )?;
    atomic_write(
        &root.join("etc/corrosion/coolify-peer-count"),
        format!("{}\n", request.peers.len()).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &root.join("etc/systemd/system/coolify-discovery-dns.service"),
        corrosion_dns_unit(&request.bind_address)?.as_bytes(),
        0o644,
    )?;
    if root == Path::new("/") {
        install_corrosion(request.version.as_str())?;
        ensure_discovery_dns_user()?;
        run(
            Command::new("systemctl").arg("daemon-reload"),
            "Systemd could not reload Corrosion.",
        )?;
        run(
            Command::new("systemctl").args(["enable", "corrosion.service"]),
            "Corrosion could not be enabled.",
        )?;
        run(
            Command::new("systemctl").args(["restart", "corrosion.service"]),
            "Corrosion could not start.",
        )?;
        run(
            Command::new("systemctl").args(["is-active", "--quiet", "corrosion.service"]),
            "Corrosion did not become active.",
        )?;
        set_corrosion_cluster_id(cluster_id)?;
        run(
            Command::new("systemctl").args(["restart", "corrosion.service"]),
            "Corrosion could not restart after its cluster ID was set.",
        )?;
        run(
            Command::new("systemctl").args(["enable", "--now", "coolify-discovery-dns.service"]),
            "The Coolify discovery DNS service could not start.",
        )?;
        run(
            Command::new("systemctl").args([
                "is-active",
                "--quiet",
                "coolify-discovery-dns.service",
            ]),
            "The Coolify discovery DNS service did not become active.",
        )?;
        let peer_addresses = request
            .peers
            .iter()
            .filter_map(|peer| peer.rsplit_once(':').map(|(address, _)| address))
            .collect::<Vec<_>>();
        configure_discovery_resolver("coolify0", &request.bind_address, &peer_addresses)?;
    }
    Ok(CorrosionReconcileResult {
        state: Some(inspect_corrosion(root)),
        changed,
    })
}

pub(crate) fn inspect_corrosion(root: &Path) -> CorrosionInspectResult {
    let configured = root.join("etc/corrosion/config.toml").exists();
    if !configured {
        return CorrosionInspectResult {
            version: String::new(),
            member_state: "absent".into(),
            endpoint_count: 0,
            last_convergence_unix_seconds: None,
        };
    }
    if root != Path::new("/") {
        return CorrosionInspectResult {
            version: CORROSION_VERSION.into(),
            member_state: "configured".into(),
            endpoint_count: 0,
            last_convergence_unix_seconds: None,
        };
    }

    let version = fs::read_to_string("/usr/local/bin/corrosion.version")
        .unwrap_or_default()
        .trim()
        .to_string();
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", "corrosion.service"])
        .status()
        .is_ok_and(|status| status.success());
    let cluster_id = read_trimmed_u64("/etc/corrosion/coolify-cluster-id")
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or_default();
    let peer_count = read_trimmed_u64("/etc/corrosion/coolify-peer-count").unwrap_or_default();
    let membership = active
        .then(|| {
            Command::new("/usr/local/bin/corrosion")
                .args([
                    "cluster",
                    "membership-states",
                    "--config",
                    "/etc/corrosion/config.toml",
                ])
                .output()
        })
        .transpose()
        .ok()
        .flatten();
    let converged = active
        && membership.as_ref().is_some_and(|output| {
            output.status.success()
                && corrosion_membership_converged(&output.stdout, cluster_id, peer_count)
        });
    let convergence_path = Path::new("/var/lib/coolify/network/corrosion.converged");
    if converged {
        let now = unix_seconds();
        let _ = atomic_write(convergence_path, format!("{now}\n").as_bytes(), 0o600);
    }
    let endpoint_count = corrosion_endpoint_count().unwrap_or_default();

    CorrosionInspectResult {
        version,
        member_state: if !active {
            "inactive".into()
        } else if converged {
            "converged".into()
        } else {
            "joining".into()
        },
        endpoint_count,
        last_convergence_unix_seconds: read_trimmed_u64(convergence_path)
            .and_then(|value| i64::try_from(value).ok()),
    }
}

fn read_trimmed_u64(path: impl AsRef<Path>) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn corrosion_membership_converged(output: &[u8], cluster_id: u16, peer_count: u64) -> bool {
    if cluster_id == 0 {
        return false;
    }
    if peer_count == 0 {
        return true;
    }
    let text = String::from_utf8_lossy(output);
    let expected_cluster = format!("\"cluster_id\": {cluster_id}");
    text.matches("\"state\": \"Alive\"").count() as u64 >= peer_count
        && text.matches(&expected_cluster).count() as u64 >= peer_count
}

fn corrosion_endpoint_count() -> Option<u64> {
    let output = Command::new("/usr/local/bin/corrosion")
        .args([
            "query",
            "--config",
            "/etc/corrosion/config.toml",
            "SELECT COUNT(*) FROM workload_endpoints WHERE expires_at > unixepoch()",
        ])
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

fn set_corrosion_cluster_id(cluster_id: u16) -> Result<(), String> {
    let cluster_id = cluster_id.to_string();
    let mut last_error = "Corrosion could not set its cluster ID.".to_string();
    for _ in 0..20 {
        match Command::new("/usr/local/bin/corrosion")
            .args([
                "cluster",
                "set-id",
                "--config",
                "/etc/corrosion/config.toml",
                &cluster_id,
            ])
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if !message.is_empty() {
                    last_error = message.chars().take(2_000).collect();
                }
            }
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    Err(last_error)
}

fn discovery_resolver_commands(
    interface: &str,
    address: &str,
    peer_addresses: &[&str],
) -> Result<Vec<Vec<String>>, String> {
    validate_interface(interface)?;
    let bind_address = address.strip_suffix("/32").unwrap_or(address);
    let bind_address = bind_address
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .filter(|address| !address.is_unspecified())
        .ok_or("The discovery DNS address is invalid.")?
        .to_string();

    let mut addresses = peer_addresses
        .iter()
        .copied()
        .chain(std::iter::once(bind_address.as_str()))
        .filter_map(|address| address.strip_suffix("/32").unwrap_or(address).parse().ok())
        .collect::<Vec<std::net::Ipv4Addr>>();
    addresses.sort_unstable();
    addresses.dedup();
    let reverse_zones = addresses.into_iter().map(|address| {
        let octets = address.octets();
        format!(
            "~{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )
    });

    Ok(vec![
        vec!["dns".into(), interface.into(), bind_address],
        std::iter::once("domain".into())
            .chain(std::iter::once(interface.into()))
            .chain(std::iter::once("~coolify.internal".into()))
            .chain(reverse_zones)
            .collect(),
    ])
}

fn configure_discovery_resolver(
    interface: &str,
    address: &str,
    peer_addresses: &[&str],
) -> Result<(), String> {
    for arguments in discovery_resolver_commands(interface, address, peer_addresses)? {
        run(
            Command::new("resolvectl").args(arguments),
            "The Coolify discovery resolver could not be configured.",
        )?;
    }

    Ok(())
}

fn corrosion_schema() -> &'static str {
    "CREATE TABLE IF NOT EXISTS workload_endpoints (workload_id TEXT NOT NULL, namespace TEXT NOT NULL, owner_node_ip TEXT NOT NULL, container_ip TEXT NOT NULL, state TEXT NOT NULL DEFAULT '', health TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (namespace, workload_id, owner_node_ip, container_ip));\n"
}

fn corrosion_unit() -> &'static str {
    "[Unit]\nDescription=Coolify Corrosion discovery\nAfter=network-online.target\nWants=network-online.target\n[Service]\nExecStart=/usr/local/bin/corrosion agent --config /etc/corrosion/config.toml\nUser=corrosion\nGroup=corrosion\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nStateDirectory=corrosion\nRuntimeDirectory=corrosion\nReadWritePaths=/var/lib/corrosion /run/corrosion\nRestart=on-failure\nRestartSec=2s\n[Install]\nWantedBy=multi-user.target\n"
}

fn corrosion_dns_unit(bind_address: &str) -> Result<String, String> {
    if bind_address.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("The Corrosion DNS bind address is invalid.".into());
    }
    Ok(format!(
        "[Unit]\nDescription=Coolify internal discovery DNS\nAfter=corrosion.service\nRequires=corrosion.service\n[Service]\nExecStart=/usr/local/bin/sentinel discovery-dns --bind {bind_address}:53 --zone coolify.internal --corrosion-config /etc/corrosion/config.toml\nUser=coolify-dns\nGroup=coolify-dns\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nRestart=on-failure\nRestartSec=2s\n[Install]\nWantedBy=multi-user.target\n"
    ))
}

fn corrosion_download(version: &str, architecture: &str) -> Result<String, String> {
    let target = match architecture.trim() {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => return Err("The host architecture is not supported by Corrosion.".into()),
    };
    Ok(format!(
        "https://github.com/superfly/corrosion/releases/download/{version}/corrosion-{target}.tar.gz"
    ))
}

fn install_corrosion(version: &str) -> Result<(), String> {
    if fs::read_to_string("/usr/local/bin/corrosion.version")
        .ok()
        .is_some_and(|installed| installed.trim() == version)
        && Path::new("/usr/local/bin/corrosion").exists()
    {
        return Ok(());
    }
    let architecture = Command::new("uname")
        .arg("-m")
        .output()
        .map_err(|_| "The host architecture could not be detected.")?;
    let url = corrosion_download(version, &String::from_utf8_lossy(&architecture.stdout))?;
    let directory = PathBuf::from(format!(
        "/var/lib/coolify/downloads/corrosion-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)
        .map_err(|_| "The Corrosion download directory could not be created.")?;
    let archive = directory.join("corrosion.tar.gz");
    run(
        Command::new("curl")
            .args(["-fsSL", "--retry", "3", "--max-time", "120", "-o"])
            .arg(&archive)
            .arg(&url),
        "Corrosion could not be downloaded.",
    )?;
    run(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&directory),
        "Corrosion could not be extracted.",
    )?;
    run(
        Command::new("install")
            .args(["-m", "0755"])
            .arg(directory.join("corrosion"))
            .arg("/usr/local/bin/corrosion"),
        "Corrosion could not be installed.",
    )?;
    atomic_write(
        Path::new("/usr/local/bin/corrosion.version"),
        format!("{version}\n").as_bytes(),
        0o644,
    )?;
    if !Command::new("id")
        .args(["-u", "corrosion"])
        .status()
        .is_ok_and(|status| status.success())
    {
        run(
            Command::new("useradd").args([
                "--system",
                "--home",
                "/var/lib/corrosion",
                "--shell",
                "/usr/sbin/nologin",
                "corrosion",
            ]),
            "The Corrosion service user could not be created.",
        )?;
    }
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

fn ensure_discovery_dns_user() -> Result<(), String> {
    if Command::new("id")
        .args(["-u", "coolify-dns"])
        .status()
        .is_ok_and(|status| status.success())
    {
        return Ok(());
    }
    run(
        Command::new("useradd").args([
            "--system",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "coolify-dns",
        ]),
        "The Coolify discovery DNS service user could not be created.",
    )
}

fn run(command: &mut Command, fallback: &str) -> Result<(), String> {
    let output = command.output().map_err(|_| fallback.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(2_000)
        .collect::<String>();
    Err(if message.is_empty() {
        fallback.into()
    } else {
        message
    })
}

fn read_state_file(path: &Path) -> Option<(u64, String)> {
    let contents = fs::read_to_string(path).ok()?;
    let (revision, hash) = contents.trim().split_once(' ')?;
    Some((revision.parse().ok()?, hash.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::control::v1::{FirewallRule, WireguardPeer};

    #[test]
    fn renders_deterministic_full_mesh_without_peer_secrets() {
        let request = WireguardReconcileRequest {
            interface: "coolify0".into(),
            address: "10.240.0.2/32".into(),
            listen_port: 51820,
            revision: 1,
            peers: vec![WireguardPeer {
                public_key: "b".into(),
                endpoint: "192.0.2.2:51820".into(),
                allowed_ips: vec!["10.240.0.3/32".into()],
                persistent_keepalive_seconds: 25,
            }],
            flux_probe_host: "10.240.0.1".into(),
        };
        let rendered = render_wireguard(&request, "private").unwrap();
        assert!(rendered.contains("Address = 10.240.0.2/32"));
        assert!(rendered.contains("AllowedIPs = 10.240.0.3/32"));
        assert!(!rendered.contains("PrivateKey = b"));
    }

    #[test]
    fn firewall_output_is_scoped_to_the_coolify_table() {
        let rendered = render_firewall(&FirewallReconcileRequest {
            revision: 1,
            wireguard_port: 51820,
            cluster_cidr: "10.240.0.0/24".into(),
            rules: vec![FirewallRule {
                source_ip: "100.64.0.2".into(),
                destination_ip: "100.64.1.2".into(),
                protocol: "tcp".into(),
                port: 5432,
            }],
            wireguard_interface: "coolify0".into(),
            workload_cidrs: vec!["100.64.0.0/24".into(), "100.64.1.0/24".into()],
            flux_probe_host: "10.240.0.1".into(),
        })
        .unwrap();
        assert!(rendered.contains("table inet coolify_cluster"));
        assert!(!rendered.contains("flush ruleset"));
        assert!(!rendered.contains("delete table"));
        assert!(rendered.contains("ip saddr @workload_networks ip daddr @workload_networks drop"));
        assert!(rendered.contains("ip saddr 100.64.0.2 ip daddr 100.64.1.2 tcp dport 5432 accept"));
        assert!(rendered.contains("policy accept"));
    }

    #[test]
    fn atomic_writes_keep_mode_and_replace_content() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config");
        atomic_write(&path, b"first", 0o600).unwrap();
        atomic_write(&path, b"second", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn generates_a_private_key_with_strict_permissions_and_returns_only_the_public_key() {
        let temp = tempfile::tempdir().unwrap();
        let wireguard = temp.path().join("wg");
        fs::write(&wireguard, "#!/bin/sh\nif [ \"$1\" = genkey ]; then echo private-secret; else cat >/dev/null; echo public-only; fi\n").unwrap();
        fs::set_permissions(&wireguard, fs::Permissions::from_mode(0o700)).unwrap();
        let public = ensure_key_with_binary(temp.path(), "coolify0", &wireguard).unwrap();
        let key = temp.path().join("etc/coolify/network/coolify0.key");
        assert_eq!(public, "public-only");
        assert_eq!(fs::read_to_string(&key).unwrap().trim(), "private-secret");
        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn wireguard_reconciliation_is_atomic_and_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let key = temp.path().join("etc/coolify/network/coolify0.key");
        atomic_write(&key, b"private-secret", 0o600).unwrap();
        let request = WireguardReconcileRequest {
            interface: "coolify0".into(),
            address: "10.240.0.2/32".into(),
            listen_port: 51820,
            revision: 7,
            peers: vec![WireguardPeer {
                public_key: "peer-public".into(),
                endpoint: "192.0.2.2:51820".into(),
                allowed_ips: vec!["10.240.0.3/32".into()],
                persistent_keepalive_seconds: 25,
            }],
            flux_probe_host: String::new(),
        };
        let first = reconcile_wireguard(temp.path(), &request).unwrap();
        let second = reconcile_wireguard(temp.path(), &request).unwrap();
        assert!(first.changed);
        assert!(!second.changed);
        assert!(first.rollback_cancelled && second.rollback_cancelled);
        assert_eq!(first.state.as_ref().unwrap().peers.len(), 1);
        assert_eq!(second.state.as_ref().unwrap().peers.len(), 1);
        assert_eq!(
            fs::metadata(temp.path().join("etc/wireguard/coolify0.conf"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!format!("{first:?}").contains("private-secret"));
    }

    #[test]
    fn wireguard_stage_keeps_a_valid_wg_quick_filename() {
        let staged = staged_wireguard_path(Path::new("/"), "coolify0");

        assert_eq!(
            staged,
            Path::new("/etc/wireguard/.coolify-stage/coolify0.conf")
        );
    }

    #[test]
    fn wireguard_health_requires_the_complete_expected_peer_state() {
        let request = WireguardReconcileRequest {
            interface: "coolify0".into(),
            address: "10.240.0.2/32".into(),
            listen_port: 51820,
            revision: 7,
            peers: vec![WireguardPeer {
                public_key: "peer-public".into(),
                endpoint: "192.0.2.2:51820".into(),
                allowed_ips: vec!["10.240.0.3/32".into()],
                persistent_keepalive_seconds: 25,
            }],
            flux_probe_host: "192.0.2.1".into(),
        };
        let mut observed = WireguardInspectResult {
            interface: "coolify0".into(),
            public_key: "local-public".into(),
            listen_port: 51820,
            peers: vec![WireguardPeerState {
                public_key: "peer-public".into(),
                endpoint: "192.0.2.2:51820".into(),
                allowed_ips: vec!["10.240.0.3/32".into()],
                latest_handshake_unix_seconds: 0,
            }],
            applied_revision: 0,
            configuration_hash: String::new(),
            drifted: false,
        };

        assert!(wireguard_state_matches(&request, &observed));
        observed.peers[0].allowed_ips = vec!["10.240.0.99/32".into()];
        assert!(!wireguard_state_matches(&request, &observed));
        observed.peers[0].allowed_ips = vec!["10.240.0.3/32".into()];
        observed.listen_port = 51821;
        assert!(!wireguard_state_matches(&request, &observed));
        observed.listen_port = 51820;
        observed.peers.clear();
        assert!(!wireguard_state_matches(&request, &observed));
    }

    #[test]
    fn discovery_resolver_configuration_tracks_a_recreated_wireguard_link() {
        let commands = discovery_resolver_commands(
            "mesh0",
            "10.0.0.130/32",
            &["10.0.0.129/32", "10.0.0.131/32"],
        )
        .unwrap();

        assert_eq!(
            commands,
            vec![
                vec!["dns", "mesh0", "10.0.0.130"],
                vec![
                    "domain",
                    "mesh0",
                    "~coolify.internal",
                    "~129.0.0.10.in-addr.arpa",
                    "~130.0.0.10.in-addr.arpa",
                    "~131.0.0.10.in-addr.arpa",
                ],
            ]
        );
    }

    #[test]
    fn transient_rollbacks_are_started_synchronously() {
        assert_eq!(
            rollback_start_arguments("coolify-network-rollback-mesh0.service"),
            ["start", "--wait", "coolify-network-rollback-mesh0.service"]
        );
    }

    #[test]
    fn firewall_reconciliation_never_changes_unrelated_rules() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = temp.path().join("etc/nftables.conf");
        fs::create_dir_all(unrelated.parent().unwrap()).unwrap();
        fs::write(&unrelated, "table inet user_owned {}\n").unwrap();
        let request = FirewallReconcileRequest {
            revision: 3,
            wireguard_port: 51820,
            cluster_cidr: "10.240.0.0/24".into(),
            rules: vec![],
            wireguard_interface: "coolify0".into(),
            flux_probe_host: String::new(),
            workload_cidrs: vec!["100.64.0.0/24".into()],
        };
        let first = reconcile_firewall(temp.path(), &request).unwrap();
        let second = reconcile_firewall(temp.path(), &request).unwrap();
        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(
            fs::read_to_string(unrelated).unwrap(),
            "table inet user_owned {}\n"
        );
        assert!(
            !fs::read_to_string(state_path(temp.path(), "firewall.nft"))
                .unwrap()
                .contains("flush ruleset")
        );
        let transaction = nft_transaction(&render_firewall(&request).unwrap(), true);
        assert!(transaction.starts_with("delete table inet coolify_cluster"));
        assert!(!transaction.contains("flush ruleset"));
        assert!(!transaction.contains("user_owned"));
    }

    #[test]
    fn corrosion_configuration_is_pinned_bound_and_hardened() {
        let temp = tempfile::tempdir().unwrap();
        let request = CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: "cluster-one".into(),
            bind_address: "10.240.0.2".into(),
            peers: vec!["10.240.0.3:8787".into()],
        };
        let result = reconcile_corrosion(temp.path(), &request).unwrap();
        assert!(result.changed);
        let config = fs::read_to_string(temp.path().join("etc/corrosion/config.toml")).unwrap();
        let unit =
            fs::read_to_string(temp.path().join("etc/systemd/system/corrosion.service")).unwrap();
        let schema =
            fs::read_to_string(temp.path().join("etc/corrosion/schemas/coolify.sql")).unwrap();
        assert!(config.contains("10.240.0.2:8787") && config.contains("10.240.0.2:8080"));
        assert!(unit.contains("NoNewPrivileges=true") && unit.contains("ProtectSystem=strict"));
        assert!(!unit.contains("wg-quick@coolify0.service"));
        assert!(schema.contains("owner_node_ip") && schema.contains("expires_at"));
        assert!(schema.contains("state TEXT NOT NULL DEFAULT ''"));
        assert!(schema.contains("health TEXT NOT NULL DEFAULT ''"));
        assert!(schema.contains("updated_at INTEGER NOT NULL DEFAULT 0"));
        assert!(schema.contains("expires_at INTEGER NOT NULL DEFAULT 0"));
    }

    #[test]
    fn corrosion_configuration_rejects_non_ip_bindings_and_peer_injection() {
        let mut request = CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: "cluster-one".into(),
            bind_address: "0.0.0.0".into(),
            peers: vec!["10.240.0.3:8787".into()],
        };
        assert!(render_corrosion(&request).is_err());

        request.bind_address = "10.240.0.2".into();
        request.peers = vec!["10.240.0.3:8787\"\nplaintext = false".into()];
        assert!(render_corrosion(&request).is_err());
    }

    #[test]
    fn corrosion_download_is_pinned_to_the_tested_release_and_architecture() {
        assert_eq!(
            corrosion_download(CORROSION_VERSION, "x86_64").unwrap(),
            "https://github.com/superfly/corrosion/releases/download/v1.0.0/corrosion-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert!(corrosion_download(CORROSION_VERSION, "unknown").is_err());
    }

    #[test]
    fn corrosion_cluster_id_is_stable_nonzero_and_bounded() {
        let first = corrosion_cluster_id("cluster-one").unwrap();
        let second = corrosion_cluster_id("cluster-one").unwrap();

        assert_eq!(first, second);
        assert_ne!(first, 0);
        assert!(corrosion_cluster_id("").is_err());
    }

    #[test]
    fn corrosion_endpoint_snapshot_is_owned_and_atomic() {
        let request = CorrosionEndpointReconcileRequest {
            owner_node_ip: "10.240.0.2".into(),
            endpoints: vec![WorkloadEndpoint {
                workload_id: "web".into(),
                namespace: "default".into(),
                owner_node_ip: "10.240.0.2".into(),
                container_ip: "10.240.0.2".into(),
                state: "running".into(),
                health: "healthy".into(),
                updated_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_300,
            }],
        };

        let transaction = corrosion_endpoint_transaction(&request, "10.240.0.2").unwrap();

        assert_eq!(
            transaction[0][0],
            "DELETE FROM workload_endpoints WHERE owner_node_ip = ?"
        );
        assert_eq!(transaction[0][1][0], "10.240.0.2");
        assert_eq!(transaction.len(), 2);
        assert!(
            transaction[1][0]
                .as_str()
                .unwrap()
                .starts_with("INSERT INTO workload_endpoints")
        );
    }

    #[test]
    fn corrosion_endpoint_snapshot_rejects_another_nodes_rows() {
        let request = CorrosionEndpointReconcileRequest {
            owner_node_ip: "10.240.0.2".into(),
            endpoints: vec![WorkloadEndpoint {
                workload_id: "web".into(),
                namespace: "default".into(),
                owner_node_ip: "10.240.0.3".into(),
                container_ip: "10.240.0.3".into(),
                state: "running".into(),
                health: "healthy".into(),
                updated_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_300,
            }],
        };

        assert!(corrosion_endpoint_transaction(&request, "10.240.0.2").is_err());
        assert!(corrosion_endpoint_transaction(&request, "10.240.0.3").is_err());
    }

    #[test]
    fn corrosion_membership_requires_every_expected_peer_and_cluster() {
        let output = br#"{
          "id": {"addr": "10.240.0.3:8787", "cluster_id": 42},
          "state": "Alive"
        }"#;

        assert!(corrosion_membership_converged(output, 42, 1));
        assert!(!corrosion_membership_converged(output, 43, 1));
        assert!(!corrosion_membership_converged(output, 42, 2));
    }

    #[test]
    fn corrosion_dns_unit_binds_only_to_the_node_wireguard_ip() {
        let unit = corrosion_dns_unit("10.240.0.2").unwrap();

        assert!(unit.contains("discovery-dns --bind 10.240.0.2:53"));
        assert!(!unit.contains("0.0.0.0"));
        assert!(unit.contains("NoNewPrivileges=true"));
    }

    #[test]
    fn observed_wireguard_state_discards_the_private_and_preshared_keys() {
        let state = parse_wireguard_dump("coolify0", b"private-secret\tpublic-local\t51820\toff\npeer-public\tpreshared-secret\t192.0.2.2:51820\t10.240.0.3/32\t1234\t5\t7\t25\n").unwrap();
        assert_eq!(state.public_key, "public-local");
        assert_eq!(state.peers[0].latest_handshake_unix_seconds, 1234);
        let visible = format!("{state:?}");
        assert!(!visible.contains("private-secret"));
        assert!(!visible.contains("preshared-secret"));
    }
}
