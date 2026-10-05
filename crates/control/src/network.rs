use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sentinel_protocol::control::v1::{
    ClusterLeaveRequest, ClusterLeaveResult, CorrosionInspectResult, CorrosionReconcileRequest,
    CorrosionReconcileResult, FirewallInspectResult, FirewallReconcileRequest,
    FirewallReconcileResult, WireguardInspectResult, WireguardPeer, WireguardPeerState,
    WireguardReconcileRequest, WireguardReconcileResult,
};
use sha2::{Digest, Sha256};

const COOLIFY_NFT_TABLE: &str = "coolify_cluster";
const COOLIFY_NFT_BRIDGE_TABLE: &str = "coolify_cluster_bridge";
const BRIDGE_SYSCTL_FILE: &str = "etc/sysctl.d/90-coolify-workload-firewall.conf";
pub(crate) const CORROSION_VERSION: &str = "v1.0.0";
/// The Node WireGuard IP that owns this Node's discovery rows and serves its Corrosion API.
pub(crate) const CORROSION_OWNER_FILE: &str = "etc/corrosion/coolify-owner";
/// The Node DNS label published as `<name>.nodes.coolify.internal`.
pub(crate) const CORROSION_NODE_NAME_FILE: &str = "etc/corrosion/coolify-node-name";

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

pub(crate) fn validate_cluster_leave(request: &ClusterLeaveRequest) -> Result<(), String> {
    validate_interface(&request.interface)?;
    request
        .owner_node_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "The Node owner address is invalid.".to_string())?;
    if request.workload_cidrs.len() > 100
        || request
            .workload_cidrs
            .iter()
            .any(|cidr| !valid_ipv4_cidr(cidr))
    {
        return Err("A workload CIDR is invalid.".into());
    }
    Ok(())
}

pub(crate) fn leave_cluster(
    root: &Path,
    request: &ClusterLeaveRequest,
) -> Result<ClusterLeaveResult, String> {
    validate_cluster_leave(request)?;
    // Hold the publisher lock so no endpoint publish can run between withdrawing
    // this Node's rows and removing the identity files that enable publishing.
    let _publisher = crate::discovery::publisher_lock();
    // The ingress uses the cluster network, so it leaves with it. Its routes in
    // Corrosion stay: they belong to the cluster, not to this Node.
    {
        let _ingress = crate::ingress::ingress_lock();
        crate::ingress::remove(root)?;
    }

    if root == Path::new("/") {
        match crate::discovery::withdraw_endpoints(&request.owner_node_ip) {
            // Give Corrosion a moment to broadcast the deletion before it stops;
            // rows that do not propagate still expire within the endpoint TTL.
            Ok(()) => std::thread::sleep(std::time::Duration::from_secs(2)),
            Err(message) => {
                tracing::warn!(error = %message, "could not withdraw this Node's discovery endpoints before leaving the cluster");
            }
        }
        let _ = Command::new("resolvectl")
            .args(["revert", &request.interface])
            .status();
        for unit in ["coolify-discovery-dns.service", "corrosion.service"] {
            let _ = Command::new("systemctl")
                .args(["disable", "--now", unit])
                .status();
        }
        let _ = Command::new("wg-quick")
            .args(["down", &request.interface])
            .status();
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", COOLIFY_NFT_TABLE])
            .status();
        let _ = Command::new("nft")
            .args(["delete", "table", "bridge", COOLIFY_NFT_BRIDGE_TABLE])
            .status();
        for cidr in &request.workload_cidrs {
            let _ = Command::new("iptables")
                .args(["-t", "nat", "-D", "POSTROUTING"])
                .args(mesh_nat_rule_arguments(&request.interface, cidr))
                .status();
        }
    }

    let managed_files = [
        root.join("etc/wireguard")
            .join(format!("{}.conf", request.interface)),
        state_path(root, &format!("{}.state", request.interface)),
        state_path(root, &format!("{}.last-good.conf", request.interface)),
        state_path(root, &format!("{}.key", request.interface)),
        state_path(root, "firewall.state"),
        state_path(root, "firewall.nft"),
        state_path(root, "firewall.last-good.nft"),
        state_path(root, "firewall.transaction.nft"),
        root.join("etc/corrosion/config.toml"),
        root.join("etc/corrosion/schemas/coolify.sql"),
        root.join(CORROSION_OWNER_FILE),
        root.join(CORROSION_NODE_NAME_FILE),
        root.join("etc/corrosion/coolify-cluster-id"),
        root.join("etc/corrosion/coolify-peer-count"),
        root.join("etc/systemd/system/corrosion.service"),
        root.join("etc/systemd/system/coolify-discovery-dns.service"),
    ];
    for path in managed_files {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("A managed cluster network file could not be removed.".into()),
        }
    }
    let corrosion_state = root.join("var/lib/corrosion");
    match fs::remove_dir_all(corrosion_state) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("The Corrosion state could not be removed.".into()),
    }
    if root == Path::new("/") {
        run(
            Command::new("systemctl").arg("daemon-reload"),
            "Systemd could not reload after cluster cleanup.",
        )?;
        if Command::new("ip")
            .args(["link", "show", "dev", &request.interface])
            .status()
            .is_ok_and(|status| status.success())
        {
            return Err("The WireGuard interface is still active after cleanup.".into());
        }
    }

    Ok(ClusterLeaveResult {
        wireguard_removed: true,
        firewall_removed: true,
        discovery_removed: true,
        resolver_reverted: true,
    })
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
        || !ipv4_in_cidr(&request.local_node_ip, &request.cluster_cidr)
        || validate_interface(&request.wireguard_interface).is_err()
        || request.workload_cidrs.is_empty()
        || request.workload_cidrs.len() > 10_000
        || request
            .workload_cidrs
            .iter()
            .any(|cidr| !valid_ipv4_cidr(cidr))
        || request.rules.len() > 100_000
        || request.ingress_rules.len() > 100_000
        || request.rules.iter().any(|rule| {
            rule.source_ip.parse::<std::net::Ipv4Addr>().is_err()
                || rule.destination_ip.parse::<std::net::Ipv4Addr>().is_err()
                || match rule.protocol.as_str() {
                    "tcp" | "udp" => rule.port == 0,
                    "icmp" => rule.port != 0,
                    _ => true,
                }
                || (!request
                    .workload_cidrs
                    .iter()
                    .any(|cidr| ipv4_in_cidr(&rule.source_ip, cidr))
                    && !ipv4_in_cidr(&rule.source_ip, &request.cluster_cidr))
                || !request
                    .workload_cidrs
                    .iter()
                    .any(|cidr| ipv4_in_cidr(&rule.destination_ip, cidr))
        })
        || request.ingress_rules.iter().any(|rule| {
            rule.destination_ip.parse::<std::net::Ipv4Addr>().is_err()
                || !matches!(rule.protocol.as_str(), "tcp" | "udp")
                || rule.port == 0
                || rule.port > 65_535
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
        .iter()
        .map(|rule| {
            if rule.protocol == "icmp" {
                format!(
                    "ip saddr {} ip daddr {} ip protocol icmp accept;",
                    rule.source_ip, rule.destination_ip
                )
            } else {
                format!(
                    "ip saddr {} ip daddr {} {} dport {} accept;",
                    rule.source_ip, rule.destination_ip, rule.protocol, rule.port
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let bridge_allow_rules = rules
        .iter()
        .filter(|rule| {
            request
                .workload_cidrs
                .iter()
                .any(|cidr| ipv4_in_cidr(&rule.source_ip, cidr))
        })
        .map(|rule| {
            if rule.protocol == "icmp" {
                format!(
                    "ip saddr {} ip daddr {} ip protocol icmp accept;",
                    rule.source_ip, rule.destination_ip
                )
            } else {
                format!(
                    "ip saddr {} ip daddr {} {} dport {} accept;",
                    rule.source_ip, rule.destination_ip, rule.protocol, rule.port
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let output_allow_rules = rules
        .iter()
        .filter(|rule| rule.source_ip == request.local_node_ip)
        .map(|rule| {
            if rule.protocol == "icmp" {
                format!("ip daddr {} ip protocol icmp accept;", rule.destination_ip)
            } else {
                format!(
                    "ip daddr {} {} dport {} accept;",
                    rule.destination_ip, rule.protocol, rule.port
                )
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut ingress_rules = request.ingress_rules.clone();
    ingress_rules.sort_by(|left, right| {
        (&left.destination_ip, &left.protocol, left.port).cmp(&(
            &right.destination_ip,
            &right.protocol,
            right.port,
        ))
    });
    let forward_ingress_rules = ingress_rules
        .iter()
        .map(|rule| {
            format!(
                "ip saddr != @workload_networks ip daddr {} {} dport {} accept;",
                rule.destination_ip, rule.protocol, rule.port
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let output_ingress_rules = ingress_rules
        .iter()
        .map(|rule| {
            format!(
                "ip daddr {} {} dport {} accept;",
                rule.destination_ip, rule.protocol, rule.port
            )
        })
        .collect::<Vec<_>>()
        .join(" ");

    let local_node_ip = &request.local_node_ip;

    Ok(format!(
        "table inet {COOLIFY_NFT_TABLE} {{
 set workload_networks {{ type ipv4_addr; flags interval; elements = {{ {elements} }} }}
 chain input {{ type filter hook input priority -5; policy accept; ct state established,related accept; udp dport {} accept; ip saddr @workload_networks udp dport 53 accept; ip saddr @workload_networks tcp dport 53 accept; ip saddr {} udp dport 8787 accept; ip saddr {local_node_ip} ip daddr {local_node_ip} udp dport 53 accept; ip saddr {local_node_ip} ip daddr {local_node_ip} tcp dport 53 accept; ip saddr {local_node_ip} ip daddr {local_node_ip} tcp dport 8080 accept; ip saddr {} drop; iifname \"{}\" ip saddr != {} ip saddr != @workload_networks drop; ip saddr @workload_networks drop; }}
 chain forward {{ type filter hook forward priority -5; policy accept; ct state established,related accept; {allow_rules} {forward_ingress_rules} ip saddr @workload_networks ip daddr @workload_networks drop; ip saddr @workload_networks ip daddr {} drop; ip saddr != @workload_networks ip daddr @workload_networks drop; }}
 chain output {{ type filter hook output priority -5; policy accept; ct state established,related accept; ip daddr {} udp dport 8787 accept; ip daddr {local_node_ip} udp dport 53 accept; ip daddr {local_node_ip} tcp dport 53 accept; ip daddr {local_node_ip} tcp dport 8080 accept; {output_allow_rules} {output_ingress_rules} ip daddr {} drop; ip daddr @workload_networks drop; }}
}}
table bridge {COOLIFY_NFT_BRIDGE_TABLE} {{
 set workload_networks {{ type ipv4_addr; flags interval; elements = {{ {elements} }} }}
 chain forward {{ type filter hook forward priority -200; policy accept; meta protocol != ip accept; ct state established,related accept; {bridge_allow_rules} ip saddr @workload_networks ip daddr @workload_networks drop; }}
}}
",
        request.wireguard_port,
        request.cluster_cidr,
        request.cluster_cidr,
        request.wireguard_interface,
        request.cluster_cidr,
        request.cluster_cidr,
        request.cluster_cidr,
        request.cluster_cidr
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
    if !valid_discovery_label(&request.node_dns_name) {
        return Err("The Corrosion Node DNS name is invalid.".into());
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

pub(crate) fn valid_discovery_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
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
    let config_path = root
        .join("etc/wireguard")
        .join(format!("{}.conf", request.interface));
    let unchanged = prior.as_ref().is_some_and(|state| {
        state.1 == configuration_hash
            && (state.0 == request.revision
                || (fs::read(&config_path).ok().as_deref() == Some(config.as_bytes())
                    && (root != Path::new("/") || validate_live_wireguard(request).is_ok())))
    });
    if unchanged && firewall_tables_active(root) {
        // A new revision with the same configuration, such as a firewall-only change, keeps
        // the link: `wg-quick down` would cut the mesh and every cross-Node connection.
        if prior
            .as_ref()
            .is_some_and(|state| state.0 != request.revision)
        {
            atomic_write(
                &state_path(root, &format!("{}.state", request.interface)),
                format!("{} {}\n", request.revision, configuration_hash).as_bytes(),
                0o600,
            )?;
        }
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
            .flat_map(|peer| peer.allowed_ips.iter().map(String::as_str))
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
                .flat_map(|peer| peer.allowed_ips.iter().map(String::as_str))
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
        activate_firewall(root, &snapshot, request)?;
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

fn nft_transaction(snapshot: &str, inet_table_exists: bool, bridge_table_exists: bool) -> String {
    format!(
        "{}{}{}",
        if inet_table_exists {
            format!("delete table inet {COOLIFY_NFT_TABLE}\n")
        } else {
            String::new()
        },
        if bridge_table_exists {
            format!("delete table bridge {COOLIFY_NFT_BRIDGE_TABLE}\n")
        } else {
            String::new()
        },
        snapshot
    )
}

fn activate_firewall(
    root: &Path,
    snapshot: &str,
    request: &FirewallReconcileRequest,
) -> Result<(), String> {
    load_bridge_sysctls(root)?;
    let current_inet = Command::new("nft")
        .args(["list", "table", "inet", COOLIFY_NFT_TABLE])
        .output()
        .map_err(|_| "nftables is unavailable.")?;
    let current_bridge = Command::new("nft")
        .args(["list", "table", "bridge", COOLIFY_NFT_BRIDGE_TABLE])
        .output()
        .map_err(|_| "nftables is unavailable.")?;
    let inet_table_exists = current_inet.status.success();
    let bridge_table_exists = current_bridge.status.success();
    let last_good = state_path(root, "firewall.last-good.nft");
    if inet_table_exists || bridge_table_exists {
        let mut last_good_snapshot = current_inet.stdout;
        last_good_snapshot.extend_from_slice(&current_bridge.stdout);
        atomic_write(&last_good, &last_good_snapshot, 0o600)?;
    }
    let transaction_path = state_path(root, "firewall.transaction.nft");
    atomic_write(
        &transaction_path,
        nft_transaction(snapshot, inet_table_exists, bridge_table_exists).as_bytes(),
        0o600,
    )?;
    run(
        Command::new("nft")
            .args(["--check", "--file"])
            .arg(&transaction_path),
        "The firewall configuration is invalid.",
    )?;
    let delete_tables = format!(
        "nft delete table inet {COOLIFY_NFT_TABLE} >/dev/null 2>&1 || true; nft delete table bridge {COOLIFY_NFT_BRIDGE_TABLE} >/dev/null 2>&1 || true"
    );
    let rollback = if inet_table_exists || bridge_table_exists {
        format!("{delete_tables}; nft --file '{}'", last_good.display())
    } else {
        delete_tables
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
        run(
            Command::new("nft").args(["list", "table", "bridge", COOLIFY_NFT_BRIDGE_TABLE]),
            "The Coolify bridge firewall table is not active.",
        )
    })
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
    .and_then(|_| configure_mesh_nat(&request.wireguard_interface, &request.workload_cidrs));
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

/// Writes the persistent forwarding settings and loads them. `br_netfilter` is
/// not loaded at boot, so the bridge setting must be re-applied after a reboot.
fn load_bridge_sysctls(root: &Path) -> Result<(), String> {
    let sysctl_path = root.join(BRIDGE_SYSCTL_FILE);
    atomic_write(
        &sysctl_path,
        b"net.ipv4.ip_forward=1\nnet.bridge.bridge-nf-call-iptables=1\n",
        0o644,
    )?;
    if root != Path::new("/") {
        return Ok(());
    }
    run(
        Command::new("modprobe").arg("br_netfilter"),
        "The bridge firewall module could not be loaded.",
    )?;
    run(
        Command::new("sysctl").arg("--load").arg(&sysctl_path),
        "The bridge firewall settings could not be activated.",
    )
}

fn configure_mesh_nat(interface: &str, workload_cidrs: &[String]) -> Result<(), String> {
    for cidr in workload_cidrs {
        let rule = mesh_nat_rule_arguments(interface, cidr);
        let exists = Command::new("iptables")
            .args(["-t", "nat", "-C", "POSTROUTING"])
            .args(rule)
            .status()
            .map_err(|_| "iptables is unavailable.")?
            .success();
        if !exists {
            run(
                Command::new("iptables")
                    .args(["-t", "nat", "-I", "POSTROUTING", "1"])
                    .args(rule),
                "The workload mesh NAT exemption could not be activated.",
            )?;
        }
    }

    Ok(())
}

fn mesh_nat_rule_arguments<'a>(interface: &'a str, cidr: &'a str) -> [&'a str; 6] {
    ["-s", cidr, "-o", interface, "-j", "RETURN"]
}

pub(crate) fn inspect_firewall(
    root: &Path,
    expected_revision: u64,
    expected_hash: &str,
) -> FirewallInspectResult {
    let state = read_state_file(&state_path(root, "firewall.state"));
    let tables_active = firewall_tables_active(root);
    FirewallInspectResult {
        applied_revision: state.as_ref().map_or(0, |state| state.0),
        configuration_hash: state
            .as_ref()
            .map_or_else(String::new, |state| state.1.clone()),
        drifted: !tables_active
            || state
                .as_ref()
                .is_none_or(|state| state.0 != expected_revision || state.1 != expected_hash),
        table: COOLIFY_NFT_TABLE.into(),
        ingress_enforced: tables_active,
    }
}

fn firewall_tables_active(root: &Path) -> bool {
    root != Path::new("/")
        || [
            ["list", "table", "inet", COOLIFY_NFT_TABLE],
            ["list", "table", "bridge", COOLIFY_NFT_BRIDGE_TABLE],
        ]
        .iter()
        .all(|arguments| {
            Command::new("nft")
                .args(arguments)
                .status()
                .is_ok_and(|status| status.success())
        })
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
        ingress_enforced: true,
    }
}

/// What a Corrosion reconcile changed on disk. Only these decide whether the
/// running services must be touched.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CorrosionChanges {
    pub(crate) config: bool,
    pub(crate) schema: bool,
    pub(crate) unit: bool,
    pub(crate) cluster_id: bool,
    pub(crate) dns_unit: bool,
    /// Owner address, Node DNS name or peer count: read by Sentinel, not by Corrosion.
    pub(crate) metadata: bool,
}

impl CorrosionChanges {
    fn any(self) -> bool {
        self.config || self.schema || self.unit || self.cluster_id || self.dns_unit || self.metadata
    }
}

/// One service action of a Corrosion reconcile on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorrosionStep {
    DaemonReload,
    /// Restart, wait until active, set the cluster ID, and restart again.
    RestartWithClusterId,
    Restart,
    /// `corrosion reload` re-reads the schema; a restart is the fallback.
    ReloadSchema,
    RestartDiscoveryDns,
}

/// The service actions a Corrosion reconcile needs. Unchanged inputs on an
/// active Corrosion need none: a restart drops the endpoints that the Nodes
/// replicate to each other, and every network revision runs this command.
pub(crate) fn corrosion_steps(
    changes: CorrosionChanges,
    corrosion_active: bool,
) -> Vec<CorrosionStep> {
    let mut steps = Vec::new();
    if changes.unit || changes.dns_unit {
        steps.push(CorrosionStep::DaemonReload);
    }
    if changes.cluster_id {
        steps.push(CorrosionStep::RestartWithClusterId);
    } else if changes.config || changes.unit || !corrosion_active {
        // A restart also loads a changed schema.
        steps.push(CorrosionStep::Restart);
    } else if changes.schema {
        steps.push(CorrosionStep::ReloadSchema);
    }
    if changes.dns_unit {
        steps.push(CorrosionStep::RestartDiscoveryDns);
    }
    steps
}

/// Writes the Corrosion files and reports which of them changed. The schema is
/// only compared here: the caller writes it, or `ReloadSchema` does.
fn write_corrosion_files(
    root: &Path,
    request: &CorrosionReconcileRequest,
) -> Result<CorrosionChanges, String> {
    if request.version != CORROSION_VERSION {
        return Err(format!(
            "Corrosion must use the tested version {CORROSION_VERSION}."
        ));
    }
    let config = render_corrosion(request)?;
    let cluster_id = corrosion_cluster_id(&request.cluster_id)?;
    let dns_unit = corrosion_dns_unit(&request.bind_address)?;
    let schema_path = root.join("etc/corrosion/schemas/coolify.sql");
    let mut changes = CorrosionChanges {
        schema: fs::read(&schema_path).ok().as_deref() != Some(corrosion_schema().as_bytes()),
        ..CorrosionChanges::default()
    };
    changes.config = write_if_changed(
        &root.join("etc/corrosion/config.toml"),
        config.as_bytes(),
        0o644,
    )?;
    changes.unit = write_if_changed(
        &root.join("etc/systemd/system/corrosion.service"),
        corrosion_unit().as_bytes(),
        0o644,
    )?;
    changes.cluster_id = write_if_changed(
        &root.join("etc/corrosion/coolify-cluster-id"),
        format!("{cluster_id}\n").as_bytes(),
        0o644,
    )?;
    changes.dns_unit = write_if_changed(
        &root.join("etc/systemd/system/coolify-discovery-dns.service"),
        dns_unit.as_bytes(),
        0o644,
    )?;
    for (path, contents) in [
        (CORROSION_OWNER_FILE, format!("{}\n", request.bind_address)),
        (
            CORROSION_NODE_NAME_FILE,
            format!("{}\n", request.node_dns_name),
        ),
        (
            "etc/corrosion/coolify-peer-count",
            format!("{}\n", request.peers.len()),
        ),
    ] {
        changes.metadata |= write_if_changed(&root.join(path), contents.as_bytes(), 0o644)?;
    }
    Ok(changes)
}

/// Writes `contents` only when it differs. Returns whether it changed.
pub(crate) fn write_if_changed(path: &Path, contents: &[u8], mode: u32) -> Result<bool, String> {
    if fs::read(path).ok().as_deref() == Some(contents) {
        return Ok(false);
    }
    atomic_write(path, contents, mode)?;
    Ok(true)
}

fn service_enabled(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

fn service_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

fn apply_corrosion_step(root: &Path, step: CorrosionStep, cluster_id: u16) -> Result<(), String> {
    match step {
        CorrosionStep::DaemonReload => run(
            Command::new("systemctl").arg("daemon-reload"),
            "Systemd could not reload Corrosion.",
        ),
        CorrosionStep::Restart => {
            let _ = Command::new("systemctl")
                .args(["reset-failed", "corrosion.service"])
                .status();
            run(
                Command::new("systemctl").args(["restart", "corrosion.service"]),
                "Corrosion could not start.",
            )
        }
        CorrosionStep::RestartWithClusterId => {
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
            )
        }
        CorrosionStep::ReloadSchema => ensure_corrosion_schema(root).map(|_| ()),
        CorrosionStep::RestartDiscoveryDns => run(
            Command::new("systemctl").args(["restart", "coolify-discovery-dns.service"]),
            "The Coolify discovery DNS service could not restart.",
        ),
    }
}

/// Applies `discovery.corrosion.reconcile.v1`. It runs on every network
/// revision, so it only restarts or reloads Corrosion when its inputs changed
/// or it is not running.
pub(crate) fn reconcile_corrosion(
    root: &Path,
    request: &CorrosionReconcileRequest,
) -> Result<CorrosionReconcileResult, String> {
    let changes = write_corrosion_files(root, request)?;
    let host = root == Path::new("/");
    let steps = if host {
        install_corrosion(request.version.as_str())?;
        ensure_discovery_dns_user()?;
        corrosion_steps(changes, service_active("corrosion.service"))
    } else {
        Vec::new()
    };
    if changes.schema && !steps.contains(&CorrosionStep::ReloadSchema) {
        atomic_write(
            &root.join("etc/corrosion/schemas/coolify.sql"),
            corrosion_schema().as_bytes(),
            0o644,
        )?;
    }
    let changed = changes.any() || !steps.is_empty();
    if host {
        let cluster_id = corrosion_cluster_id(&request.cluster_id)?;
        for step in steps {
            apply_corrosion_step(root, step, cluster_id)?;
        }
        // `systemctl enable` reloads systemd, so it only runs for a unit that is not enabled yet.
        if !service_enabled("corrosion.service") {
            run(
                Command::new("systemctl").args(["enable", "corrosion.service"]),
                "Corrosion could not be enabled.",
            )?;
        }
        run(
            Command::new("systemctl").args(["is-active", "--quiet", "corrosion.service"]),
            "Corrosion did not become active.",
        )?;
        if !service_enabled("coolify-discovery-dns.service") {
            run(
                Command::new("systemctl").args(["enable", "coolify-discovery-dns.service"]),
                "The Coolify discovery DNS service could not be enabled.",
            )?;
        }
        if !service_active("coolify-discovery-dns.service") {
            run(
                Command::new("systemctl").args(["start", "coolify-discovery-dns.service"]),
                "The Coolify discovery DNS service could not start.",
            )?;
        }
        run(
            Command::new("systemctl").args([
                "is-active",
                "--quiet",
                "coolify-discovery-dns.service",
            ]),
            "The Coolify discovery DNS service did not become active.",
        )?;
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
            alive_member_count: None,
        };
    }
    if root != Path::new("/") {
        return CorrosionInspectResult {
            version: CORROSION_VERSION.into(),
            member_state: "configured".into(),
            endpoint_count: 0,
            last_convergence_unix_seconds: None,
            alive_member_count: None,
        };
    }

    let version = fs::read_to_string("/usr/local/bin/corrosion.version")
        .unwrap_or_default()
        .trim()
        .to_string();
    let corrosion_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "corrosion.service"])
        .status()
        .is_ok_and(|status| status.success());
    let dns_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "coolify-discovery-dns.service"])
        .status()
        .is_ok_and(|status| status.success());
    let owner_ip = fs::read_to_string("/etc/corrosion/coolify-owner").unwrap_or_default();
    let resolver_active = Command::new("resolvectl")
        .arg("status")
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(owner_ip.trim())
                && String::from_utf8_lossy(&output.stdout).contains("~coolify.internal")
        });
    let active = corrosion_active && dns_active && resolver_active;
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
    let alive_member_count = membership
        .as_ref()
        .filter(|output| output.status.success())
        .map(|output| corrosion_alive_member_count(&output.stdout, cluster_id));
    let converged = active
        && alive_member_count
            .is_some_and(|alive| corrosion_membership_converged(alive, cluster_id, peer_count));
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
        alive_member_count,
    }
}

fn read_trimmed_u64(path: impl AsRef<Path>) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn corrosion_membership_converged(
    alive_member_count: u64,
    cluster_id: u16,
    peer_count: u64,
) -> bool {
    cluster_id != 0 && alive_member_count >= peer_count
}

/// Counts the Corrosion members of this cluster that are `Alive`. Coolify compares this
/// with the number of reachable peers, so an offline peer does not block convergence.
fn corrosion_alive_member_count(output: &[u8], cluster_id: u16) -> u64 {
    if cluster_id == 0 {
        return 0;
    }
    let members: Result<Vec<serde_json::Value>, _> = serde_json::Deserializer::from_slice(output)
        .into_iter::<serde_json::Value>()
        .collect();
    if let Ok(members) = members {
        return members
            .iter()
            .filter(|member| {
                member.get("state").and_then(serde_json::Value::as_str) == Some("Alive")
                    && member
                        .pointer("/id/cluster_id")
                        .and_then(serde_json::Value::as_u64)
                        == Some(u64::from(cluster_id))
            })
            .count() as u64;
    }
    let text = String::from_utf8_lossy(output);
    let expected_cluster = format!("\"cluster_id\": {cluster_id}");
    (text.matches("\"state\": \"Alive\"").count() as u64)
        .min(text.matches(&expected_cluster).count() as u64)
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

    let mut reverse_zones = peer_addresses
        .iter()
        .copied()
        .chain(std::iter::once(bind_address.as_str()))
        .filter_map(reverse_dns_zone)
        .collect::<Vec<_>>();
    reverse_zones.sort();
    reverse_zones.dedup();

    Ok(vec![
        vec!["dns".into(), interface.into(), bind_address],
        std::iter::once("domain".into())
            .chain(std::iter::once(interface.into()))
            .chain(std::iter::once("~coolify.internal".into()))
            .chain(reverse_zones)
            .collect(),
    ])
}

fn reverse_dns_zone(cidr: &str) -> Option<String> {
    let (address, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let address = address.parse::<std::net::Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    let octets = address.octets();
    match prefix {
        8 => Some(format!("~{}.in-addr.arpa", octets[0])),
        16 => Some(format!("~{}.{}.in-addr.arpa", octets[1], octets[0])),
        24 => Some(format!(
            "~{}.{}.{}.in-addr.arpa",
            octets[2], octets[1], octets[0]
        )),
        32 => Some(format!(
            "~{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        )),
        _ => None,
    }
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

pub(crate) fn corrosion_schema() -> &'static str {
    "CREATE TABLE IF NOT EXISTS workload_endpoints (workload_id TEXT NOT NULL, namespace TEXT NOT NULL, owner_node_ip TEXT NOT NULL, container_ip TEXT NOT NULL, state TEXT NOT NULL DEFAULT '', health TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (namespace, workload_id, owner_node_ip, container_ip));\nCREATE TABLE IF NOT EXISTS ingress_routes (host TEXT NOT NULL PRIMARY KEY, workload_id TEXT NOT NULL DEFAULT '', namespace TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);\n"
}

/// Brings the installed Corrosion schema file up to date. A changed file is
/// applied with `corrosion reload`, which re-reads the schema paths through
/// the admin socket and creates new tables without a restart; a restart is the
/// fallback. Returns whether the schema changed.
pub(crate) fn ensure_corrosion_schema(root: &Path) -> Result<bool, String> {
    let path = root.join("etc/corrosion/schemas/coolify.sql");
    if fs::read(&path).ok().as_deref() == Some(corrosion_schema().as_bytes()) {
        return Ok(false);
    }
    atomic_write(&path, corrosion_schema().as_bytes(), 0o644)?;
    if root != Path::new("/") {
        return Ok(true);
    }
    if let Err(error) = run(
        Command::new("/usr/local/bin/corrosion").args([
            "reload",
            "--config",
            "/etc/corrosion/config.toml",
        ]),
        "Corrosion could not reload its schema.",
    ) {
        tracing::warn!(%error, "Corrosion could not reload its schema; restarting it");
        run(
            Command::new("systemctl").args(["restart", "corrosion.service"]),
            "Corrosion could not restart to apply its schema.",
        )?;
    }
    let owner = fs::read_to_string(root.join(CORROSION_OWNER_FILE))
        .map_err(|_| "The Corrosion owner address could not be read.".to_string())?;
    let probe = serde_json::to_vec("SELECT COUNT(*) FROM ingress_routes").unwrap_or_default();
    let mut last_error = String::new();
    for _ in 0..30 {
        match crate::discovery::corrosion_api(owner.trim(), "queries", &probe)
            .and_then(|output| crate::ingress::parse_query_events(&output))
        {
            Ok(_) => return Ok(true),
            Err(error) => last_error = error,
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!(
        "Corrosion did not apply the ingress schema: {last_error}"
    ))
}

fn corrosion_unit() -> &'static str {
    "[Unit]\nDescription=Coolify Corrosion discovery\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=0\n[Service]\nExecStart=/usr/local/bin/corrosion agent --config /etc/corrosion/config.toml\nUser=corrosion\nGroup=corrosion\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nStateDirectory=corrosion\nRuntimeDirectory=corrosion\nReadWritePaths=/var/lib/corrosion /run/corrosion\nRestart=always\nRestartSec=5s\n[Install]\nWantedBy=multi-user.target\n"
}

fn corrosion_dns_unit(bind_address: &str) -> Result<String, String> {
    if bind_address.parse::<std::net::Ipv4Addr>().is_err() {
        return Err("The Corrosion DNS bind address is invalid.".into());
    }
    Ok(format!(
        "[Unit]\nDescription=Coolify internal discovery DNS\nAfter=corrosion.service\nWants=corrosion.service\nStartLimitIntervalSec=0\n[Service]\nExecStart=/usr/local/bin/sentinel discovery-dns --bind {bind_address}:53 --zone coolify.internal --corrosion-config /etc/corrosion/config.toml\nUser=coolify-dns\nGroup=coolify-dns\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nRestart=always\nRestartSec=5s\n[Install]\nWantedBy=multi-user.target\n"
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

pub(crate) fn run(command: &mut Command, fallback: &str) -> Result<(), String> {
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

/// Cluster network state that Coolify already applied to this Node, read from
/// the files Sentinel keeps. A boot restore re-activates only this state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct AppliedNetwork {
    pub(crate) wireguard: Vec<AppliedWireguard>,
    pub(crate) firewall: Option<AppliedFirewall>,
    pub(crate) corrosion: Option<AppliedCorrosion>,
    pub(crate) ingress: Option<AppliedIngress>,
    /// Applied state that exists but could not be read; the restore is incomplete.
    pub(crate) problems: Vec<String>,
}

impl AppliedNetwork {
    pub(crate) fn is_empty(&self) -> bool {
        self.wireguard.is_empty()
            && self.firewall.is_none()
            && self.corrosion.is_none()
            && self.ingress.is_none()
            && self.problems.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedWireguard {
    pub(crate) interface: String,
    pub(crate) address: String,
    pub(crate) peer_addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedFirewall {
    pub(crate) wireguard_interface: String,
    pub(crate) workload_cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedCorrosion {
    pub(crate) units_current: bool,
    pub(crate) dns_unit_installed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedIngress {
    pub(crate) unit_current: bool,
}

/// What is live on the host right now.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct LiveNetwork {
    pub(crate) links_up: Vec<String>,
    pub(crate) inet_table_exists: bool,
    pub(crate) bridge_table_exists: bool,
    pub(crate) corrosion_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RestoreStep {
    BridgeSysctls,
    LoadFirewall {
        inet_table_exists: bool,
        bridge_table_exists: bool,
    },
    WireguardUp {
        interface: String,
        address: String,
    },
    DiscoveryResolver {
        interface: String,
        address: String,
        peer_addresses: Vec<String>,
    },
    RefreshCorrosionUnits,
    RestartCorrosion,
    StartDiscoveryDns,
    MeshNat {
        interface: String,
        workload_cidrs: Vec<String>,
    },
    RefreshIngressUnit,
    StartIngress,
}

/// Network restore steps, split around the workload restart: the mesh NAT
/// exemption goes last so it is inserted ahead of the rules Netavark adds when
/// the workloads start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RestorePlan {
    pub(crate) before_workloads: Vec<RestoreStep>,
    pub(crate) after_workloads: Vec<RestoreStep>,
}

pub(crate) fn read_applied_network(root: &Path) -> AppliedNetwork {
    let mut applied = AppliedNetwork::default();
    let state_dir = state_path(root, "");
    let mut interfaces = fs::read_dir(&state_dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .filter_map(|name| name.strip_suffix(".state").map(str::to_string))
                .filter(|name| name != "firewall" && validate_interface(name).is_ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    interfaces.sort();
    for interface in interfaces {
        let config_path = root.join("etc/wireguard").join(format!("{interface}.conf"));
        if !config_path.exists() {
            continue;
        }
        match fs::read_to_string(&config_path)
            .map_err(|_| "The WireGuard configuration could not be read.".to_string())
            .and_then(|config| parse_wireguard_config(&config))
        {
            Ok((address, peer_addresses)) => applied.wireguard.push(AppliedWireguard {
                interface,
                address,
                peer_addresses,
            }),
            Err(message) => applied.problems.push(format!("{interface}: {message}")),
        }
    }

    if state_path(root, "firewall.state").exists() {
        match fs::read_to_string(state_path(root, "firewall.last-good.nft")) {
            Ok(snapshot) => match parse_firewall_snapshot(&snapshot) {
                Some(firewall) => applied.firewall = Some(firewall),
                None => applied
                    .problems
                    .push("The firewall snapshot does not describe the workload networks.".into()),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => applied
                .problems
                .push("The firewall snapshot could not be read.".into()),
        }
    }

    let unit_path = root.join("etc/systemd/system/corrosion.service");
    if root.join("etc/corrosion/config.toml").exists() && unit_path.exists() {
        let dns_unit_path = root.join("etc/systemd/system/coolify-discovery-dns.service");
        let dns_unit_installed = dns_unit_path.exists();
        let dns_unit_current = !dns_unit_installed
            || expected_dns_unit(root).is_none_or(|expected| {
                fs::read(&dns_unit_path).ok().as_deref() == Some(expected.as_bytes())
            });
        applied.corrosion = Some(AppliedCorrosion {
            units_current: dns_unit_current
                && fs::read(&unit_path).ok().as_deref() == Some(corrosion_unit().as_bytes()),
            dns_unit_installed,
        });
    }

    if crate::ingress::enabled(root) {
        applied.ingress = Some(AppliedIngress {
            unit_current: fs::read(root.join(crate::ingress::INGRESS_UNIT_FILE))
                .ok()
                .as_deref()
                == Some(crate::ingress::ingress_unit().as_bytes()),
        });
    }

    applied
}

fn expected_dns_unit(root: &Path) -> Option<String> {
    let owner = fs::read_to_string(root.join(CORROSION_OWNER_FILE)).ok()?;
    corrosion_dns_unit(owner.trim()).ok()
}

/// Reads the address and peer addresses from a rendered WireGuard config,
/// never the keys.
fn parse_wireguard_config(config: &str) -> Result<(String, Vec<String>), String> {
    let mut address = None;
    let mut peer_addresses = Vec::new();
    for line in config.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "Address" => address = Some(value.trim().to_string()),
            "AllowedIPs" => peer_addresses.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|cidr| valid_ipv4_cidr(cidr))
                    .map(str::to_string),
            ),
            _ => {}
        }
    }
    let address = address
        .filter(|address| address.ends_with("/32") && valid_ipv4_cidr(address))
        .ok_or("The WireGuard configuration has no valid address.")?;
    Ok((address, peer_addresses))
}

/// Recovers the WireGuard interface and workload CIDRs from a firewall
/// snapshot, both as rendered here and as printed by `nft list table`.
fn parse_firewall_snapshot(snapshot: &str) -> Option<AppliedFirewall> {
    let interface = snapshot
        .split_once("iifname \"")?
        .1
        .split_once('"')?
        .0
        .to_string();
    validate_interface(&interface).ok()?;
    let elements = snapshot
        .split_once("set workload_networks")?
        .1
        .split_once("elements = {")?
        .1
        .split_once('}')?
        .0;
    let mut workload_cidrs = elements
        .split(|character: char| character == ',' || character.is_whitespace())
        .filter(|token| !token.is_empty())
        .map(|token| {
            if token.contains('/') {
                token.to_string()
            } else {
                format!("{token}/32")
            }
        })
        .filter(|cidr| valid_ipv4_cidr(cidr))
        .collect::<Vec<_>>();
    workload_cidrs.sort();
    workload_cidrs.dedup();
    (!workload_cidrs.is_empty()).then_some(AppliedFirewall {
        wireguard_interface: interface,
        workload_cidrs,
    })
}

/// Observes the live host. Outside the host root everything counts as live,
/// matching how the reconcilers treat a test root.
pub(crate) fn observe_live_network(root: &Path, applied: &AppliedNetwork) -> LiveNetwork {
    if root != Path::new("/") {
        return LiveNetwork {
            links_up: applied
                .wireguard
                .iter()
                .map(|wireguard| wireguard.interface.clone())
                .collect(),
            inet_table_exists: true,
            bridge_table_exists: true,
            corrosion_active: true,
        };
    }
    let succeeds = |command: &mut Command| {
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    };
    LiveNetwork {
        links_up: applied
            .wireguard
            .iter()
            .filter(|wireguard| {
                succeeds(Command::new("ip").args(["link", "show", "dev", &wireguard.interface]))
            })
            .map(|wireguard| wireguard.interface.clone())
            .collect(),
        inet_table_exists: applied.firewall.is_some()
            && succeeds(Command::new("nft").args(["list", "table", "inet", COOLIFY_NFT_TABLE])),
        bridge_table_exists: applied.firewall.is_some()
            && succeeds(Command::new("nft").args([
                "list",
                "table",
                "bridge",
                COOLIFY_NFT_BRIDGE_TABLE,
            ])),
        corrosion_active: applied.corrosion.is_some()
            && succeeds(Command::new("systemctl").args([
                "is-active",
                "--quiet",
                "corrosion.service",
            ])),
    }
}

pub(crate) fn restore_plan(applied: &AppliedNetwork, live: &LiveNetwork) -> RestorePlan {
    let mut plan = RestorePlan::default();
    if let Some(firewall) = &applied.firewall {
        plan.before_workloads.push(RestoreStep::BridgeSysctls);
        if !(live.inet_table_exists && live.bridge_table_exists) {
            plan.before_workloads.push(RestoreStep::LoadFirewall {
                inet_table_exists: live.inet_table_exists,
                bridge_table_exists: live.bridge_table_exists,
            });
        }
        plan.after_workloads.push(RestoreStep::MeshNat {
            interface: firewall.wireguard_interface.clone(),
            workload_cidrs: firewall.workload_cidrs.clone(),
        });
    }
    let mut link_restored = false;
    for wireguard in &applied.wireguard {
        if !live.links_up.contains(&wireguard.interface) {
            link_restored = true;
            plan.before_workloads.push(RestoreStep::WireguardUp {
                interface: wireguard.interface.clone(),
                address: wireguard.address.clone(),
            });
        }
        // systemd-resolved forgets per-link DNS on reboot, even for a link that is up.
        plan.before_workloads.push(RestoreStep::DiscoveryResolver {
            interface: wireguard.interface.clone(),
            address: wireguard.address.clone(),
            peer_addresses: wireguard.peer_addresses.clone(),
        });
    }
    if let Some(corrosion) = &applied.corrosion {
        if !corrosion.units_current {
            plan.before_workloads
                .push(RestoreStep::RefreshCorrosionUnits);
        }
        // Corrosion binds the WireGuard address, so it must restart once the link is back.
        if link_restored || !live.corrosion_active {
            plan.before_workloads.push(RestoreStep::RestartCorrosion);
        }
        if corrosion.dns_unit_installed {
            plan.before_workloads.push(RestoreStep::StartDiscoveryDns);
        }
    }
    // Caddy starts on boot with its last configuration; this only replaces a
    // unit written by an older Sentinel and starts a unit that gave up.
    if let Some(ingress) = &applied.ingress {
        if !ingress.unit_current {
            plan.before_workloads.push(RestoreStep::RefreshIngressUnit);
        }
        plan.before_workloads.push(RestoreStep::StartIngress);
    }
    plan
}

pub(crate) fn apply_restore_step(root: &Path, step: &RestoreStep) -> Result<(), String> {
    if let RestoreStep::BridgeSysctls = step {
        return load_bridge_sysctls(root);
    }
    if let RestoreStep::RefreshIngressUnit = step {
        return refresh_ingress_unit(root);
    }
    if root != Path::new("/") {
        return Ok(());
    }
    match step {
        RestoreStep::BridgeSysctls => Ok(()),
        RestoreStep::LoadFirewall {
            inet_table_exists,
            bridge_table_exists,
        } => restore_firewall_tables(root, *inet_table_exists, *bridge_table_exists),
        RestoreStep::WireguardUp { interface, address } => {
            restore_wireguard_link(interface, address)
        }
        RestoreStep::DiscoveryResolver {
            interface,
            address,
            peer_addresses,
        } => {
            let peers = peer_addresses
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            configure_discovery_resolver(interface, address, &peers)
        }
        RestoreStep::RefreshCorrosionUnits => refresh_corrosion_units(root),
        RestoreStep::RestartCorrosion => {
            let _ = Command::new("systemctl")
                .args(["reset-failed", "corrosion.service"])
                .status();
            run(
                Command::new("systemctl").args(["restart", "corrosion.service"]),
                "Corrosion could not restart.",
            )
        }
        RestoreStep::StartDiscoveryDns => {
            let _ = Command::new("systemctl")
                .args(["reset-failed", "coolify-discovery-dns.service"])
                .status();
            run(
                Command::new("systemctl").args(["start", "coolify-discovery-dns.service"]),
                "The Coolify discovery DNS service could not start.",
            )
        }
        RestoreStep::MeshNat {
            interface,
            workload_cidrs,
        } => configure_mesh_nat(interface, workload_cidrs),
        RestoreStep::RefreshIngressUnit => Ok(()),
        RestoreStep::StartIngress => {
            let _ = Command::new("systemctl")
                .args(["reset-failed", crate::ingress::INGRESS_UNIT])
                .status();
            run(
                Command::new("systemctl").args(["start", crate::ingress::INGRESS_UNIT]),
                "The Coolify ingress could not start.",
            )
        }
    }
}

/// Rewrites the ingress unit with the current template and restarts Caddy
/// with it, so a Node keeps current hardening without Coolify.
fn refresh_ingress_unit(root: &Path) -> Result<(), String> {
    let _ingress = crate::ingress::ingress_lock();
    if !crate::ingress::enabled(root) {
        return Ok(());
    }
    atomic_write(
        &root.join(crate::ingress::INGRESS_UNIT_FILE),
        crate::ingress::ingress_unit().as_bytes(),
        0o644,
    )?;
    if root != Path::new("/") {
        return Ok(());
    }
    run(
        Command::new("systemctl").arg("daemon-reload"),
        "Systemd could not reload the ingress unit.",
    )?;
    run(
        Command::new("systemctl").args(["enable", crate::ingress::INGRESS_UNIT]),
        "The Coolify ingress could not be enabled.",
    )?;
    run(
        Command::new("systemctl").args(["restart", crate::ingress::INGRESS_UNIT]),
        "The Coolify ingress could not restart.",
    )
}

/// Loads the last known-good snapshot with the same transaction activation
/// uses. There is no rollback timer: this is a known-good state, not a change.
fn restore_firewall_tables(
    root: &Path,
    inet_table_exists: bool,
    bridge_table_exists: bool,
) -> Result<(), String> {
    let snapshot = fs::read_to_string(state_path(root, "firewall.last-good.nft"))
        .map_err(|_| "The last good firewall snapshot could not be read.")?;
    let transaction_path = state_path(root, "firewall.transaction.nft");
    atomic_write(
        &transaction_path,
        nft_transaction(&snapshot, inet_table_exists, bridge_table_exists).as_bytes(),
        0o600,
    )?;
    run(
        Command::new("nft")
            .args(["--check", "--file"])
            .arg(&transaction_path),
        "The last good firewall snapshot is invalid.",
    )?;
    run(
        Command::new("nft").arg("--file").arg(&transaction_path),
        "The last good firewall snapshot could not be loaded.",
    )?;
    if !firewall_tables_active(root) {
        return Err("The Coolify firewall tables are not active after the restore.".into());
    }
    Ok(())
}

fn restore_wireguard_link(interface: &str, address: &str) -> Result<(), String> {
    let _ = Command::new("wg-quick")
        .args(["down", interface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    run(
        Command::new("wg-quick").args(["up", interface]),
        "WireGuard could not be brought up.",
    )?;
    let output = Command::new("ip")
        .args(["-4", "-o", "address", "show", "dev", interface])
        .output()
        .map_err(|_| "WireGuard address validation failed.".to_string())?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout).contains(&format!("inet {address}"))
    {
        return Err("WireGuard does not have the expected address.".into());
    }
    Ok(())
}

/// Rewrites the Corrosion units with the current templates, so a Node that was
/// joined by an older Sentinel gets the restart policy without Coolify.
fn refresh_corrosion_units(root: &Path) -> Result<(), String> {
    atomic_write(
        &root.join("etc/systemd/system/corrosion.service"),
        corrosion_unit().as_bytes(),
        0o644,
    )?;
    let dns_unit_path = root.join("etc/systemd/system/coolify-discovery-dns.service");
    if dns_unit_path.exists()
        && let Some(unit) = expected_dns_unit(root)
    {
        atomic_write(&dns_unit_path, unit.as_bytes(), 0o644)?;
    }
    if root != Path::new("/") {
        return Ok(());
    }
    run(
        Command::new("systemctl").arg("daemon-reload"),
        "Systemd could not reload the Corrosion units.",
    )
}

fn read_state_file(path: &Path) -> Option<(u64, String)> {
    let contents = fs::read_to_string(path).ok()?;
    let (revision, hash) = contents.trim().split_once(' ')?;
    Some((revision.parse().ok()?, hash.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::control::v1::{FirewallIngressRule, FirewallRule, WireguardPeer};

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
            local_node_ip: "10.240.0.2".into(),
            rules: vec![
                FirewallRule {
                    source_ip: "100.64.0.2".into(),
                    destination_ip: "100.64.1.2".into(),
                    protocol: "tcp".into(),
                    port: 5432,
                },
                FirewallRule {
                    source_ip: "10.240.0.2".into(),
                    destination_ip: "100.64.1.3".into(),
                    protocol: "icmp".into(),
                    port: 0,
                },
            ],
            ingress_rules: vec![FirewallIngressRule {
                destination_ip: "100.64.1.2".into(),
                protocol: "tcp".into(),
                port: 8080,
            }],
            wireguard_interface: "coolify0".into(),
            workload_cidrs: vec!["100.64.0.0/24".into(), "100.64.1.0/24".into()],
            flux_probe_host: "10.240.0.1".into(),
        })
        .unwrap();
        assert!(rendered.contains("table inet coolify_cluster"));
        let bridge = rendered
            .split("table bridge coolify_cluster_bridge")
            .nth(1)
            .expect("the same-Node bridge policy must be rendered");
        assert!(bridge.contains("ip saddr 100.64.0.2 ip daddr 100.64.1.2 tcp dport 5432 accept"));
        assert!(bridge.contains("ip saddr @workload_networks ip daddr @workload_networks drop"));
        assert!(
            !bridge.contains("ip saddr 10.240.0.2 ip daddr 100.64.1.3 ip protocol icmp accept")
        );
        assert!(!rendered.contains("flush ruleset"));
        assert!(!rendered.contains("delete table"));
        assert!(rendered.contains("ip saddr @workload_networks ip daddr @workload_networks drop"));
        assert!(
            rendered.contains("ip saddr 10.240.0.2 ip daddr 100.64.1.3 ip protocol icmp accept")
        );
        assert!(rendered.contains("ip daddr 100.64.1.3 ip protocol icmp accept"));
        assert!(!rendered.contains(
            "ip saddr @workload_networks ip daddr @workload_networks ip protocol icmp accept"
        ));
        assert!(rendered.contains("ip saddr 100.64.0.2 ip daddr 100.64.1.2 tcp dport 5432 accept"));
        assert!(
            rendered.contains(
                "ip saddr != @workload_networks ip daddr 100.64.1.2 tcp dport 8080 accept"
            )
        );
        assert!(
            rendered.contains("ip saddr != @workload_networks ip daddr @workload_networks drop")
        );
        assert!(rendered.contains("ip daddr 100.64.1.2 tcp dport 8080 accept"));
        assert!(rendered.contains("ip saddr 10.240.0.0/24 udp dport 8787 accept"));
        assert!(rendered.contains("ip saddr 10.240.0.0/24 drop"));
        assert!(rendered.contains("ip daddr 10.240.0.0/24 udp dport 8787 accept"));
        assert!(rendered.contains("ip saddr 10.240.0.2 ip daddr 10.240.0.2 tcp dport 8080 accept"));
        assert!(rendered.contains("ip daddr 10.240.0.2 tcp dport 8080 accept"));
        assert!(rendered.contains("ip saddr 10.240.0.2 ip daddr 10.240.0.2 udp dport 53 accept"));
        assert!(rendered.contains("ip saddr 10.240.0.2 ip daddr 10.240.0.2 tcp dport 53 accept"));
        assert!(rendered.contains("ip daddr 10.240.0.2 udp dport 53 accept"));
        assert!(rendered.contains("ip daddr 10.240.0.2 tcp dport 53 accept"));
        assert!(rendered.contains("ip daddr 10.240.0.0/24 drop"));
        assert!(!rendered.contains("ip saddr 10.240.0.0/24 tcp dport 8080 accept"));
        assert!(!rendered.contains("ip daddr 10.240.0.0/24 ip protocol icmp accept"));
        assert!(rendered.contains("chain output { type filter hook output priority -5; policy accept; ct state established,related accept;"));
        assert!(rendered.contains("ip daddr @workload_networks drop"));
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

        // A new revision with the same peers keeps the link and records the revision.
        let next = WireguardReconcileRequest {
            revision: 8,
            ..request.clone()
        };
        let third = reconcile_wireguard(temp.path(), &next).unwrap();
        assert!(!third.changed);
        assert_eq!(third.state.as_ref().unwrap().applied_revision, 8);
        assert_eq!(read_applied_state(temp.path(), "coolify0").unwrap().0, 8);

        // A changed peer set applies the new configuration.
        let mut changed = next.clone();
        changed.revision = 9;
        changed.peers[0].allowed_ips.push("100.64.1.0/24".into());
        assert!(reconcile_wireguard(temp.path(), &changed).unwrap().changed);

        // A configuration file edited on the host is rewritten even with the same peers.
        let edited = WireguardReconcileRequest {
            revision: 10,
            ..changed.clone()
        };
        fs::write(
            temp.path().join("etc/wireguard/coolify0.conf"),
            "[Interface]\n",
        )
        .unwrap();
        assert!(reconcile_wireguard(temp.path(), &edited).unwrap().changed);
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
            &["10.0.0.129/32", "10.0.0.131/32", "100.64.1.0/24"],
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
                    "~1.64.100.in-addr.arpa",
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

    /// A packet as the inet table sees it.
    struct Packet<'a> {
        iifname: &'a str,
        saddr: &'a str,
        daddr: &'a str,
        protocol: &'a str,
        dport: u32,
        established: bool,
    }

    /// Evaluates one chain of the rendered `table inet` against a packet, for
    /// the subset of nft syntax `render_firewall` emits. Returns the verdict.
    fn evaluate_chain(
        rendered: &str,
        chain: &str,
        workload_cidrs: &[&str],
        packet: &Packet,
    ) -> &'static str {
        let inet = rendered.split("table bridge").next().unwrap();
        let body = inet
            .split_once(&format!("chain {chain} {{"))
            .unwrap()
            .1
            .split_once("}\n")
            .unwrap()
            .0;
        let in_set = |value: &str, address: &str| {
            if value == "@workload_networks" {
                workload_cidrs
                    .iter()
                    .any(|cidr| ipv4_in_cidr(address, cidr))
            } else if value.contains('/') {
                ipv4_in_cidr(address, value)
            } else {
                value == address
            }
        };
        for statement in body.split(';').map(str::trim) {
            if statement.is_empty()
                || statement.starts_with("type ")
                || statement.starts_with("policy ")
            {
                continue;
            }
            let tokens = statement.split_whitespace().collect::<Vec<_>>();
            let mut index = 0;
            let mut matched = true;
            let mut verdict = None;
            while index < tokens.len() && matched {
                let negated = tokens.get(index + 2) == Some(&"!=");
                let value_at = if negated { index + 3 } else { index + 2 };
                match tokens[index] {
                    "ct" => {
                        matched = packet.established;
                        index += 3;
                    }
                    "iifname" => {
                        let negated = tokens[index + 1] == "!=";
                        let value = tokens[index + if negated { 2 } else { 1 }].trim_matches('"');
                        matched = (value == packet.iifname) != negated;
                        index += if negated { 3 } else { 2 };
                    }
                    "ip" if tokens[index + 1] == "protocol" => {
                        matched = packet.protocol == tokens[index + 2];
                        index += 3;
                    }
                    "ip" => {
                        let address = if tokens[index + 1] == "saddr" {
                            packet.saddr
                        } else {
                            packet.daddr
                        };
                        matched = in_set(tokens[value_at], address) != negated;
                        index = value_at + 1;
                    }
                    "tcp" | "udp" => {
                        matched = packet.protocol == tokens[index]
                            && tokens[index + 1] == "dport"
                            && tokens[index + 2].parse::<u32>().unwrap() == packet.dport;
                        index += 3;
                    }
                    "accept" => {
                        verdict = Some("accept");
                        index += 1;
                    }
                    "drop" => {
                        verdict = Some("drop");
                        index += 1;
                    }
                    other => panic!("unsupported nft token {other} in {statement}"),
                }
            }
            if matched && let Some(verdict) = verdict {
                return verdict;
            }
        }
        "accept"
    }

    #[test]
    fn ingress_rules_admit_caddy_on_the_same_and_on_another_node() {
        let workload_cidrs = ["100.64.0.0/24", "100.64.1.0/24"];
        let request = |local_node_ip: &str| FirewallReconcileRequest {
            local_node_ip: local_node_ip.into(),
            workload_cidrs: workload_cidrs.iter().map(|cidr| cidr.to_string()).collect(),
            // Coolify renders the same cluster-wide ingress rules on every Node.
            ingress_rules: vec![
                FirewallIngressRule {
                    destination_ip: "100.64.0.5".into(),
                    protocol: "tcp".into(),
                    port: 3000,
                },
                FirewallIngressRule {
                    destination_ip: "100.64.1.7".into(),
                    protocol: "tcp".into(),
                    port: 8080,
                },
            ],
            ..firewall_request()
        };
        // Node A (10.240.0.2) owns 100.64.0.0/24; Node B (10.240.0.3) owns 100.64.1.0/24.
        let node_a = render_firewall(&request("10.240.0.2")).unwrap();
        let node_b = render_firewall(&request("10.240.0.3")).unwrap();
        let new = |iifname, saddr, daddr, dport| Packet {
            iifname,
            saddr,
            daddr,
            protocol: "tcp",
            dport,
            established: false,
        };

        // (a) Caddy on Node A reaches its own workload: host output through the
        // Podman bridge, whose gateway address is the source.
        let local = new("", "100.64.0.1", "100.64.0.5", 3000);
        assert_eq!(
            evaluate_chain(&node_a, "output", &workload_cidrs, &local),
            "accept"
        );
        // The reply enters the host as established traffic.
        let reply = Packet {
            iifname: "podman1",
            saddr: "100.64.0.5",
            daddr: "100.64.0.1",
            protocol: "tcp",
            dport: 40000,
            established: true,
        };
        assert_eq!(
            evaluate_chain(&node_a, "input", &workload_cidrs, &reply),
            "accept"
        );

        // (b) Caddy on Node B reaches the workload on Node A: it leaves B from
        // B's WireGuard address and A forwards it from coolify0 to the bridge.
        let remote = new("coolify0", "10.240.0.3", "100.64.0.5", 3000);
        assert_eq!(
            evaluate_chain(&node_b, "output", &workload_cidrs, &remote),
            "accept"
        );
        assert_eq!(
            evaluate_chain(&node_a, "forward", &workload_cidrs, &remote),
            "accept"
        );
        let remote_reply = Packet {
            iifname: "podman1",
            saddr: "100.64.0.5",
            daddr: "10.240.0.3",
            protocol: "tcp",
            dport: 40000,
            established: true,
        };
        assert_eq!(
            evaluate_chain(&node_a, "forward", &workload_cidrs, &remote_reply),
            "accept"
        );
        assert_eq!(
            evaluate_chain(
                &node_b,
                "input",
                &workload_cidrs,
                &Packet {
                    iifname: "coolify0",
                    ..remote_reply
                }
            ),
            "accept"
        );
        // And the reverse direction for B's workload.
        let to_b = new("coolify0", "10.240.0.2", "100.64.1.7", 8080);
        assert_eq!(
            evaluate_chain(&node_a, "output", &workload_cidrs, &to_b),
            "accept"
        );
        assert_eq!(
            evaluate_chain(&node_b, "forward", &workload_cidrs, &to_b),
            "accept"
        );

        // Only the routed port is open: other ports and workloads stay closed.
        for (iifname, saddr, daddr, dport) in [
            ("coolify0", "10.240.0.3", "100.64.0.5", 22),
            ("coolify0", "10.240.0.3", "100.64.0.6", 3000),
            ("eth0", "203.0.113.9", "100.64.0.6", 3000),
        ] {
            assert_eq!(
                evaluate_chain(
                    &node_a,
                    "forward",
                    &workload_cidrs,
                    &new(iifname, saddr, daddr, dport)
                ),
                "drop"
            );
        }
        assert_eq!(
            evaluate_chain(
                &node_a,
                "output",
                &workload_cidrs,
                &new("", "100.64.0.1", "100.64.0.5", 22)
            ),
            "drop"
        );
        assert_eq!(
            evaluate_chain(
                &node_b,
                "output",
                &workload_cidrs,
                &new("", "10.240.0.3", "100.64.0.6", 3000)
            ),
            "drop"
        );
        // A workload cannot use an ingress rule to reach another workload.
        assert_eq!(
            evaluate_chain(
                &node_a,
                "forward",
                &workload_cidrs,
                &new("podman1", "100.64.0.9", "100.64.0.5", 3000)
            ),
            "drop"
        );
        // Public clients reach Caddy on port 80: the input policy accepts.
        assert_eq!(
            evaluate_chain(
                &node_a,
                "input",
                &workload_cidrs,
                &new("eth0", "203.0.113.9", "198.51.100.2", 80)
            ),
            "accept"
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
            local_node_ip: "10.240.0.2".into(),
            rules: vec![],
            wireguard_interface: "coolify0".into(),
            flux_probe_host: String::new(),
            workload_cidrs: vec!["100.64.0.0/24".into()],
            ingress_rules: vec![],
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
        let transaction = nft_transaction(&render_firewall(&request).unwrap(), true, true);
        assert!(transaction.starts_with("delete table inet coolify_cluster"));
        assert!(transaction.contains("delete table bridge coolify_cluster_bridge"));
        assert!(!transaction.contains("flush ruleset"));
        assert!(!transaction.contains("user_owned"));
    }

    #[test]
    fn workload_mesh_nat_bypasses_netavark_masquerading() {
        assert_eq!(
            mesh_nat_rule_arguments("coolify0", "100.64.0.0/24"),
            ["-s", "100.64.0.0/24", "-o", "coolify0", "-j", "RETURN",]
        );
    }

    #[test]
    fn corrosion_configuration_is_pinned_bound_and_hardened() {
        let temp = tempfile::tempdir().unwrap();
        let request = CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: "cluster-one".into(),
            bind_address: "10.240.0.2".into(),
            peers: vec!["10.240.0.3:8787".into()],
            node_dns_name: "worker-1".into(),
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
        assert_eq!(
            fs::read_to_string(temp.path().join(CORROSION_OWNER_FILE)).unwrap(),
            "10.240.0.2\n"
        );
        assert_eq!(
            fs::read_to_string(temp.path().join(CORROSION_NODE_NAME_FILE)).unwrap(),
            "worker-1\n"
        );
        let node_name_mode = fs::metadata(temp.path().join(CORROSION_NODE_NAME_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(node_name_mode, 0o644);
    }

    fn corrosion_request(cluster_id: &str, peers: &[&str]) -> CorrosionReconcileRequest {
        CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: cluster_id.into(),
            bind_address: "10.240.0.2".into(),
            peers: peers.iter().map(|peer| (*peer).into()).collect(),
            node_dns_name: "worker-1".into(),
        }
    }

    #[test]
    fn corrosion_reconcile_with_unchanged_inputs_plans_no_restart() {
        let temp = tempfile::tempdir().unwrap();
        let request = corrosion_request("cluster-one", &["10.240.0.3:8787"]);

        let first = write_corrosion_files(temp.path(), &request).unwrap();
        assert!(first.config && first.unit && first.cluster_id && first.dns_unit && first.schema);
        assert_eq!(
            corrosion_steps(first, false),
            [
                CorrosionStep::DaemonReload,
                CorrosionStep::RestartWithClusterId,
                CorrosionStep::RestartDiscoveryDns,
            ]
        );
        assert!(reconcile_corrosion(temp.path(), &request).unwrap().changed);

        let again = write_corrosion_files(temp.path(), &request).unwrap();
        assert_eq!(again, CorrosionChanges::default());
        assert!(corrosion_steps(again, true).is_empty());
        assert!(!reconcile_corrosion(temp.path(), &request).unwrap().changed);
    }

    #[test]
    fn corrosion_reconcile_plans_the_action_each_change_needs() {
        let temp = tempfile::tempdir().unwrap();
        let request = corrosion_request("cluster-one", &["10.240.0.3:8787"]);
        reconcile_corrosion(temp.path(), &request).unwrap();

        // A new peer changes the configuration: one restart, the cluster ID stays.
        let peers = corrosion_request("cluster-one", &["10.240.0.3:8787", "10.240.0.4:8787"]);
        let changes = write_corrosion_files(temp.path(), &peers).unwrap();
        assert!(changes.config && changes.metadata && !changes.cluster_id);
        assert_eq!(corrosion_steps(changes, true), [CorrosionStep::Restart]);

        // Another cluster: restart, set the new cluster ID, restart.
        let other = corrosion_request("cluster-two", &["10.240.0.3:8787", "10.240.0.4:8787"]);
        let changes = write_corrosion_files(temp.path(), &other).unwrap();
        assert!(changes.cluster_id && !changes.config);
        assert_eq!(
            corrosion_steps(changes, true),
            [CorrosionStep::RestartWithClusterId]
        );

        // An outdated unit: reload systemd and restart.
        write(
            temp.path(),
            "etc/systemd/system/corrosion.service",
            "[Service]\nExecStart=/old\n",
        );
        let changes = write_corrosion_files(temp.path(), &other).unwrap();
        assert!(changes.unit);
        assert_eq!(
            corrosion_steps(changes, true),
            [CorrosionStep::DaemonReload, CorrosionStep::Restart]
        );

        // An outdated schema on a running Corrosion: reload, no restart.
        write(
            temp.path(),
            "etc/corrosion/schemas/coolify.sql",
            "CREATE TABLE IF NOT EXISTS workload_endpoints (old);\n",
        );
        let changes = write_corrosion_files(temp.path(), &other).unwrap();
        assert_eq!(
            changes,
            CorrosionChanges {
                schema: true,
                ..CorrosionChanges::default()
            }
        );
        assert_eq!(
            corrosion_steps(changes, true),
            [CorrosionStep::ReloadSchema]
        );
        // A stopped Corrosion restarts and loads the schema on start.
        assert_eq!(corrosion_steps(changes, false), [CorrosionStep::Restart]);
        assert!(reconcile_corrosion(temp.path(), &other).unwrap().changed);
        assert_eq!(
            fs::read_to_string(temp.path().join("etc/corrosion/schemas/coolify.sql")).unwrap(),
            corrosion_schema()
        );

        // Nothing changed, but Corrosion is not running: start it.
        assert_eq!(
            corrosion_steps(CorrosionChanges::default(), false),
            [CorrosionStep::Restart]
        );

        // Only the DNS unit changed: reload systemd and restart the DNS service alone.
        write(
            temp.path(),
            "etc/systemd/system/coolify-discovery-dns.service",
            "[Service]\nExecStart=/old\n",
        );
        let changes = write_corrosion_files(temp.path(), &other).unwrap();
        assert_eq!(
            corrosion_steps(changes, true),
            [
                CorrosionStep::DaemonReload,
                CorrosionStep::RestartDiscoveryDns
            ]
        );

        // The owner metadata does not touch the services.
        let renamed = CorrosionReconcileRequest {
            node_dns_name: "worker-9".into(),
            ..other.clone()
        };
        let changes = write_corrosion_files(temp.path(), &renamed).unwrap();
        assert!(changes.metadata && changes.any());
        assert!(corrosion_steps(changes, true).is_empty());
    }

    #[test]
    fn corrosion_reconcile_rejects_an_invalid_node_dns_name_before_writing() {
        for invalid in ["", "-worker", "worker-", "worker.one", "worker_one", "a\nb"] {
            let temp = tempfile::tempdir().unwrap();
            let request = CorrosionReconcileRequest {
                version: CORROSION_VERSION.into(),
                cluster_id: "cluster-one".into(),
                bind_address: "10.240.0.2".into(),
                peers: vec![],
                node_dns_name: invalid.into(),
            };

            assert_eq!(
                reconcile_corrosion(temp.path(), &request).unwrap_err(),
                "The Corrosion Node DNS name is invalid."
            );
            assert!(render_corrosion(&request).is_err());
            assert!(!temp.path().join(CORROSION_NODE_NAME_FILE).exists());
            assert!(!temp.path().join("etc/corrosion/config.toml").exists());
        }
        let too_long = CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: "cluster-one".into(),
            bind_address: "10.240.0.2".into(),
            peers: vec![],
            node_dns_name: "a".repeat(64),
        };
        assert!(render_corrosion(&too_long).is_err());
    }

    #[test]
    fn corrosion_configuration_rejects_non_ip_bindings_and_peer_injection() {
        let mut request = CorrosionReconcileRequest {
            version: CORROSION_VERSION.into(),
            cluster_id: "cluster-one".into(),
            bind_address: "0.0.0.0".into(),
            peers: vec!["10.240.0.3:8787".into()],
            node_dns_name: "worker-1".into(),
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
    fn corrosion_membership_requires_every_expected_peer_and_cluster() {
        let output = br#"{
          "id": {"addr": "10.240.0.3:8787", "cluster_id": 42},
          "state": "Alive"
        }"#;

        assert!(corrosion_membership_converged(
            corrosion_alive_member_count(output, 42),
            42,
            1
        ));
        assert!(!corrosion_membership_converged(
            corrosion_alive_member_count(output, 43),
            43,
            1
        ));
        assert!(!corrosion_membership_converged(
            corrosion_alive_member_count(output, 42),
            42,
            2
        ));
        assert!(!corrosion_membership_converged(5, 0, 1));
        assert!(corrosion_membership_converged(0, 42, 0));
    }

    #[test]
    fn corrosion_alive_member_count_counts_only_alive_members_of_the_cluster() {
        let output = br#"{
          "id": {"addr": "10.240.0.3:8787", "cluster_id": 42},
          "state": "Alive"
        }
        {
          "id": {"addr": "10.240.0.4:8787", "cluster_id": 42},
          "state": "Down"
        }
        {
          "id": {"addr": "10.240.0.5:8787", "cluster_id": 7},
          "state": "Alive"
        }"#;

        assert_eq!(corrosion_alive_member_count(output, 42), 1);
        assert_eq!(corrosion_alive_member_count(output, 7), 1);
        assert_eq!(corrosion_alive_member_count(output, 0), 0);
        assert_eq!(corrosion_alive_member_count(b"", 42), 0);
    }

    #[test]
    fn corrosion_alive_member_count_falls_back_for_unstructured_output() {
        let output = b"member \"cluster_id\": 42 \"state\": \"Alive\" trailing text";

        assert_eq!(corrosion_alive_member_count(output, 42), 1);
        assert_eq!(corrosion_alive_member_count(output, 43), 0);
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

    #[test]
    fn cluster_leave_removes_only_managed_network_state_and_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let managed = [
            "etc/wireguard/coolify0.conf",
            "var/lib/coolify/network/coolify0.state",
            "var/lib/coolify/network/coolify0.last-good.conf",
            "var/lib/coolify/network/coolify0.key",
            "var/lib/coolify/network/firewall.state",
            "etc/corrosion/config.toml",
            "etc/corrosion/schemas/coolify.sql",
            "etc/corrosion/coolify-owner",
            "etc/corrosion/coolify-node-name",
            "etc/corrosion/coolify-cluster-id",
            "etc/corrosion/coolify-peer-count",
            "etc/systemd/system/corrosion.service",
            "etc/systemd/system/coolify-discovery-dns.service",
            "var/lib/corrosion/db.sqlite",
            "etc/systemd/system/coolify-ingress.service",
            "etc/coolify-ingress/caddy.json",
            "var/lib/coolify/network/ingress.state",
        ];
        for relative in managed {
            let path = temp.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "managed").unwrap();
        }
        let unrelated = temp.path().join("etc/systemd/system/example.service");
        fs::write(&unrelated, "keep").unwrap();
        let request = ClusterLeaveRequest {
            interface: "coolify0".into(),
            owner_node_ip: "10.240.0.2".into(),
            workload_cidrs: vec!["100.64.0.0/24".into()],
        };

        let first = leave_cluster(temp.path(), &request).unwrap();
        let second = leave_cluster(temp.path(), &request).unwrap();

        assert!(first.wireguard_removed && first.firewall_removed && first.discovery_removed);
        assert!(second.wireguard_removed && second.firewall_removed && second.discovery_removed);
        assert!(unrelated.exists());
        for relative in managed {
            assert!(!temp.path().join(relative).exists());
        }
        assert!(!temp.path().join("etc/coolify-ingress").exists());
    }

    #[test]
    fn corrosion_units_restart_forever_and_dns_does_not_stop_with_corrosion() {
        let unit = corrosion_unit();
        let (unit_section, service_section) = unit.split_once("[Service]").unwrap();
        assert!(unit_section.contains("StartLimitIntervalSec=0\n"));
        assert!(service_section.contains("Restart=always\nRestartSec=5s\n"));
        assert!(!unit.contains("Restart=on-failure"));

        let dns = corrosion_dns_unit("10.240.0.2").unwrap();
        let (dns_unit_section, dns_service_section) = dns.split_once("[Service]").unwrap();
        assert!(dns_unit_section.contains("After=corrosion.service\nWants=corrosion.service\n"));
        assert!(dns_unit_section.contains("StartLimitIntervalSec=0\n"));
        assert!(!dns.contains("Requires=corrosion.service"));
        assert!(dns_service_section.contains("Restart=always\nRestartSec=5s\n"));
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    const WIREGUARD_CONFIG: &str = "[Interface]\nAddress = 10.240.0.2/32\nListenPort = 51820\nPrivateKey = private-secret\n\n[Peer]\nPublicKey = peer-a\nEndpoint = 192.0.2.3:51820\nAllowedIPs = 10.240.0.3/32, 100.64.1.0/24\nPersistentKeepalive = 25\n\n[Peer]\nPublicKey = peer-b\nEndpoint = 192.0.2.4:51820\nAllowedIPs = 10.240.0.4/32\nPersistentKeepalive = 25\n\n";

    fn firewall_request() -> FirewallReconcileRequest {
        FirewallReconcileRequest {
            revision: 3,
            wireguard_port: 51820,
            cluster_cidr: "10.240.0.0/24".into(),
            local_node_ip: "10.240.0.2".into(),
            rules: vec![],
            wireguard_interface: "coolify0".into(),
            flux_probe_host: String::new(),
            workload_cidrs: vec!["100.64.1.0/24".into(), "100.64.0.0/24".into()],
            ingress_rules: vec![],
        }
    }

    /// Writes the files a fully applied cluster network leaves behind.
    fn applied_root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(root, "etc/wireguard/coolify0.conf", WIREGUARD_CONFIG);
        write(root, "var/lib/coolify/network/coolify0.state", "7 hash\n");
        write(root, "var/lib/coolify/network/firewall.state", "3 hash\n");
        write(
            root,
            "var/lib/coolify/network/firewall.last-good.nft",
            &render_firewall(&firewall_request()).unwrap(),
        );
        write(root, "etc/corrosion/config.toml", "config");
        write(root, CORROSION_OWNER_FILE, "10.240.0.2\n");
        write(
            root,
            "etc/systemd/system/corrosion.service",
            corrosion_unit(),
        );
        write(
            root,
            "etc/systemd/system/coolify-discovery-dns.service",
            &corrosion_dns_unit("10.240.0.2").unwrap(),
        );
        temp
    }

    fn live(links_up: &[&str], tables: bool, corrosion_active: bool) -> LiveNetwork {
        LiveNetwork {
            links_up: links_up.iter().map(|link| link.to_string()).collect(),
            inet_table_exists: tables,
            bridge_table_exists: tables,
            corrosion_active,
        }
    }

    #[test]
    fn restore_reads_the_applied_network_without_keys() {
        let temp = applied_root();
        let applied = read_applied_network(temp.path());

        assert_eq!(
            applied.wireguard,
            vec![AppliedWireguard {
                interface: "coolify0".into(),
                address: "10.240.0.2/32".into(),
                peer_addresses: vec![
                    "10.240.0.3/32".into(),
                    "100.64.1.0/24".into(),
                    "10.240.0.4/32".into(),
                ],
            }]
        );
        assert_eq!(
            applied.firewall,
            Some(AppliedFirewall {
                wireguard_interface: "coolify0".into(),
                workload_cidrs: vec!["100.64.0.0/24".into(), "100.64.1.0/24".into()],
            })
        );
        assert_eq!(
            applied.corrosion,
            Some(AppliedCorrosion {
                units_current: true,
                dns_unit_installed: true,
            })
        );
        assert!(applied.problems.is_empty());
        assert!(!format!("{applied:?}").contains("private-secret"));
    }

    #[test]
    fn restore_is_a_no_op_without_an_applied_network() {
        let temp = tempfile::tempdir().unwrap();
        // Files without their applied-state partner are not an applied network.
        write(temp.path(), "etc/wireguard/coolify0.conf", WIREGUARD_CONFIG);
        write(
            temp.path(),
            "var/lib/coolify/network/firewall.last-good.nft",
            &render_firewall(&firewall_request()).unwrap(),
        );
        write(temp.path(), "etc/corrosion/config.toml", "config");
        write(
            temp.path(),
            "var/lib/coolify/network/mesh9.state",
            "1 hash\n",
        );
        write(
            temp.path(),
            "var/lib/coolify/network/firewall.state",
            "3 hash\n",
        );
        fs::remove_file(state_path(temp.path(), "firewall.last-good.nft")).unwrap();

        let applied = read_applied_network(temp.path());

        assert!(applied.is_empty());
        assert_eq!(
            restore_plan(&applied, &live(&[], false, false)),
            RestorePlan::default()
        );
    }

    #[test]
    fn restore_brings_back_a_missing_link_and_firewall_and_restarts_corrosion() {
        let temp = applied_root();
        let applied = read_applied_network(temp.path());

        let plan = restore_plan(&applied, &live(&[], false, false));

        assert_eq!(
            plan.before_workloads,
            vec![
                RestoreStep::BridgeSysctls,
                RestoreStep::LoadFirewall {
                    inet_table_exists: false,
                    bridge_table_exists: false,
                },
                RestoreStep::WireguardUp {
                    interface: "coolify0".into(),
                    address: "10.240.0.2/32".into(),
                },
                RestoreStep::DiscoveryResolver {
                    interface: "coolify0".into(),
                    address: "10.240.0.2/32".into(),
                    peer_addresses: applied.wireguard[0].peer_addresses.clone(),
                },
                RestoreStep::RestartCorrosion,
                RestoreStep::StartDiscoveryDns,
            ]
        );
        assert_eq!(
            plan.after_workloads,
            vec![RestoreStep::MeshNat {
                interface: "coolify0".into(),
                workload_cidrs: vec!["100.64.0.0/24".into(), "100.64.1.0/24".into()],
            }]
        );
        // A test root never runs host commands, so every step succeeds.
        for step in plan.before_workloads.iter().chain(&plan.after_workloads) {
            apply_restore_step(temp.path(), step).unwrap();
        }
    }

    #[test]
    fn restore_keeps_a_live_network_and_only_reapplies_non_persistent_state() {
        let temp = applied_root();
        let applied = read_applied_network(temp.path());

        let plan = restore_plan(&applied, &live(&["coolify0"], true, true));

        assert_eq!(
            plan.before_workloads,
            vec![
                RestoreStep::BridgeSysctls,
                RestoreStep::DiscoveryResolver {
                    interface: "coolify0".into(),
                    address: "10.240.0.2/32".into(),
                    peer_addresses: applied.wireguard[0].peer_addresses.clone(),
                },
                RestoreStep::StartDiscoveryDns,
            ]
        );
        assert_eq!(plan.after_workloads.len(), 1);

        // Only one firewall table missing still reloads, replacing the other.
        let plan = restore_plan(
            &applied,
            &LiveNetwork {
                bridge_table_exists: false,
                ..live(&["coolify0"], true, true)
            },
        );
        assert!(plan.before_workloads.contains(&RestoreStep::LoadFirewall {
            inet_table_exists: true,
            bridge_table_exists: false,
        }));
        assert!(
            !plan
                .before_workloads
                .contains(&RestoreStep::RestartCorrosion)
        );

        // A failed Corrosion restarts even when the link was already up.
        let plan = restore_plan(&applied, &live(&["coolify0"], true, false));
        assert!(
            plan.before_workloads
                .contains(&RestoreStep::RestartCorrosion)
        );
    }

    #[test]
    fn restore_refreshes_corrosion_units_written_by_an_older_sentinel() {
        let temp = applied_root();
        write(
            temp.path(),
            "etc/systemd/system/corrosion.service",
            "[Service]\nRestart=on-failure\n",
        );
        write(
            temp.path(),
            "etc/systemd/system/coolify-discovery-dns.service",
            "[Unit]\nRequires=corrosion.service\n",
        );
        let applied = read_applied_network(temp.path());
        assert!(!applied.corrosion.as_ref().unwrap().units_current);

        let plan = restore_plan(&applied, &live(&["coolify0"], true, true));
        assert!(
            plan.before_workloads
                .contains(&RestoreStep::RefreshCorrosionUnits)
        );

        // The refresh writes the current templates; a test root skips systemd.
        refresh_corrosion_units(temp.path()).unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join("etc/systemd/system/corrosion.service")).unwrap(),
            corrosion_unit()
        );
        assert!(
            read_applied_network(temp.path())
                .corrosion
                .unwrap()
                .units_current
        );
    }

    #[test]
    fn restore_starts_the_ingress_and_refreshes_an_outdated_unit() {
        let temp = applied_root();
        assert!(read_applied_network(temp.path()).ingress.is_none());

        write(
            temp.path(),
            "var/lib/coolify/network/ingress.state",
            "enabled v2.11.7\n",
        );
        write(
            temp.path(),
            crate::ingress::INGRESS_UNIT_FILE,
            &crate::ingress::ingress_unit(),
        );
        let applied = read_applied_network(temp.path());
        assert_eq!(applied.ingress, Some(AppliedIngress { unit_current: true }));
        let plan = restore_plan(&applied, &live(&["coolify0"], true, true));
        assert_eq!(
            plan.before_workloads.last(),
            Some(&RestoreStep::StartIngress)
        );
        assert!(
            !plan
                .before_workloads
                .contains(&RestoreStep::RefreshIngressUnit)
        );

        write(
            temp.path(),
            crate::ingress::INGRESS_UNIT_FILE,
            "[Service]\nExecStart=/usr/local/bin/caddy run\nRestart=on-failure\n",
        );
        let applied = read_applied_network(temp.path());
        assert_eq!(
            applied.ingress,
            Some(AppliedIngress {
                unit_current: false
            })
        );
        let plan = restore_plan(&applied, &live(&["coolify0"], true, true));
        assert_eq!(
            plan.before_workloads[plan.before_workloads.len() - 2..],
            [RestoreStep::RefreshIngressUnit, RestoreStep::StartIngress]
        );

        // The refresh writes the current template; a test root skips systemd.
        for step in &plan.before_workloads {
            apply_restore_step(temp.path(), step).unwrap();
        }
        assert_eq!(
            fs::read_to_string(temp.path().join(crate::ingress::INGRESS_UNIT_FILE)).unwrap(),
            crate::ingress::ingress_unit()
        );
        assert!(
            read_applied_network(temp.path())
                .ingress
                .unwrap()
                .unit_current
        );
    }

    #[test]
    fn restore_never_recreates_an_ingress_unit_that_was_removed() {
        let temp = tempfile::tempdir().unwrap();
        apply_restore_step(temp.path(), &RestoreStep::RefreshIngressUnit).unwrap();
        assert!(!temp.path().join(crate::ingress::INGRESS_UNIT_FILE).exists());
        assert!(read_applied_network(temp.path()).is_empty());
    }

    #[test]
    fn corrosion_schema_declares_the_ingress_route_table_and_is_rewritten_when_outdated() {
        assert!(corrosion_schema().contains("CREATE TABLE IF NOT EXISTS ingress_routes (host TEXT NOT NULL PRIMARY KEY, workload_id TEXT NOT NULL DEFAULT '', namespace TEXT NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"));
        assert!(corrosion_schema().starts_with("CREATE TABLE IF NOT EXISTS workload_endpoints"));

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("etc/corrosion/schemas/coolify.sql");
        write(
            temp.path(),
            "etc/corrosion/schemas/coolify.sql",
            "CREATE TABLE IF NOT EXISTS workload_endpoints (old);\n",
        );
        assert!(ensure_corrosion_schema(temp.path()).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), corrosion_schema());
        assert!(!ensure_corrosion_schema(temp.path()).unwrap());
    }

    #[test]
    fn restore_reports_applied_state_it_cannot_read() {
        let temp = applied_root();
        write(
            temp.path(),
            "etc/wireguard/coolify0.conf",
            "[Interface]\nPrivateKey = private-secret\n",
        );
        write(
            temp.path(),
            "var/lib/coolify/network/firewall.last-good.nft",
            "table inet coolify_cluster {}\n",
        );

        let applied = read_applied_network(temp.path());

        assert!(applied.wireguard.is_empty());
        assert!(applied.firewall.is_none());
        assert_eq!(applied.problems.len(), 2);
        assert!(!applied.is_empty());
        assert!(!format!("{applied:?}").contains("private-secret"));
    }

    #[test]
    fn firewall_snapshot_parsing_accepts_nft_list_output() {
        let listed = "table inet coolify_cluster {\n\tset workload_networks {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 100.64.0.0/24, 100.64.1.0/24,\n\t\t\t     100.64.2.5 }\n\t}\n\n\tchain input {\n\t\tiifname \"mesh0\" ip saddr != 10.240.0.0/24 ip saddr != @workload_networks drop\n\t}\n}\n";

        assert_eq!(
            parse_firewall_snapshot(listed),
            Some(AppliedFirewall {
                wireguard_interface: "mesh0".into(),
                workload_cidrs: vec![
                    "100.64.0.0/24".into(),
                    "100.64.1.0/24".into(),
                    "100.64.2.5/32".into(),
                ],
            })
        );
        assert_eq!(
            parse_firewall_snapshot(
                "iifname \"../eth0\" set workload_networks { elements = { 100.64.0.0/24 } }"
            ),
            None
        );
        assert_eq!(parse_firewall_snapshot("iifname \"mesh0\""), None);
    }

    #[test]
    fn cluster_leave_rejects_untrusted_network_identifiers() {
        assert!(
            validate_cluster_leave(&ClusterLeaveRequest {
                interface: "../../eth0".into(),
                owner_node_ip: "10.240.0.2".into(),
                workload_cidrs: vec![],
            })
            .is_err()
        );
        assert!(
            validate_cluster_leave(&ClusterLeaveRequest {
                interface: "coolify0".into(),
                owner_node_ip: "not-an-ip".into(),
                workload_cidrs: vec![],
            })
            .is_err()
        );
    }
}
