//! The cluster image registry (`registry.reconcile.v1`).
//!
//! Every Node gets the registry trust: the registry CA in Podman's `certs.d`
//! and a pull credential that `workload.deploy` passes to Podman. The registry
//! Node also runs zot as the `coolify-registry` container on its mesh address.
//! Discovery publishes that Node as `registry.cluster.coolify.internal`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sentinel_protocol::REGISTRY_HOST;
use sentinel_protocol::control::v1::{
    RegistryReconcileRequest, RegistryReconcileResult, RegistryServer,
};

use crate::commands::{PODMAN_DEPLOY_TIMEOUT, PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::{hash, output_with_timeout, write_if_changed};

/// zot v2.1.23, multi-architecture index.
pub(crate) const ZOT_IMAGE: &str = "ghcr.io/project-zot/zot:v2.1.23@sha256:9d3de83ac2099e6f4843045b4c9b65b7e8baf40f92d28f54906dee9d4d390fd7";
pub(crate) const REGISTRY_CONTAINER: &str = "coolify-registry";
pub(crate) const SERVICE_LABEL: &str = "coolify.service";
pub(crate) const CONFIG_HASH_LABEL: &str = "coolify.config-hash";
const REGISTRY_VOLUME: &str = "coolify-registry";
const REGISTRY_PORT: u16 = 5443;
const CERTS_DIR: &str = "etc/containers/certs.d";
const REGISTRY_DIR: &str = "etc/coolify/registry";
const MAX_PEM_BYTES: usize = 64 * 1024;

pub(crate) fn ca_path(root: &Path) -> PathBuf {
    root.join(CERTS_DIR).join(REGISTRY_HOST).join("ca.crt")
}

/// The Podman auth file with the pull credential, when this Node has one.
pub(crate) fn pull_auth_path(root: &Path) -> PathBuf {
    root.join(REGISTRY_DIR).join("pull-auth.json")
}

fn server_dir(root: &Path) -> PathBuf {
    root.join(REGISTRY_DIR).join("server")
}

pub(crate) fn valid_username(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
}

pub(crate) fn valid_password(value: &str) -> bool {
    (16..=256).contains(&value.len()) && value.chars().all(|character| character.is_ascii_graphic())
}

fn valid_certificate_pem(value: &str) -> bool {
    value.len() <= MAX_PEM_BYTES
        && value
            .trim_start()
            .starts_with("-----BEGIN CERTIFICATE-----")
        && !value.contains("PRIVATE KEY")
}

pub(crate) fn validate(request: &RegistryReconcileRequest) -> Result<(), String> {
    if !valid_certificate_pem(&request.ca_pem) {
        return Err("The registry CA is invalid.".into());
    }
    if !valid_username(&request.pull_username) || !valid_password(&request.pull_password) {
        return Err("The registry pull credential is invalid.".into());
    }
    if let Some(server) = &request.server {
        validate_server(server)?;
    }
    Ok(())
}

fn validate_server(server: &RegistryServer) -> Result<(), String> {
    if !valid_certificate_pem(&server.certificate_pem) {
        return Err("The registry certificate is invalid.".into());
    }
    if server.private_key_pem.len() > MAX_PEM_BYTES
        || !server
            .private_key_pem
            .trim_start()
            .starts_with("-----BEGIN ")
        || !server.private_key_pem.contains("PRIVATE KEY-----")
    {
        return Err("The registry private key is invalid.".into());
    }
    if !valid_username(&server.push_username) || !(1..=100).contains(&server.keep_tags) {
        return Err("The registry server settings are invalid.".into());
    }
    let lines: Vec<&str> = server
        .htpasswd
        .lines()
        .filter(|line| !line.is_empty())
        .collect();
    let valid_line = |line: &&str| {
        line.split_once(':').is_some_and(|(user, hash)| {
            valid_username(user)
                && ["$2a$", "$2b$", "$2y$"]
                    .iter()
                    .any(|prefix| hash.starts_with(prefix))
                && hash.len() <= 128
                && hash.chars().all(|character| character.is_ascii_graphic())
        })
    };
    if lines.is_empty()
        || lines.len() > 16
        || !lines.iter().all(valid_line)
        || !lines
            .iter()
            .any(|line| line.split_once(':').map(|(user, _)| user) == Some(&server.push_username))
    {
        return Err("The registry htpasswd is invalid.".into());
    }
    Ok(())
}

/// A Docker-format auth file for one user of the cluster registry.
pub(crate) fn auth_file(username: &str, password: &str) -> Vec<u8> {
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    serde_json::to_vec_pretty(&serde_json::json!({ "auths": { REGISTRY_HOST: { "auth": token } } }))
        .unwrap_or_default()
}

pub(crate) fn zot_config(address: &str, push_username: &str, keep_tags: u32) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "distSpecVersion": "1.1.1",
        "storage": {
            "rootDirectory": "/var/lib/registry",
            "dedupe": true,
            "gc": true,
            "gcDelay": "1h",
            "gcInterval": "1h",
            "retention": {
                "delay": "1h",
                "policies": [{
                    "repositories": ["**"],
                    "deleteReferrers": true,
                    "deleteUntagged": true,
                    "keepTags": [{ "patterns": [".*"], "mostRecentlyPushedCount": keep_tags }],
                }],
            },
        },
        "http": {
            "address": address,
            "port": REGISTRY_PORT.to_string(),
            "tls": { "cert": "/etc/zot/tls.crt", "key": "/etc/zot/tls.key" },
            "auth": { "htpasswd": { "path": "/etc/zot/htpasswd" } },
            "accessControl": {
                "repositories": {
                    "**": {
                        "policies": [{ "users": [push_username], "actions": ["read", "create", "update", "delete"] }],
                        // Every other user with a valid login can only pull.
                        "defaultPolicy": ["read"],
                        "anonymousPolicy": [],
                    },
                },
            },
        },
        "log": { "level": "warn" },
    }))
    .unwrap_or_default()
}

pub(crate) fn reconcile(
    root: &Path,
    podman: &Path,
    request: &RegistryReconcileRequest,
) -> Result<RegistryReconcileResult, String> {
    validate(request)?;
    write_if_changed(&ca_path(root), request.ca_pem.as_bytes(), 0o644)?;
    write_if_changed(
        &pull_auth_path(root),
        &auth_file(&request.pull_username, &request.pull_password),
        0o600,
    )?;

    let server_running = match &request.server {
        Some(server) => {
            ensure_server(root, podman, server)?;
            true
        }
        None => {
            remove_server(root, podman)?;
            false
        }
    };
    Ok(RegistryReconcileResult {
        trust_installed: true,
        server_running,
        registry_host: REGISTRY_HOST.into(),
    })
}

fn ensure_server(root: &Path, podman: &Path, server: &RegistryServer) -> Result<(), String> {
    let identity = crate::discovery::read_identity(root)?
        .ok_or("This Node is not in a cluster, so it cannot run the registry.")?;
    let config = zot_config(
        &identity.owner_node_ip,
        &server.push_username,
        server.keep_tags,
    );

    let dir = server_dir(root);
    let htpasswd = format!("{}\n", server.htpasswd.trim_end());
    let files: [(&str, &[u8], u32); 4] = [
        ("config.json", &config, 0o600),
        ("tls.crt", server.certificate_pem.as_bytes(), 0o600),
        ("tls.key", server.private_key_pem.as_bytes(), 0o600),
        ("htpasswd", htpasswd.as_bytes(), 0o600),
    ];
    let mut fingerprint = Vec::new();
    for (name, contents, mode) in files {
        write_if_changed(&dir.join(name), contents, mode)?;
        fingerprint.extend_from_slice(name.as_bytes());
        fingerprint.extend_from_slice(contents);
    }
    fingerprint.extend_from_slice(ZOT_IMAGE.as_bytes());
    let config_hash = hash(&fingerprint);
    if running_with_hash(podman, REGISTRY_CONTAINER, &config_hash) {
        return Ok(());
    }

    let mount = |file: &str, target: &str| format!("{}:{target}:ro", dir.join(file).display());
    let arguments: Vec<String> = vec![
        "run".into(),
        "--detach".into(),
        "--replace".into(),
        "--pull".into(),
        "missing".into(),
        "--name".into(),
        REGISTRY_CONTAINER.into(),
        "--restart".into(),
        "always".into(),
        "--label".into(),
        "coolify.managed=true".into(),
        "--label".into(),
        format!("{SERVICE_LABEL}=registry"),
        "--label".into(),
        format!("{CONFIG_HASH_LABEL}={config_hash}"),
        "--network".into(),
        "host".into(),
        "--cap-drop".into(),
        "all".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--read-only".into(),
        "--volume".into(),
        format!("{REGISTRY_VOLUME}:/var/lib/registry"),
        "--volume".into(),
        mount("config.json", "/etc/zot/config.json"),
        "--volume".into(),
        mount("tls.crt", "/etc/zot/tls.crt"),
        "--volume".into(),
        mount("tls.key", "/etc/zot/tls.key"),
        "--volume".into(),
        mount("htpasswd", "/etc/zot/htpasswd"),
        ZOT_IMAGE.into(),
        "serve".into(),
        "/etc/zot/config.json".into(),
    ];
    let output = output_with_timeout(Command::new(podman).args(arguments), PODMAN_DEPLOY_TIMEOUT)
        .map_err(|error| podman_failure(&error))?;
    if !output.status.success() {
        return Err(stderr_or(
            &output.stderr,
            "Podman could not start the registry.",
        ));
    }
    Ok(())
}

/// Stops zot on a Node that no longer runs the registry. The image data stays
/// in its volume: a short outage can move the role and back, and a returning
/// role must not start with an empty registry.
fn remove_server(root: &Path, podman: &Path) -> Result<(), String> {
    let output = output_with_timeout(
        Command::new(podman).args(["rm", "--force", "--ignore", REGISTRY_CONTAINER]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if !output.status.success() {
        return Err(stderr_or(
            &output.stderr,
            "Podman could not stop the registry.",
        ));
    }
    match std::fs::remove_dir_all(server_dir(root)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("The registry files could not be removed.".into()),
    }
}

/// Whether a container runs and was started with this configuration hash.
pub(crate) fn running_with_hash(podman: &Path, name: &str, config_hash: &str) -> bool {
    let format =
        format!("{{{{.State.Running}}}} {{{{index .Config.Labels \"{CONFIG_HASH_LABEL}\"}}}}");
    output_with_timeout(
        Command::new(podman).args(["container", "inspect", "--format", &format, name]),
        PODMAN_QUERY_TIMEOUT,
    )
    .is_ok_and(|output| {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == format!("true {config_hash}")
    })
}

pub(crate) fn remove_container_and_volume(
    podman: &Path,
    container: &str,
    volume: &str,
) -> Result<(), String> {
    for arguments in [
        vec!["rm", "--force", "--ignore", container],
        vec!["volume", "rm", "--force", volume],
    ] {
        let output =
            output_with_timeout(Command::new(podman).args(&arguments), PODMAN_QUERY_TIMEOUT)
                .map_err(|error| podman_failure(&error))?;
        let missing = String::from_utf8_lossy(&output.stderr).contains("no such volume");
        if !output.status.success() && !missing {
            return Err(stderr_or(
                &output.stderr,
                "Podman could not remove the service.",
            ));
        }
    }
    Ok(())
}

pub(crate) fn stderr_or(stderr: &[u8], fallback: &str) -> String {
    let message: String = String::from_utf8_lossy(stderr)
        .trim()
        .chars()
        .take(2_000)
        .collect();
    if message.is_empty() {
        fallback.into()
    } else {
        message
    }
}
