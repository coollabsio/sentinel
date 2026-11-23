//! Registry logins and the Podman helpers that the BuildKit service shares.
//!
//! Sentinel has no registry of its own. Builds load into the local Podman
//! store or push to an external registry with a login from Coolify; other
//! Nodes fetch local images from a peer (`image_transfer.rs`). The built-in
//! zot registry of earlier versions is removed when Sentinel starts
//! ([`remove_builtin_registry`]).

use std::path::Path;
use std::process::Command;

use crate::commands::{PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::output_with_timeout;

pub(crate) const SERVICE_LABEL: &str = "coolify.service";
pub(crate) const CONFIG_HASH_LABEL: &str = "coolify.config-hash";

/// What the built-in registry (`registry.reconcile.v1`) of earlier versions
/// left on a Node: the zot container and its data volume, its files, the CA
/// that Podman trusted for it, and the copies of that CA and of the push
/// login in the BuildKit files.
const OLD_REGISTRY_CONTAINER: &str = "coolify-registry";
const OLD_REGISTRY_VOLUME: &str = "coolify-registry";
const OLD_REGISTRY_PATHS: [&str; 4] = [
    "etc/coolify/registry",
    "etc/containers/certs.d/registry.cluster.coolify.internal:5443",
    "etc/coolify/builder/registry-ca.crt",
    "etc/coolify/builder/docker",
];

/// Removes the built-in registry of an earlier version. Best effort and
/// idempotent; runs when Sentinel starts.
pub(crate) fn remove_builtin_registry(root: &Path, podman: &Path) {
    let mut removed_any = false;
    for path in OLD_REGISTRY_PATHS {
        let path = root.join(path);
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => removed_any = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "could not remove a file of the old registry")
            }
        }
    }
    let container = output_with_timeout(
        Command::new(podman).args(["container", "exists", OLD_REGISTRY_CONTAINER]),
        PODMAN_QUERY_TIMEOUT,
    )
    .is_ok_and(|output| output.status.success());
    let volume = output_with_timeout(
        Command::new(podman).args(["volume", "exists", OLD_REGISTRY_VOLUME]),
        PODMAN_QUERY_TIMEOUT,
    )
    .is_ok_and(|output| output.status.success());
    if (container || volume)
        && let Err(error) =
            remove_container_and_volume(podman, OLD_REGISTRY_CONTAINER, OLD_REGISTRY_VOLUME)
    {
        tracing::warn!(%error, "could not remove the old registry");
        return;
    }
    if container || volume || removed_any {
        tracing::info!("removed the built-in registry of an earlier version");
    }
}

const DOCKER_HUB: &str = "docker.io";

/// A Docker-format auth file with one login that only `host` gets. Docker Hub
/// also gets the legacy key that BuildKit looks up.
pub(crate) fn login_auth_file(host: &str, username: &str, password: &str) -> Vec<u8> {
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    let mut auths = serde_json::Map::new();
    auths.insert(host.into(), serde_json::json!({ "auth": token }));
    if host == DOCKER_HUB {
        auths.insert(
            "https://index.docker.io/v1/".into(),
            serde_json::json!({ "auth": token }),
        );
    }
    serde_json::to_vec_pretty(&serde_json::json!({ "auths": auths })).unwrap_or_default()
}

/// The registry host of an image reference, the way Podman reads it: the first
/// path part is a host only when it has a `.` or a `:`, or is `localhost`.
pub(crate) fn image_registry_host(image: &str) -> String {
    let host = match image.split_once('/') {
        Some((first, _)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            first.to_ascii_lowercase()
        }
        _ => return DOCKER_HUB.into(),
    };
    match host.as_str() {
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com" => DOCKER_HUB.into(),
        _ => host,
    }
}

pub(crate) fn validate_login(username: &str, password: &str) -> Result<bool, String> {
    if username.is_empty() && password.is_empty() {
        return Ok(false);
    }
    let printable = |value: &str| value.chars().all(|character| !character.is_control());
    if username.is_empty()
        || username.len() > 255
        || username.contains(':')
        || !printable(username)
        || password.is_empty()
        || password.len() > 8_192
        || !printable(password)
    {
        return Err("The registry login is invalid.".into());
    }
    Ok(true)
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
