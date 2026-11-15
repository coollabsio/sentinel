//! `registry.inspect.v1`: a read-only report of the cluster registry and the
//! build cache on this Node, for the Image registry section in Coolify.
//!
//! Every Node reports the disk use of its registry volume and BuildKit cache.
//! The registry Node also asks zot, over TLS with the pull credential, whether
//! it answers, and which repositories and tags it stores.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sentinel_protocol::REGISTRY_HOST;
use sentinel_protocol::control::v1::{RegistryInspectResult, RegistryRepository, RegistryTag};

use crate::commands::PODMAN_QUERY_TIMEOUT;
use crate::network::output_with_timeout;

const BUILDKIT_CONTAINER: &str = crate::builder::BUILDKIT_CONTAINER;
const REGISTRY_VOLUME: &str = "coolify-registry";
const BUILDKIT_VOLUME: &str = "coolify-buildkit";
const MAX_REPOSITORIES: usize = 100;
const MAX_TAGS: usize = 50;
const MAX_TAG_LOOKUPS: usize = 300;
const MAX_WALKED_ENTRIES: usize = 500_000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn inspect(root: &Path, podman: &Path) -> RegistryInspectResult {
    let registry_running = container_running(podman, crate::registry::REGISTRY_CONTAINER);
    let mut result = RegistryInspectResult {
        registry_running,
        builder_running: container_running(podman, BUILDKIT_CONTAINER),
        registry_bytes: volume_bytes(podman, REGISTRY_VOLUME),
        build_cache_bytes: volume_bytes(podman, BUILDKIT_VOLUME),
        ..Default::default()
    };
    if !registry_running {
        return result;
    }
    match query_zot(root) {
        Ok((repositories, truncated)) => {
            result.healthy = true;
            result.repositories = repositories;
            result.repositories_truncated = truncated;
        }
        Err(message) => result.error = message,
    }
    result
}

fn container_running(podman: &Path, name: &str) -> bool {
    output_with_timeout(
        Command::new(podman).args([
            "container",
            "inspect",
            "--format",
            "{{.State.Running}}",
            name,
        ]),
        PODMAN_QUERY_TIMEOUT,
    )
    .is_ok_and(|output| {
        output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
    })
}

/// Bytes used by a named volume. zot dedupes blobs with hard links, so each
/// inode counts once.
fn volume_bytes(podman: &Path, volume: &str) -> u64 {
    let Ok(output) = output_with_timeout(
        Command::new(podman).args(["volume", "inspect", "--format", "{{.Mountpoint}}", volume]),
        PODMAN_QUERY_TIMEOUT,
    ) else {
        return 0;
    };
    if !output.status.success() {
        return 0;
    }
    let mountpoint = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if mountpoint.is_empty() {
        return 0;
    }
    let mut seen = HashSet::new();
    let mut stack = vec![std::path::PathBuf::from(mountpoint)];
    let mut total = 0_u64;
    let mut walked = 0_usize;
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            walked += 1;
            if walked > MAX_WALKED_ENTRIES {
                return total;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() && seen.insert((metadata.dev(), metadata.ino())) {
                total = total.saturating_add(metadata.blocks().saturating_mul(512));
            }
        }
    }
    total
}

fn pull_authorization(root: &Path) -> Result<String, String> {
    let raw = std::fs::read(crate::registry::pull_auth_path(root))
        .map_err(|_| "The registry pull credential is missing on this Node.".to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| "The registry pull credential is invalid.".to_string())?;
    value
        .pointer(&format!(
            "/auths/{}/auth",
            REGISTRY_HOST.replace('~', "~0").replace('/', "~1")
        ))
        .and_then(serde_json::Value::as_str)
        .map(|auth| format!("Basic {auth}"))
        .ok_or_else(|| "The registry pull credential is invalid.".to_string())
}

type Repositories = (Vec<RegistryRepository>, bool);

fn query_zot(root: &Path) -> Result<Repositories, String> {
    let identity =
        crate::discovery::read_identity(root)?.ok_or("This Node is not in a cluster.")?;
    let address: IpAddr = identity
        .owner_node_ip
        .parse()
        .map_err(|_| "The Node mesh address is invalid.".to_string())?;
    let ca = std::fs::read(crate::registry::ca_path(root))
        .map_err(|_| "The registry CA is missing on this Node.".to_string())?;
    let authorization = pull_authorization(root)?;
    let (host, port) = REGISTRY_HOST
        .split_once(':')
        .unwrap_or((REGISTRY_HOST, "5443"));
    let port: u16 = port.parse().unwrap_or(5443);
    let client = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(&ca)
            .map_err(|_| "The registry CA is invalid.".to_string())?])
        .resolve(host, SocketAddr::new(address, port))
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "The registry client could not be created.".to_string())?;
    let base = format!("https://{REGISTRY_HOST}/v2");
    let handle = tokio::runtime::Handle::current();
    handle.block_on(async move {
        let get = |url: String| {
            let request = client.get(url).header(reqwest::header::AUTHORIZATION, &authorization);
            async move {
                let response = request
                    .send()
                    .await
                    .map_err(|error| format!("The registry did not answer: {error}"))?;
                if !response.status().is_success() {
                    return Err(format!("The registry answered HTTP {}.", response.status().as_u16()));
                }
                Ok(response)
            }
        };
        get(format!("{base}/")).await?;
        let catalog: serde_json::Value = get(format!("{base}/_catalog?n={}", MAX_REPOSITORIES + 1))
            .await?
            .json()
            .await
            .map_err(|_| "The registry returned an invalid catalog.".to_string())?;
        let mut names: Vec<String> = catalog
            .get("repositories")
            .and_then(serde_json::Value::as_array)
            .map(|names| names.iter().filter_map(|name| name.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let mut truncated = names.len() > MAX_REPOSITORIES;
        names.truncate(MAX_REPOSITORIES);
        let mut lookups = 0_usize;
        let mut repositories = Vec::with_capacity(names.len());
        for name in names {
            let tags: serde_json::Value = get(format!("{base}/{name}/tags/list"))
                .await?
                .json()
                .await
                .map_err(|_| "The registry returned an invalid tag list.".to_string())?;
            let mut tag_names: Vec<String> = tags
                .get("tags")
                .and_then(serde_json::Value::as_array)
                .map(|tags| tags.iter().filter_map(|tag| tag.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            if tag_names.len() > MAX_TAGS {
                truncated = true;
                tag_names.truncate(MAX_TAGS);
            }
            let mut repository_tags = Vec::with_capacity(tag_names.len());
            for tag in tag_names {
                let mut digest = String::new();
                if lookups < MAX_TAG_LOOKUPS {
                    lookups += 1;
                    let response = client
                        .head(format!("{base}/{name}/manifests/{tag}"))
                        .header(reqwest::header::AUTHORIZATION, &authorization)
                        .header(
                            reqwest::header::ACCEPT,
                            "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json",
                        )
                        .send()
                        .await;
                    if let Ok(response) = response {
                        digest = response
                            .headers()
                            .get("docker-content-digest")
                            .and_then(|value| value.to_str().ok())
                            .filter(|value| value.starts_with("sha256:") && value.len() == 71)
                            .unwrap_or_default()
                            .to_string();
                    }
                } else {
                    truncated = true;
                }
                repository_tags.push(RegistryTag { tag, digest });
            }
            repositories.push(RegistryRepository { name, tags: repository_tags });
        }
        Ok((repositories, truncated))
    })
}
