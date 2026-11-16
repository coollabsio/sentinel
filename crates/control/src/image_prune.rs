//! `image.prune.v1`: removes the images that no container uses, except the
//! images that Coolify keeps for rollbacks and the infrastructure images, and
//! the `coolify-build-*` containers of builds that ended (decision 0027 of
//! Coolify). It never touches volumes, networks, the BuildKit cache, or the
//! registry data.

use std::collections::HashSet;
use std::path::Path;

use sentinel_protocol::control::v1::{ImagePruneRequest, ImagePruneResult};
use serde::Deserialize;
use sysinfo::Disks;

use crate::builder::BUILDKIT_IMAGE;
use crate::commands::{PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::output_with_timeout;
use crate::registry::ZOT_IMAGE;

pub(crate) const MAX_KEEP: usize = 2048;
const MAX_REFERENCE: usize = 512;
const MAX_RUNNING_BUILDS: usize = 64;
const BUILD_CONTAINER_PREFIX: &str = "coolify-build-";
/// Install and upgrade copy the Sentinel binary out of this image. The newest
/// one stays, so a repair does not need a pull.
const SENTINEL_HOST_REPOSITORY: &str = "ghcr.io/coollabsio/sentinel-host";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ImageRecord {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) names: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) repo_digests: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) digest: String,
    #[serde(default)]
    pub(crate) created: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(crate) struct ContainerRecord {
    #[serde(default)]
    pub(crate) names: Vec<String>,
    #[serde(rename = "ImageID", default)]
    pub(crate) image_id: String,
    #[serde(default)]
    pub(crate) state: String,
}

impl ImageRecord {
    fn names(&self) -> &[String] {
        self.names.as_deref().unwrap_or_default()
    }

    fn repo_digests(&self) -> &[String] {
        self.repo_digests.as_deref().unwrap_or_default()
    }

    /// A name, else a digest reference, else the ID.
    fn label(&self) -> String {
        self.names()
            .first()
            .or_else(|| self.repo_digests().first())
            .cloned()
            .unwrap_or_else(|| format!("sha256:{}", self.id))
    }

    fn repositories(&self) -> impl Iterator<Item = String> + '_ {
        self.names()
            .iter()
            .chain(self.repo_digests())
            .map(|reference| repository(reference).to_string())
    }
}

pub(crate) fn validate(request: &ImagePruneRequest) -> Result<(), String> {
    if request.keep.len() > MAX_KEEP || request.keep.iter().any(|value| !valid_reference(value)) {
        return Err("The keep list of the image cleanup is invalid.".into());
    }
    if request.running_build_containers.len() > MAX_RUNNING_BUILDS
        || request
            .running_build_containers
            .iter()
            .any(|name| !valid_build_container(name))
    {
        return Err("The running build containers of the image cleanup are invalid.".into());
    }
    Ok(())
}

fn valid_reference(value: &str) -> bool {
    (1..=MAX_REFERENCE).contains(&value.len())
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:/@-".contains(character))
}

fn valid_build_container(name: &str) -> bool {
    name.strip_prefix(BUILD_CONTAINER_PREFIX).is_some_and(|id| {
        (1..=128).contains(&id.len())
            && id
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    })
}

/// The repository of a reference, without its tag or digest.
fn repository(reference: &str) -> &str {
    let without_digest = reference.split('@').next().unwrap_or(reference);
    match without_digest.rfind(':') {
        Some(colon) if !without_digest[colon..].contains('/') => &without_digest[..colon],
        _ => without_digest,
    }
}

/// The Podman form of a reference: `nginx` is `docker.io/library/nginx:latest`.
fn normalize(reference: &str) -> String {
    let (name, digest) = match reference.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (reference, None),
    };
    let has_tag = name
        .rfind(':')
        .is_some_and(|colon| !name[colon..].contains('/'));
    let mut parts = name.splitn(2, '/');
    let first = parts.next().unwrap_or_default();
    let qualified = match parts.next() {
        Some(_) if first.contains('.') || first.contains(':') || first == "localhost" => {
            name.to_string()
        }
        Some(_) => format!("docker.io/{name}"),
        None => format!("docker.io/library/{name}"),
    };
    match digest {
        Some(digest) => format!("{qualified}@{digest}"),
        None if has_tag => qualified,
        None => format!("{qualified}:latest"),
    }
}

fn digest_of(reference: &str) -> Option<&str> {
    reference.split_once('@').map(|(_, digest)| digest)
}

fn matches(image: &ImageRecord, keep: &str) -> bool {
    if let Some(id) = keep.strip_prefix("sha256:").filter(|_| !keep.contains('/')) {
        return (id.len() >= 12 && image.id.starts_with(id))
            || image.digest == keep
            || image
                .repo_digests()
                .iter()
                .any(|reference| digest_of(reference) == Some(keep));
    }
    if let Some(digest) = digest_of(keep) {
        return image.digest == digest
            || image
                .repo_digests()
                .iter()
                .chain(image.names())
                .any(|reference| digest_of(reference) == Some(digest));
    }
    let wanted = normalize(keep);
    image.names().iter().any(|name| normalize(name) == wanted)
}

#[derive(Debug, Default, PartialEq)]
pub(crate) struct Plan {
    /// Image IDs with their label.
    pub(crate) remove_images: Vec<(String, String, usize)>,
    pub(crate) remove_containers: Vec<String>,
    pub(crate) kept_images: u32,
}

/// Decides what to remove. `containers` is the state after the build
/// containers are removed; `remove_containers` comes from the state before.
pub(crate) fn plan(
    images: &[ImageRecord],
    containers: &[ContainerRecord],
    request: &ImagePruneRequest,
) -> Plan {
    let running_builds: HashSet<&str> = request
        .running_build_containers
        .iter()
        .map(String::as_str)
        .collect();
    let remove_containers: Vec<String> = containers
        .iter()
        .filter(|container| container.state != "running")
        .filter_map(|container| container.names.first())
        .filter(|name| name.starts_with(BUILD_CONTAINER_PREFIX))
        .filter(|name| !running_builds.contains(name.as_str()))
        .cloned()
        .collect();
    let used: HashSet<&str> = containers
        .iter()
        .filter(|container| {
            container
                .names
                .first()
                .is_none_or(|name| !remove_containers.contains(name))
        })
        .map(|container| container.image_id.as_str())
        .collect();
    let newest_sentinel_host = images
        .iter()
        .filter(|image| {
            image
                .repositories()
                .any(|name| name == SENTINEL_HOST_REPOSITORY)
        })
        .max_by_key(|image| image.created)
        .map(|image| image.id.as_str());
    let keep: Vec<&str> = request
        .keep
        .iter()
        .map(String::as_str)
        .chain([BUILDKIT_IMAGE, ZOT_IMAGE])
        .collect();
    let mut kept_images = 0;
    let mut remove_images = Vec::new();
    for image in images {
        let kept = used.contains(image.id.as_str())
            || newest_sentinel_host == Some(image.id.as_str())
            || keep.iter().any(|reference| matches(image, reference));
        if kept {
            kept_images += 1;
        } else {
            remove_images.push((image.id.clone(), image.label(), image.names().len()));
        }
    }
    Plan {
        remove_images,
        remove_containers,
        kept_images,
    }
}

fn podman_json<T: for<'de> Deserialize<'de>>(podman: &Path, args: &[&str]) -> Result<T, String> {
    let output = output_with_timeout(
        std::process::Command::new(podman).args(args),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if !output.status.success() {
        return Err(stderr_message(&output, "Podman could not list the images."));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "Podman returned an image list that Sentinel cannot read.".to_string())
}

fn podman_run(podman: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    output_with_timeout(
        std::process::Command::new(podman).args(args),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))
}

fn stderr_message(output: &std::process::Output, fallback: &str) -> String {
    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.is_empty() {
        fallback.into()
    } else {
        message.chars().take(500).collect()
    }
}

fn root_available() -> Option<u64> {
    Disks::new_with_refreshed_list()
        .list()
        .iter()
        .find(|disk| disk.mount_point() == Path::new("/"))
        .map(|disk| disk.available_space())
}

pub(crate) fn prune(
    podman: &Path,
    request: &ImagePruneRequest,
) -> Result<ImagePruneResult, String> {
    validate(request)?;
    let before = root_available();
    let containers: Vec<ContainerRecord> =
        podman_json(podman, &["ps", "--all", "--format", "json"])?;
    let images: Vec<ImageRecord> = podman_json(podman, &["images", "--format", "json"])?;
    let planned = plan(&images, &containers, request);

    let mut skipped = Vec::new();
    let mut removed_containers = Vec::new();
    for name in &planned.remove_containers {
        // Without `--force`: Podman refuses a container that started in between.
        let output = podman_run(podman, &["rm", name])?;
        if output.status.success() {
            removed_containers.push(name.clone());
        } else {
            skipped.push(format!(
                "{name}: {}",
                stderr_message(&output, "not removed")
            ));
        }
    }
    // A container that was not removed still uses its image.
    let containers: Vec<ContainerRecord> =
        podman_json(podman, &["ps", "--all", "--format", "json"])?;
    let planned = plan(&images, &containers, request);

    let mut removed_images = Vec::new();
    for (id, label, names) in &planned.remove_images {
        // An image with several names needs an untag first; `rmi` without
        // `--force` refuses it, and `--force` would also remove containers.
        if *names > 1 {
            let _ = podman_run(podman, &["untag", id])?;
        }
        let output = podman_run(podman, &["rmi", id])?;
        if output.status.success() {
            removed_images.push(label.clone());
        } else {
            skipped.push(format!(
                "{label}: {}",
                stderr_message(&output, "not removed")
            ));
        }
    }
    let after = root_available();
    Ok(ImagePruneResult {
        freed_bytes: match (before, after) {
            (Some(before), Some(after)) => after.saturating_sub(before),
            _ => 0,
        },
        removed_images,
        removed_containers,
        kept_images: planned.kept_images,
        skipped,
        disk_available_bytes: after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(id: &str, names: &[&str], digests: &[&str], created: i64) -> ImageRecord {
        ImageRecord {
            id: id.into(),
            names: Some(names.iter().map(|name| name.to_string()).collect()),
            repo_digests: Some(digests.iter().map(|digest| digest.to_string()).collect()),
            digest: digests
                .first()
                .and_then(|reference| digest_of(reference))
                .unwrap_or_default()
                .into(),
            created,
        }
    }

    fn container(name: &str, image_id: &str, state: &str) -> ContainerRecord {
        ContainerRecord {
            names: vec![name.into()],
            image_id: image_id.into(),
            state: state.into(),
        }
    }

    fn request(keep: &[&str], running: &[&str]) -> ImagePruneRequest {
        ImagePruneRequest {
            keep: keep.iter().map(|value| value.to_string()).collect(),
            running_build_containers: running.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn removed(plan: &Plan) -> Vec<&str> {
        plan.remove_images
            .iter()
            .map(|(id, _, _)| id.as_str())
            .collect()
    }

    const OLD: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const NEW: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn normalizes_docker_hub_references() {
        assert_eq!(normalize("nginx"), "docker.io/library/nginx:latest");
        assert_eq!(normalize("nginx:alpine"), "docker.io/library/nginx:alpine");
        assert_eq!(normalize("n8nio/n8n:2.10.2"), "docker.io/n8nio/n8n:2.10.2");
        assert_eq!(
            normalize("registry.cluster.coolify.internal:5443/app@sha256:aa"),
            "registry.cluster.coolify.internal:5443/app@sha256:aa"
        );
        assert_eq!(normalize("localhost/app:abc"), "localhost/app:abc");
        assert_eq!(normalize("localhost:5000/app"), "localhost:5000/app:latest");
        assert_eq!(
            repository("registry.example:5443/team/app:1@sha256:aa"),
            "registry.example:5443/team/app"
        );
        assert_eq!(
            repository("registry.example:5443/app"),
            "registry.example:5443/app"
        );
    }

    #[test]
    fn keeps_used_and_listed_images_and_removes_the_others() {
        let images = [
            image("a1", &["docker.io/library/nginx:alpine"], &[], 1),
            image(
                "b2",
                &["registry.cluster.coolify.internal:5443/app@sha256:2222"],
                &[&format!(
                    "registry.cluster.coolify.internal:5443/app{}",
                    "@sha256:2222"
                )],
                2,
            ),
            image(
                "c3",
                &["registry.cluster.coolify.internal:5443/app@sha256:1111"],
                &["registry.cluster.coolify.internal:5443/app@sha256:1111"],
                1,
            ),
            image("d4", &[], &[], 1),
            image("e5", &["docker.io/library/postgres:16-alpine"], &[], 1),
            image("f6", &["localhost/app:old"], &[], 1),
            image("aaaaaaaaaaaaaaaa", &["docker.io/library/redis:7"], &[], 1),
        ];
        let containers = [
            container("coolify-app-main", "a1", "running"),
            container("coolify-db-main", "e5", "exited"),
        ];
        let plan = plan(
            &images,
            &containers,
            &request(
                &[
                    "registry.cluster.coolify.internal:5443/app@sha256:2222",
                    "sha256:aaaaaaaaaaaa",
                ],
                &[],
            ),
        );
        assert_eq!(removed(&plan), ["c3", "d4", "f6"]);
        assert_eq!(plan.kept_images, 4);
    }

    #[test]
    fn keeps_an_image_by_its_tag_or_any_of_its_digests() {
        let images = [
            image("a1", &["docker.io/library/nginx:alpine"], &[], 1),
            image(
                "b2",
                &["ghcr.io/coollabsio/coolify-builder@sha256:3333"],
                &[
                    "ghcr.io/coollabsio/coolify-builder@sha256:4444",
                    "ghcr.io/coollabsio/coolify-builder@sha256:3333",
                ],
                1,
            ),
        ];
        let plan = plan(
            &images,
            &[],
            &request(
                &[
                    "nginx:alpine",
                    "ghcr.io/coollabsio/coolify-builder:main-1@sha256:4444",
                ],
                &[],
            ),
        );
        assert!(removed(&plan).is_empty());
    }

    #[test]
    fn always_keeps_buildkit_zot_and_the_newest_sentinel_host() {
        let buildkit_digest = digest_of(BUILDKIT_IMAGE).unwrap();
        let images = [
            image(
                "bk",
                &[],
                &[&format!("docker.io/moby/buildkit@{buildkit_digest}")],
                1,
            ),
            image("zot", &[ZOT_IMAGE.split('@').next().unwrap()], &[], 1),
            image(
                "old-host",
                &["ghcr.io/coollabsio/sentinel-host:main-1"],
                &[&format!("ghcr.io/coollabsio/sentinel-host@{OLD}")],
                1,
            ),
            image(
                "new-host",
                &[&format!("ghcr.io/coollabsio/sentinel-host@{NEW}")],
                &[&format!("ghcr.io/coollabsio/sentinel-host@{NEW}")],
                2,
            ),
        ];
        let plan = plan(&images, &[], &request(&[], &[]));
        // zot is pinned by digest: a tag without that digest is not the pinned image.
        assert_eq!(removed(&plan), ["zot", "old-host"]);
    }

    #[test]
    fn removes_ended_build_containers_but_not_running_or_reported_ones() {
        let images = [
            image("builder", &["ghcr.io/coollabsio/coolify-builder:1"], &[], 1),
            image("other", &["docker.io/library/busybox:1"], &[], 1),
        ];
        let containers = [
            container("coolify-build-a", "builder", "exited"),
            container("coolify-build-b", "builder", "created"),
            container("coolify-build-c", "other", "running"),
            container("coolify-app-main", "other", "exited"),
        ];
        let plan = plan(&images, &containers, &request(&[], &["coolify-build-b"]));
        assert_eq!(plan.remove_containers, ["coolify-build-a"]);
        assert!(removed(&plan).is_empty());
        let after = [
            container("coolify-build-b", "other", "created"),
            container("coolify-build-c", "other", "running"),
        ];
        let plan = plan_after(&images, &after);
        assert_eq!(removed(&plan), ["builder"]);
    }

    fn plan_after(images: &[ImageRecord], containers: &[ContainerRecord]) -> Plan {
        plan(images, containers, &request(&[], &["coolify-build-b"]))
    }

    #[test]
    fn validates_the_request() {
        assert!(
            validate(&request(
                &["nginx:alpine", "sha256:abc"],
                &["coolify-build-1"]
            ))
            .is_ok()
        );
        for keep in [
            "",
            "-rf",
            "nginx alpine",
            "nginx;id",
            "$(id)",
            &"a".repeat(513),
        ] {
            assert!(validate(&request(&[keep], &[])).is_err(), "{keep:?}");
        }
        for name in ["coolify-app-main", "coolify-build-", "coolify-build-a b"] {
            assert!(validate(&request(&[], &[name])).is_err(), "{name:?}");
        }
        let many: Vec<String> = (0..=MAX_KEEP).map(|index| format!("app:{index}")).collect();
        assert!(
            validate(&ImagePruneRequest {
                keep: many,
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn reads_podman_json() {
        let images: Vec<ImageRecord> = serde_json::from_str(
            r#"[{"Id":"abc","Names":null,"RepoDigests":["r@sha256:1"],"Digest":"sha256:1","Size":5,"Created":3}]"#,
        )
        .unwrap();
        assert_eq!(images[0].label(), "r@sha256:1");
        let containers: Vec<ContainerRecord> = serde_json::from_str(
            r#"[{"Names":["coolify-buildkitd"],"ImageID":"abc","State":"running","Image":"x"}]"#,
        )
        .unwrap();
        assert_eq!(containers[0].image_id, "abc");
    }
}
