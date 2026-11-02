//! Image builds on this Node (decision 0006).
//!
//! `builder.reconcile.v1` runs rootless BuildKit as the `coolify-buildkitd`
//! container. Its uid range starts at [`UID_BASE`], so no process of a build
//! runs as a real host user. `image.build.v1` starts one `coolify-build-<id>`
//! container with the same uid range; it clones the commit and builds through
//! the BuildKit socket. Coolify follows it with `container.list` and
//! `container.logs`, so a build never holds the command executor.

use std::path::{Path, PathBuf};
use std::process::Command;

use sentinel_protocol::REGISTRY_HOST;
use sentinel_protocol::control::v1::{
    BuilderReconcileRequest, BuilderReconcileResult, ImageBuildRequest, ImageBuildResult,
};

use crate::commands::{PODMAN_DEPLOY_TIMEOUT, PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::{hash, output_with_timeout, write_if_changed};
use crate::registry::{
    CONFIG_HASH_LABEL, SERVICE_LABEL, auth_file, ca_path, remove_container_and_volume,
    running_with_hash, stderr_or, valid_password, valid_username,
};

/// BuildKit v0.34.1, rootless, multi-architecture index.
pub(crate) const BUILDKIT_IMAGE: &str = "docker.io/moby/buildkit:v0.34.1-rootless@sha256:f68752a5a94acfcdad2d07867b7075601a421638e17fc5f28efc1c814d0c4f89";
pub(crate) const BUILDKIT_CONTAINER: &str = "coolify-buildkitd";
pub(crate) const BUILD_LABEL: &str = "coolify.build";
const BUILDKIT_VOLUME: &str = "coolify-buildkit";
/// Container uid 0 is host uid 2,000,000,000. The rootless BuildKit user
/// (container uid 1000) and its sub-uids stay far away from host users.
const UID_BASE: u32 = 2_000_000_000;
const UID_COUNT: u32 = 262_144;
const BUILD_USER: u32 = 1_000;
const BUILDER_DIR: &str = "etc/coolify/builder";
/// Persistent, so the socket mount exists again after a reboot.
const SOCKET_DIR: &str = "var/lib/coolify/builder/run";
const APPARMOR_PROFILE: &str = "coolify-buildkit";
const APPARMOR_PROFILE_PATH: &str = "etc/apparmor.d/coolify-buildkit";
const DEFAULT_CACHE_PERCENT: u64 = 20;

fn builder_dir(root: &Path) -> PathBuf {
    root.join(BUILDER_DIR)
}

fn socket_dir(root: &Path) -> PathBuf {
    root.join(SOCKET_DIR)
}

fn uid_map() -> [String; 4] {
    let map = format!("0:{UID_BASE}:{UID_COUNT}");
    ["--uidmap".into(), map.clone(), "--gidmap".into(), map]
}

pub(crate) fn validate_reconcile(request: &BuilderReconcileRequest) -> Result<(), String> {
    if request.enabled != (!request.push_username.is_empty() || !request.push_password.is_empty())
        || (request.enabled
            && (!valid_username(&request.push_username) || !valid_password(&request.push_password)))
    {
        return Err("The builder push credential is invalid.".into());
    }
    Ok(())
}

pub(crate) fn buildkitd_config(max_used_space_bytes: u64) -> String {
    let reserved = (max_used_space_bytes / 4).min(10 * 1024 * 1024 * 1024);
    format!(
        "[registry.\"{REGISTRY_HOST}\"]\n  ca = [\"/etc/coolify/registry-ca.crt\"]\n\n[worker.oci]\n  gc = true\n  maxUsedSpace = \"{max_used_space_bytes}\"\n  reservedSpace = \"{reserved}\"\n"
    )
}

/// Ubuntu 24.04 blocks unprivileged user namespaces through AppArmor. The
/// profile allows them for BuildKit only; it does not change the host sysctl.
/// Returns whether the container must use the profile.
fn ensure_apparmor_profile(root: &Path) -> Result<bool, String> {
    if !root.join("sys/kernel/security/apparmor").exists() {
        return Ok(false);
    }
    let profile = format!(
        "abi <abi/4.0>,\ninclude <tunables/global>\n\nprofile {APPARMOR_PROFILE} flags=(unconfined) {{\n  userns,\n}}\n"
    );
    let path = root.join(APPARMOR_PROFILE_PATH);
    let changed = write_if_changed(&path, profile.as_bytes(), 0o644)?;
    let loaded = std::fs::read_to_string(root.join("sys/kernel/security/apparmor/profiles"))
        .is_ok_and(|profiles| {
            profiles
                .lines()
                .any(|line| line.starts_with(&format!("{APPARMOR_PROFILE} ")))
        });
    if changed || !loaded {
        crate::network::run(
            Command::new("apparmor_parser").arg("-r").arg(&path),
            "AppArmor could not load the BuildKit profile.",
        )?;
    }
    Ok(true)
}

fn remove_apparmor_profile(root: &Path) {
    let path = root.join(APPARMOR_PROFILE_PATH);
    if path.exists() {
        let _ = output_with_timeout(
            Command::new("apparmor_parser").arg("-R").arg(&path),
            PODMAN_QUERY_TIMEOUT,
        );
        let _ = std::fs::remove_file(path);
    }
}

fn root_disk_bytes() -> u64 {
    sysinfo::Disks::new_with_refreshed_list()
        .list()
        .iter()
        .find(|disk| disk.mount_point() == Path::new("/"))
        .map_or(0, |disk| disk.total_space())
}

fn own_by_build_user(path: &Path) -> Result<(), String> {
    std::os::unix::fs::chown(
        path,
        Some(UID_BASE + BUILD_USER),
        Some(UID_BASE + BUILD_USER),
    )
    .map_err(|_| "The builder files could not be given to the build user.".to_string())
}

pub(crate) fn reconcile(
    root: &Path,
    podman: &Path,
    request: &BuilderReconcileRequest,
) -> Result<BuilderReconcileResult, String> {
    validate_reconcile(request)?;
    if !request.enabled {
        remove_container_and_volume(podman, BUILDKIT_CONTAINER, BUILDKIT_VOLUME)?;
        remove_apparmor_profile(root);
        for dir in [builder_dir(root), socket_dir(root)] {
            match std::fs::remove_dir_all(dir) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("The builder files could not be removed.".into()),
            }
        }
        return Ok(BuilderReconcileResult {
            enabled: false,
            running: false,
            apparmor_profile: false,
        });
    }

    let Ok(ca) = std::fs::read(ca_path(root)) else {
        return Err("The registry trust is missing. Run registry.reconcile first.".into());
    };
    let apparmor_profile = ensure_apparmor_profile(root)?;
    let max_used_space = match request.max_used_space_bytes {
        0 => root_disk_bytes() * DEFAULT_CACHE_PERCENT / 100,
        value => value,
    };
    if max_used_space < 1024 * 1024 * 1024 {
        return Err("The build cache limit must be at least 1 GiB.".into());
    }

    let dir = builder_dir(root);
    let config = buildkitd_config(max_used_space);
    write_if_changed(&dir.join("buildkitd.toml"), config.as_bytes(), 0o644)?;
    // The `certs.d` path has a `:` (host:port), which a `--volume` cannot take.
    write_if_changed(&dir.join("registry-ca.crt"), &ca, 0o644)?;
    // Build containers pass this login to BuildKit for the push.
    let docker_dir = dir.join("docker");
    let auth = auth_file(&request.push_username, &request.push_password);
    write_if_changed(&docker_dir.join("config.json"), &auth, 0o600)?;
    own_by_build_user(&docker_dir)?;
    own_by_build_user(&docker_dir.join("config.json"))?;
    let sockets = socket_dir(root);
    std::fs::create_dir_all(&sockets)
        .map_err(|_| "The BuildKit socket directory could not be created.")?;
    own_by_build_user(&sockets)?;

    let mut fingerprint = config.into_bytes();
    fingerprint.extend_from_slice(BUILDKIT_IMAGE.as_bytes());
    fingerprint.extend_from_slice(&ca);
    fingerprint.push(u8::from(apparmor_profile));
    let config_hash = hash(&fingerprint);
    if !running_with_hash(podman, BUILDKIT_CONTAINER, &config_hash) {
        let mut arguments: Vec<String> = vec![
            "run".into(),
            "--detach".into(),
            "--replace".into(),
            "--pull".into(),
            "missing".into(),
            "--name".into(),
            BUILDKIT_CONTAINER.into(),
            "--restart".into(),
            "always".into(),
            "--label".into(),
            "coolify.managed=true".into(),
            "--label".into(),
            format!("{SERVICE_LABEL}=buildkitd"),
            "--label".into(),
            format!("{CONFIG_HASH_LABEL}={config_hash}"),
            // The host resolver answers `registry.cluster.coolify.internal`.
            "--network".into(),
            "host".into(),
        ];
        arguments.extend(uid_map());
        arguments.extend([
            "--security-opt".into(),
            "seccomp=unconfined".into(),
            "--security-opt".into(),
            "systempaths=unconfined".into(),
            "--device".into(),
            "/dev/fuse".into(),
        ]);
        if apparmor_profile {
            arguments.extend([
                "--security-opt".into(),
                format!("apparmor={APPARMOR_PROFILE}"),
            ]);
        }
        arguments.extend([
            "--volume".into(),
            format!("{BUILDKIT_VOLUME}:/home/user/.local/share/buildkit"),
            "--volume".into(),
            format!("{}:/run/buildkit", sockets.display()),
            "--volume".into(),
            format!(
                "{}:/etc/coolify/buildkitd.toml:ro",
                dir.join("buildkitd.toml").display()
            ),
            "--volume".into(),
            format!(
                "{}:/etc/coolify/registry-ca.crt:ro",
                dir.join("registry-ca.crt").display()
            ),
            BUILDKIT_IMAGE.into(),
            "--addr".into(),
            "unix:///run/buildkit/buildkitd.sock".into(),
            "--config".into(),
            "/etc/coolify/buildkitd.toml".into(),
        ]);
        let output =
            output_with_timeout(Command::new(podman).args(arguments), PODMAN_DEPLOY_TIMEOUT)
                .map_err(|error| podman_failure(&error))?;
        if !output.status.success() {
            return Err(stderr_or(
                &output.stderr,
                "Podman could not start BuildKit.",
            ));
        }
    }
    Ok(BuilderReconcileResult {
        enabled: true,
        running: true,
        apparmor_profile,
    })
}

pub(crate) fn build_container_name(build_id: &str) -> String {
    format!("coolify-build-{build_id}")
}

fn valid_relative_path(value: &str) -> bool {
    value.len() <= 512
        && !value.starts_with('/')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-/".contains(character))
        && value
            .split('/')
            .all(|segment| segment != ".." && !segment.starts_with('-'))
}

fn valid_repository_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or_default();
    value.len() <= 2_048
        && !host.is_empty()
        && !host.contains('@')
        && rest.contains('/')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._~/:%+".contains(character))
}

pub(crate) fn validate_build(request: &ImageBuildRequest) -> Result<(), String> {
    let image_valid = |value: &str| {
        !value.is_empty()
            && !value.starts_with('-')
            && value.len() <= 2_048
            && value
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "._-/:@".contains(character))
    };
    if !(1..=64).contains(&request.build_id.len())
        || !request
            .build_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err("The build ID is invalid.".into());
    }
    if !image_valid(&request.builder_image) {
        return Err("The builder image is invalid.".into());
    }
    if !valid_repository_url(&request.repository_url) {
        return Err("The repository URL must be a public https:// URL without credentials.".into());
    }
    if !matches!(request.commit_sha.len(), 40 | 64)
        || !request
            .commit_sha
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
    {
        return Err("The commit SHA is invalid.".into());
    }
    match request.source_type.as_str() {
        "dockerfile" => {}
        "railpack" if request.dockerfile_path.is_empty() => {}
        _ => return Err("The build source type is invalid.".into()),
    }
    if !valid_relative_path(&request.base_directory)
        || !valid_relative_path(&request.dockerfile_path)
    {
        return Err("A build path is invalid.".into());
    }
    let Some(target) = request.image.strip_prefix(&format!("{REGISTRY_HOST}/")) else {
        return Err("The build image must be in the cluster registry.".into());
    };
    if !image_valid(target) || target.contains('@') || !target.contains(':') {
        return Err("The build image is invalid.".into());
    }
    Ok(())
}

pub(crate) fn build_arguments(root: &Path, request: &ImageBuildRequest) -> Vec<String> {
    let name = build_container_name(&request.build_id);
    let mut arguments: Vec<String> = vec![
        "run".into(),
        "--detach".into(),
        "--pull".into(),
        "missing".into(),
        "--name".into(),
        name,
        "--restart".into(),
        "no".into(),
        "--label".into(),
        format!("{BUILD_LABEL}={}", request.build_id),
    ];
    arguments.extend(uid_map());
    arguments.extend([
        "--user".into(),
        format!("{BUILD_USER}:{BUILD_USER}"),
        "--cap-drop".into(),
        "all".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--env".into(),
        "BUILDKIT_HOST=unix:///run/buildkit/buildkitd.sock".into(),
        "--env".into(),
        "DOCKER_CONFIG=/coolify/docker".into(),
        "--volume".into(),
        format!("{}:/run/buildkit", socket_dir(root).display()),
        "--volume".into(),
        format!(
            "{}:/coolify/docker:ro",
            builder_dir(root).join("docker").display()
        ),
        request.builder_image.clone(),
        "--repository".into(),
        request.repository_url.clone(),
        "--commit".into(),
        request.commit_sha.clone(),
        "--type".into(),
        request.source_type.clone(),
        "--base-directory".into(),
        request.base_directory.clone(),
        "--dockerfile".into(),
        request.dockerfile_path.clone(),
        "--image".into(),
        request.image.clone(),
    ]);
    arguments
}

/// Starts the build container. A repeated request for the same build returns
/// the existing container instead of a second build.
pub(crate) fn start(
    root: &Path,
    podman: &Path,
    request: &ImageBuildRequest,
) -> Result<ImageBuildResult, String> {
    validate_build(request)?;
    let name = build_container_name(&request.build_id);
    let existing = output_with_timeout(
        Command::new(podman).args(["container", "inspect", "--format", "{{.Id}}", &name]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if existing.status.success() {
        return Ok(ImageBuildResult {
            runtime_id: String::from_utf8_lossy(&existing.stdout).trim().into(),
            name,
        });
    }
    if !socket_dir(root).join("buildkitd.sock").exists() {
        return Err("BuildKit is not running on this Node.".into());
    }
    let output = output_with_timeout(
        Command::new(podman).args(build_arguments(root, request)),
        PODMAN_DEPLOY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if !output.status.success() {
        return Err(stderr_or(
            &output.stderr,
            "Podman could not start the build.",
        ));
    }
    let runtime_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if runtime_id.is_empty() {
        return Err("Podman did not return a container ID.".into());
    }
    Ok(ImageBuildResult { runtime_id, name })
}
