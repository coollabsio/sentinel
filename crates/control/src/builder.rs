//! Image builds on this Node (decision 0006).
//!
//! `builder.reconcile.v1` runs rootless BuildKit as the `coolify-buildkitd`
//! container. Its uid range starts at [`UID_BASE`], so no process of a build
//! runs as a real host user. `image.build.v1` starts one `coolify-build-<id>`
//! container with the same uid range; it clones the commit and builds through
//! the BuildKit socket. Coolify follows it with `container.list` and
//! `container.logs`, so a build never holds the command executor.
//!
//! A cluster with one Node runs no registry. Its builds target a
//! `localhost/` image: the build writes a docker archive to a per-build
//! directory, and `image.load.v1` loads it into the Podman store.

use std::path::{Path, PathBuf};
use std::process::Command;

use sentinel_protocol::REGISTRY_HOST;
use sentinel_protocol::control::v1::{
    BuilderReconcileRequest, BuilderReconcileResult, ImageBuildRequest, ImageBuildResult,
    ImageLoadRequest, ImageLoadResult,
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
/// Host tmpfs for the inputs of a running build that must not reach the disk:
/// the Git credential (decision 0011), the push login, the build-time
/// variables (decision 0012), and an inline Dockerfile.
const BUILD_INPUT_DIR: &str = "run/coolify-build-git";
/// Where the build container sees the credential file, read-only.
const GIT_CREDENTIAL_MOUNT: &str = "/run/coolify-git";
/// Where the build container sees the variables and an inline Dockerfile,
/// read-only. Matches the entrypoint.
const BUILD_INPUT_MOUNT: &str = "/run/coolify-build";
const BUILD_ARGS: &str = "args";
const BUILD_SECRETS: &str = "secrets";
const INLINE_DOCKERFILE: &str = "dockerfile";
const MAX_BUILD_VARIABLES: usize = 128;
const MAX_BUILD_VARIABLE_BYTES: usize = 64 * 1024;
const MAX_INLINE_DOCKERFILE_BYTES: usize = 128 * 1024;
const APPARMOR_PROFILE: &str = "coolify-buildkit";
const APPARMOR_PROFILE_PATH: &str = "etc/apparmor.d/coolify-buildkit";
const DEFAULT_CACHE_PERCENT: u64 = 20;
/// One directory per local build. It holds the docker archive until
/// `image.load.v1` loads it.
const OUTPUT_DIR: &str = "var/lib/coolify/builder/out";
/// Where the build container writes the archive. Matches the entrypoint.
const OUTPUT_MOUNT: &str = "/coolify/out";
const ARCHIVE_FILE: &str = "image.tar";
/// A build image with this prefix stays on the builder Node.
pub(crate) const LOCAL_IMAGE_PREFIX: &str = "localhost/";

fn builder_dir(root: &Path) -> PathBuf {
    root.join(BUILDER_DIR)
}

fn socket_dir(root: &Path) -> PathBuf {
    root.join(SOCKET_DIR)
}

fn output_dir(root: &Path, build_id: &str) -> PathBuf {
    root.join(OUTPUT_DIR).join(build_id)
}

fn is_local_image(image: &str) -> bool {
    image.starts_with(LOCAL_IMAGE_PREFIX)
}

fn valid_build_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

/// The part after the registry host or `localhost/`: `<repository>:<tag>`,
/// without a digest.
fn build_target(image: &str) -> Option<&str> {
    let target = image
        .strip_prefix(&format!("{REGISTRY_HOST}/"))
        .or_else(|| image.strip_prefix(LOCAL_IMAGE_PREFIX))?;
    let valid = !target.is_empty()
        && !target.starts_with('-')
        && target.len() <= 2_048
        && target
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-/:".contains(character))
        && target.contains(':');
    valid.then_some(target)
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

/// The Git credential of one build (decision 0011).
#[derive(Clone, Copy)]
enum GitCredential<'a> {
    None,
    HttpsToken(&'a str),
    SshKey(&'a str),
}

impl<'a> GitCredential<'a> {
    fn of(request: &'a ImageBuildRequest) -> Result<Self, String> {
        match (
            request.git_https_token.as_str(),
            request.git_ssh_private_key.as_str(),
        ) {
            ("", "") => Ok(Self::None),
            (token, "") if valid_https_token(token) => Ok(Self::HttpsToken(token)),
            ("", key) if valid_ssh_private_key(key) => Ok(Self::SshKey(key)),
            ("", _) => Err("The Git SSH private key is invalid.".into()),
            (_, "") => Err("The Git HTTPS token is invalid.".into()),
            _ => Err("A build takes at most one Git credential.".into()),
        }
    }

    /// The file name under [`GIT_CREDENTIAL_MOUNT`]; the entrypoint picks the
    /// Git transport by the file that exists.
    fn file_name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::HttpsToken(_) => Some("token"),
            Self::SshKey(_) => Some("ssh-key"),
        }
    }
}

fn valid_https_token(value: &str) -> bool {
    (1..=1_024).contains(&value.len())
        && value.chars().all(|character| character.is_ascii_graphic())
}

fn valid_ssh_private_key(value: &str) -> bool {
    let key = value.trim();
    key.len() <= 16_384
        && key.starts_with("-----BEGIN ")
        && key
            .lines()
            .next()
            .is_some_and(|line| line.ends_with("PRIVATE KEY-----"))
        && key.ends_with("PRIVATE KEY-----")
        && key
            .chars()
            .all(|character| character.is_ascii_graphic() || " \r\n".contains(character))
}

fn valid_url_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._~/%+".contains(character))
}

fn valid_ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
}

fn valid_ssh_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with(['-', '.'])
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-.".contains(character))
}

/// `https://host/path` without user info. Only these characters, so no
/// newline and no `-` prefix reaches Git.
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

/// `ssh://[user@]host[:port]/path` or the scp-like `user@host:path`.
fn valid_ssh_repository_url(value: &str) -> bool {
    if value.len() > 2_048 {
        return false;
    }
    if let Some(rest) = value.strip_prefix("ssh://") {
        let Some((authority, path)) = rest.split_once('/') else {
            return false;
        };
        let host_port = match authority.split_once('@') {
            Some((user, host_port)) if valid_ssh_user(user) => host_port,
            Some(_) => return false,
            None => authority,
        };
        let host = match host_port.split_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok_and(|port| port > 0) => host,
            Some(_) => return false,
            None => host_port,
        };
        return valid_ssh_host(host) && valid_url_path(path);
    }
    let Some((user, rest)) = value.split_once('@') else {
        return false;
    };
    let Some((host, path)) = rest.split_once(':') else {
        return false;
    };
    valid_ssh_user(user) && valid_ssh_host(host) && valid_url_path(path)
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
    if !valid_build_id(&request.build_id) {
        return Err("The build ID is invalid.".into());
    }
    if !image_valid(&request.builder_image) {
        return Err("The builder image is invalid.".into());
    }
    validate_variables(request)?;
    if !request.dockerfile_content.is_empty() {
        validate_inline_dockerfile(request)?;
    } else {
        validate_git_source(request)?;
    }
    if build_target(&request.image).is_none() {
        return Err(
            "The build image must be a tag in the cluster registry or a localhost/ image.".into(),
        );
    }
    validate_push(request)
}

/// An inline Dockerfile has no repository, so no Git field may be set.
fn validate_inline_dockerfile(request: &ImageBuildRequest) -> Result<(), String> {
    if request.dockerfile_content.len() > MAX_INLINE_DOCKERFILE_BYTES
        || request.dockerfile_content.contains('\0')
    {
        return Err("The Dockerfile must be text of at most 128 KiB.".into());
    }
    let git_fields = [
        &request.repository_url,
        &request.commit_sha,
        &request.base_directory,
        &request.dockerfile_path,
        &request.git_https_token,
        &request.git_ssh_private_key,
    ];
    if request.source_type != "dockerfile" || git_fields.iter().any(|field| !field.is_empty()) {
        return Err("A build from an inline Dockerfile takes no repository.".into());
    }
    Ok(())
}

fn valid_build_variable_key(key: &str) -> bool {
    (1..=255).contains(&key.len())
        && !key.starts_with(|character: char| character.is_ascii_digit())
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// The keys become file names and BuildKit option values, so only this set.
/// A build arg is a command argument inside the build container, so no NUL.
fn validate_variables(request: &ImageBuildRequest) -> Result<(), String> {
    for (variables, kind) in [
        (&request.build_args, "build arg"),
        (&request.build_secrets, "build secret"),
    ] {
        if variables.len() > MAX_BUILD_VARIABLES {
            return Err(format!(
                "A build takes at most {MAX_BUILD_VARIABLES} of each build-time variable kind."
            ));
        }
        for (key, value) in variables {
            if !valid_build_variable_key(key) {
                return Err(format!(
                    "The {kind} name {key:?} is invalid. Use letters, digits, and _, not starting with a digit."
                ));
            }
            if value.len() > MAX_BUILD_VARIABLE_BYTES {
                return Err(format!("The {kind} {key} is larger than 64 KiB."));
            }
            if kind == "build arg" && value.contains('\0') {
                return Err(format!("The build arg {key} contains a NUL character."));
            }
        }
    }
    if let Some(key) = request
        .build_args
        .keys()
        .find(|key| request.build_secrets.contains_key(*key))
    {
        return Err(format!("{key} is both a build arg and a build secret."));
    }
    Ok(())
}

fn validate_git_source(request: &ImageBuildRequest) -> Result<(), String> {
    match GitCredential::of(request)? {
        GitCredential::None if !valid_repository_url(&request.repository_url) => {
            return Err(
                "The repository URL must be a public https:// URL without credentials.".into(),
            );
        }
        GitCredential::HttpsToken(_) if !valid_repository_url(&request.repository_url) => {
            return Err("The repository URL must be an https:// URL without credentials.".into());
        }
        GitCredential::SshKey(_)
            if !valid_repository_url(&request.repository_url)
                && !valid_ssh_repository_url(&request.repository_url) =>
        {
            return Err(
                "The repository URL must be an https://, ssh://, or user@host:path URL without a password.".into(),
            );
        }
        _ => {}
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
    Ok(())
}

/// The optional external target (`image.build.external_push.v1`): a tag
/// outside the cluster registry, with an optional login for its registry.
fn validate_push(request: &ImageBuildRequest) -> Result<(), String> {
    let has_login =
        crate::registry::validate_login(&request.push_username, &request.push_password)?;
    let image = request.push_image.as_str();
    if image.is_empty() {
        return if has_login {
            Err("A push login needs a push image.".into())
        } else {
            Ok(())
        };
    }
    let repository_end = image.rfind('/').map_or(0, |slash| slash + 1);
    let valid = !image.starts_with('-')
        && image.len() <= 2_048
        && image
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-/:".contains(character))
        && image[repository_end..].contains(':')
        && !image.starts_with(&format!("{REGISTRY_HOST}/"))
        && !is_local_image(image);
    if !valid {
        return Err("The push image must be a tag outside the cluster registry.".into());
    }
    Ok(())
}

const PUSH_LOGIN_FILE: &str = "push-config.json";
const PUSH_LOGIN_MOUNT: &str = "/run/coolify-push";

/// One directory per build under the host `/run` (tmpfs), so an input never
/// reaches the disk and is gone after a reboot.
fn build_input_dir(root: &Path, build_id: &str) -> PathBuf {
    root.join(BUILD_INPUT_DIR).join(build_id)
}

/// Creates the 0700 input directory of root, or one of its subdirectories,
/// which the build container mounts and so belongs to the build user.
fn create_input_dir(path: &Path, owned_by_build_user: bool) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|_| "The build inputs could not be written.".to_string())?;
    if owned_by_build_user {
        own_by_build_user(path)?;
    }
    Ok(())
}

/// Writes one new file, 0600 and owned by the build user.
fn write_input_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let error = || "The build inputs could not be written.".to_string();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| error())?;
    file.write_all(contents).map_err(|_| error())?;
    own_by_build_user(path)
}

/// Writes every input of a build to its directory on tmpfs. Returns whether
/// the build has one, so the caller deletes them when the build ends.
fn write_build_inputs(root: &Path, request: &ImageBuildRequest) -> Result<bool, String> {
    remove_build_inputs(root, &request.build_id);
    let dir = build_input_dir(root, &request.build_id);
    let credential = GitCredential::of(request)?;
    let mut wrote = false;
    let mut write = |relative: &str, contents: &[u8]| -> Result<(), String> {
        create_input_dir(&dir, false)?;
        wrote = true;
        write_input_file(&dir.join(relative), contents)
    };
    let credential_contents = match credential {
        GitCredential::None => None,
        GitCredential::HttpsToken(token) => Some(token.to_string()),
        // OpenSSH needs the final newline and no carriage returns.
        GitCredential::SshKey(key) => Some(format!("{}\n", key.replace('\r', "").trim())),
    };
    if let (Some(file_name), Some(contents)) = (credential.file_name(), credential_contents) {
        write(file_name, contents.as_bytes())?;
    }
    if !request.push_username.is_empty() {
        write(
            PUSH_LOGIN_FILE,
            &crate::registry::login_auth_file(
                &crate::registry::image_registry_host(&request.push_image),
                &request.push_username,
                &request.push_password,
            ),
        )?;
    }
    for (subdir, variables) in [
        (BUILD_ARGS, &request.build_args),
        (BUILD_SECRETS, &request.build_secrets),
    ] {
        if variables.is_empty() {
            continue;
        }
        create_input_dir(&dir, false)?;
        create_input_dir(&dir.join(subdir), true)?;
        for (key, value) in variables {
            write(&format!("{subdir}/{key}"), value.as_bytes())?;
        }
    }
    if !request.dockerfile_content.is_empty() {
        create_input_dir(&dir, false)?;
        create_input_dir(&dir.join(INLINE_DOCKERFILE), true)?;
        write(
            &format!("{INLINE_DOCKERFILE}/Dockerfile"),
            request.dockerfile_content.as_bytes(),
        )?;
    }
    Ok(wrote)
}

fn remove_build_inputs(root: &Path, build_id: &str) {
    match std::fs::remove_dir_all(build_input_dir(root, build_id)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(%error, build_id, "could not remove the Git credential of a build")
        }
    }
}

/// Deletes the credential of a build once its container is no longer running:
/// it exited, was stopped (a cancel), or was removed. `podman wait` returns at
/// once for a container that is already gone.
fn remove_build_inputs_after_build(root: &Path, podman: &Path, build_id: &str) {
    let (root, podman, build_id) = (
        root.to_path_buf(),
        podman.to_path_buf(),
        build_id.to_string(),
    );
    std::thread::spawn(move || {
        let _ = Command::new(&podman)
            .args(["wait", &build_container_name(&build_id)])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        remove_build_inputs(&root, &build_id);
    });
}

/// Watches the credentials that an earlier Sentinel process wrote, so they
/// are deleted when their builds end.
pub(crate) fn remove_build_inputs_after_builds(root: &Path, podman: &Path) {
    let Ok(entries) = std::fs::read_dir(root.join(BUILD_INPUT_DIR)) else {
        return;
    };
    for entry in entries.flatten() {
        if let Some(build_id) = entry.file_name().to_str() {
            remove_build_inputs_after_build(root, podman, build_id);
        }
    }
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
    ]);
    if let Some(file_name) = GitCredential::of(request)
        .ok()
        .and_then(GitCredential::file_name)
    {
        arguments.extend([
            "--volume".into(),
            format!(
                "{}:{GIT_CREDENTIAL_MOUNT}/{file_name}:ro",
                build_input_dir(root, &request.build_id)
                    .join(file_name)
                    .display()
            ),
        ]);
    }
    if !request.push_username.is_empty() {
        arguments.extend([
            "--volume".into(),
            format!(
                "{}:{PUSH_LOGIN_MOUNT}/config.json:ro",
                build_input_dir(root, &request.build_id)
                    .join(PUSH_LOGIN_FILE)
                    .display()
            ),
        ]);
    }
    for (subdir, present) in [
        (BUILD_ARGS, !request.build_args.is_empty()),
        (BUILD_SECRETS, !request.build_secrets.is_empty()),
        (INLINE_DOCKERFILE, !request.dockerfile_content.is_empty()),
    ] {
        if present {
            arguments.extend([
                "--volume".into(),
                format!(
                    "{}:{BUILD_INPUT_MOUNT}/{subdir}:ro",
                    build_input_dir(root, &request.build_id)
                        .join(subdir)
                        .display()
                ),
            ]);
        }
    }
    if is_local_image(&request.image) {
        arguments.extend([
            "--volume".into(),
            format!(
                "{}:{OUTPUT_MOUNT}",
                output_dir(root, &request.build_id).display()
            ),
        ]);
    }
    arguments.push(request.builder_image.clone());
    if request.dockerfile_content.is_empty() {
        arguments.extend([
            "--repository".into(),
            request.repository_url.clone(),
            "--commit".into(),
            request.commit_sha.clone(),
        ]);
    }
    arguments.extend([
        "--type".into(),
        request.source_type.clone(),
        "--base-directory".into(),
        request.base_directory.clone(),
        "--dockerfile".into(),
        request.dockerfile_path.clone(),
        "--image".into(),
        request.image.clone(),
    ]);
    if !request.push_image.is_empty() {
        arguments.extend(["--push-image".into(), request.push_image.clone()]);
    }
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
    let local = is_local_image(&request.image);
    if local {
        remove_stale_outputs(root, podman);
        let dir = output_dir(root, &request.build_id);
        std::fs::create_dir_all(&dir)
            .map_err(|_| "The build output directory could not be created.")?;
        own_by_build_user(&dir)?;
    }
    let has_inputs = write_build_inputs(root, request).inspect_err(|_| {
        remove_build_inputs(root, &request.build_id);
    })?;
    let started = run_build(root, podman, request, name);
    if local && started.is_err() {
        let _ = std::fs::remove_dir_all(output_dir(root, &request.build_id));
    }
    if has_inputs {
        match &started {
            Ok(_) => remove_build_inputs_after_build(root, podman, &request.build_id),
            Err(_) => remove_build_inputs(root, &request.build_id),
        }
    }
    started
}

fn run_build(
    root: &Path,
    podman: &Path,
    request: &ImageBuildRequest,
    name: String,
) -> Result<ImageBuildResult, String> {
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

/// Deletes the output of builds whose container is gone: they failed, were
/// cancelled, or Coolify never loaded them. Coolify runs one build at a time
/// on a builder Node and loads it before the next one starts, so no archive
/// that waits for its load is deleted.
fn remove_stale_outputs(root: &Path, podman: &Path) {
    let Ok(entries) = std::fs::read_dir(root.join(OUTPUT_DIR)) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(build_id) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let exists = output_with_timeout(
            Command::new(podman).args(["container", "exists", &build_container_name(&build_id)]),
            PODMAN_QUERY_TIMEOUT,
        )
        .is_ok_and(|output| output.status.success());
        if !exists {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

pub(crate) fn validate_load(request: &ImageLoadRequest) -> Result<(), String> {
    if !valid_build_id(&request.build_id) {
        return Err("The build ID is invalid.".into());
    }
    if !is_local_image(&request.image) || build_target(&request.image).is_none() {
        return Err("The image must be a localhost/ image.".into());
    }
    if !(1..=100).contains(&request.keep_tags) {
        return Err("keep_tags must be 1 to 100.".into());
    }
    Ok(())
}

fn image_id(podman: &Path, image: &str) -> Option<String> {
    let output = output_with_timeout(
        Command::new(podman).args(["image", "inspect", "--format", "{{.Id}}", image]),
        PODMAN_QUERY_TIMEOUT,
    )
    .ok()?;
    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (output.status.success() && !id.is_empty()).then(|| format!("sha256:{id}"))
}

/// Loads the archive of a local build, then keeps the newest `keep_tags`
/// tags of its repository.
pub(crate) fn load(
    root: &Path,
    podman: &Path,
    request: &ImageLoadRequest,
) -> Result<ImageLoadResult, String> {
    validate_load(request)?;
    let dir = output_dir(root, &request.build_id);
    let archive = dir.join(ARCHIVE_FILE);
    if archive.is_file() {
        let output = output_with_timeout(
            Command::new(podman)
                .arg("load")
                .arg("--input")
                .arg(&archive),
            PODMAN_DEPLOY_TIMEOUT,
        )
        .map_err(|error| podman_failure(&error))?;
        if !output.status.success() {
            return Err(stderr_or(
                &output.stderr,
                "Podman could not load the build.",
            ));
        }
    }
    let Some(image_id) = image_id(podman, &request.image) else {
        return Err("The build left no image to load.".into());
    };
    let _ = std::fs::remove_dir_all(&dir);
    remove_old_tags(podman, &request.image, request.keep_tags as usize);
    Ok(ImageLoadResult {
        image: request.image.clone(),
        image_id,
    })
}

/// `podman rmi` without `--force`: a tag that a container uses stays.
fn remove_old_tags(podman: &Path, image: &str, keep: usize) {
    let Some((repository, _)) = image.rsplit_once(':') else {
        return;
    };
    let Ok(output) = output_with_timeout(
        Command::new(podman).args(["images", "--format", "json"]),
        PODMAN_QUERY_TIMEOUT,
    ) else {
        return;
    };
    let Ok(images) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) else {
        return;
    };
    for name in old_tags(&images, repository, image, keep) {
        let _ = output_with_timeout(
            Command::new(podman).args(["rmi", &name]),
            PODMAN_QUERY_TIMEOUT,
        );
    }
}

/// The tags of `repository` beyond the newest `keep`, by creation time. The
/// image that was just loaded is never one of them.
pub(crate) fn old_tags(
    images: &[serde_json::Value],
    repository: &str,
    current: &str,
    keep: usize,
) -> Vec<String> {
    let prefix = format!("{repository}:");
    let mut tags: Vec<(i64, String)> = images
        .iter()
        .flat_map(|image| {
            let created = image["Created"].as_i64().unwrap_or(0);
            image["Names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .filter(|name| name.starts_with(&prefix))
                .map(move |name| (created, name.to_string()))
        })
        .collect();
    tags.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
    tags.into_iter()
        .map(|(_, name)| name)
        .filter(|name| name != current)
        .skip(keep.saturating_sub(1))
        .collect()
}
