#![forbid(unsafe_code)]

use std::collections::HashSet;

pub const PROTOCOL_MIN: u32 = 1;
pub const PROTOCOL_MAX: u32 = 1;
pub const CAPABILITY_SYSTEM_PING: &str = "system.ping.v1";
pub const CAPABILITY_SYSTEM_INFO: &str = "system.info.v1";
pub const CAPABILITY_CONTAINER_LIST: &str = "container.list.v1";
pub const CAPABILITY_CONTAINER_LOGS: &str = "container.logs.v1";
pub const CAPABILITY_LOGS_READ: &str = "logs.read.v1";
pub const CAPABILITY_TRUST_BUNDLE_UPDATE: &str = "trust.bundle.update.v1";
pub const CAPABILITY_WORKLOAD_DEPLOY: &str = "workload.deploy.v1";
pub const CAPABILITY_WORKLOAD_RESOURCES: &str = "workload.resources.v1";
pub const CAPABILITY_WORKLOAD_LIFECYCLE: &str = "workload.lifecycle.v1";
/// `workload.deploy.v1` accepts `health_check`. Not a command: an older
/// Sentinel ignores the field and would run the container without the check.
pub const CAPABILITY_WORKLOAD_HEALTHCHECK: &str = "workload.healthcheck.v1";
pub const CAPABILITY_CLUSTER_LEAVE: &str = "network.cluster.leave.v1";
pub const CAPABILITY_WIREGUARD_KEY_ENSURE: &str = "network.wireguard.key.ensure.v1";
pub const CAPABILITY_WIREGUARD_INSPECT: &str = "network.wireguard.inspect.v1";
pub const CAPABILITY_WIREGUARD_RECONCILE: &str = "network.wireguard.reconcile.v1";
pub const CAPABILITY_FIREWALL_INSPECT: &str = "network.firewall.inspect.v1";
pub const CAPABILITY_FIREWALL_RECONCILE: &str = "network.firewall.reconcile.v1";
pub const CAPABILITY_CORROSION_INSPECT: &str = "discovery.corrosion.inspect.v1";
pub const CAPABILITY_CORROSION_RECONCILE: &str = "discovery.corrosion.reconcile.v1";
pub const CAPABILITY_INGRESS_RECONCILE: &str = "ingress.reconcile.v1";
/// `ingress.reconcile.v1` accepts `tls_enabled` and `tls_key`. Not a command:
/// it only tells Coolify that this Sentinel can serve HTTPS.
pub const CAPABILITY_INGRESS_TLS: &str = "ingress.tls.v1";
/// `ingress.reconcile.v1` accepts the route fields path, redirect_host,
/// http_only, allow_http, temporary_redirect, noindex, and strip_path. Not a
/// command.
pub const CAPABILITY_INGRESS_ROUTES_V2: &str = "ingress.routes.v2";
pub const CAPABILITY_IMAGE_BUILD: &str = "image.build.v1";
pub const CAPABILITY_BUILDER_RECONCILE: &str = "builder.reconcile.v1";
pub const CAPABILITY_REGISTRY_RECONCILE: &str = "registry.reconcile.v1";
pub const CAPABILITY_REGISTRY_INSPECT: &str = "registry.inspect.v1";
/// `image.build.v1` accepts `git_https_token` and `git_ssh_private_key`
/// (decision 0011). Not a command: an older Sentinel ignores the fields and
/// would clone without the credential.
pub const CAPABILITY_IMAGE_BUILD_PRIVATE_GIT: &str = "image.build.private_git.v1";
/// Loads a local build into the Podman store. It also tells Coolify that
/// `image.build.v1` accepts a `localhost/` image, so a single-Node cluster
/// needs no registry.
pub const CAPABILITY_IMAGE_LOAD: &str = "image.load.v1";
/// `image.build.v1` accepts `push_image`, `push_username`, and
/// `push_password`. Not a command: an older Sentinel ignores the fields and
/// would not push the image.
pub const CAPABILITY_IMAGE_BUILD_EXTERNAL_PUSH: &str = "image.build.external_push.v1";
/// `workload.deploy.v1` accepts `registry_username` and `registry_password`.
/// Not a command: an older Sentinel ignores the fields and would pull without
/// the login.
pub const CAPABILITY_WORKLOAD_REGISTRY_AUTH: &str = "workload.registry_auth.v1";
/// `image.build.v1` accepts `build_args` and `build_secrets` (decision 0012).
/// Not a command: an older Sentinel ignores the fields and would build
/// without the variables.
pub const CAPABILITY_IMAGE_BUILD_VARIABLES: &str = "image.build.variables.v1";
/// `image.build.v1` accepts `dockerfile_content` without a repository. Not a
/// command: an older Sentinel rejects the request for its empty repository.
pub const CAPABILITY_IMAGE_BUILD_INLINE_DOCKERFILE: &str = "image.build.inline_dockerfile.v1";
pub const BUILD_CAPABILITIES: [&str; 10] = [
    CAPABILITY_IMAGE_BUILD,
    CAPABILITY_IMAGE_BUILD_PRIVATE_GIT,
    CAPABILITY_IMAGE_LOAD,
    CAPABILITY_IMAGE_BUILD_EXTERNAL_PUSH,
    CAPABILITY_IMAGE_BUILD_VARIABLES,
    CAPABILITY_IMAGE_BUILD_INLINE_DOCKERFILE,
    CAPABILITY_WORKLOAD_REGISTRY_AUTH,
    CAPABILITY_BUILDER_RECONCILE,
    CAPABILITY_REGISTRY_RECONCILE,
    CAPABILITY_REGISTRY_INSPECT,
];
/// `workload.deploy.v1` accepts `mounts`. Not a command: an older Sentinel
/// ignores the field and would run the container without its data.
pub const CAPABILITY_VOLUME_MOUNTS: &str = "volume.mounts.v1";
pub const CAPABILITY_VOLUME_DELETE: &str = "volume.delete.v1";
pub const CAPABILITY_VOLUME_SERVE: &str = "volume.serve.v1";
pub const CAPABILITY_VOLUME_RECEIVE: &str = "volume.receive.v1";
/// This Sentinel serves and receives volumes for a move (decision 0007). Not a
/// command.
pub const CAPABILITY_VOLUME_TRANSFER: &str = "volume.transfer.v1";
/// `volume.receive.v1` accepts the `verify` pass. Not a command.
pub const CAPABILITY_VOLUME_VERIFY: &str = "volume.verify.v1";
/// `workload.lifecycle.v1` accepts `stop_timeout_seconds`, so a move can give
/// the source time for a clean shutdown. Not a command.
pub const CAPABILITY_WORKLOAD_STOP_TIMEOUT: &str = "workload.stop_timeout.v1";
/// Backs up a volume to S3 with presigned multipart part URLs (decision 0009).
pub const CAPABILITY_VOLUME_BACKUP: &str = "volume.backup.v1";
/// Restores a volume backup from a presigned URL (decision 0009).
pub const CAPABILITY_VOLUME_RESTORE: &str = "volume.restore.v1";
/// `workload.deploy.v1` accepts `secrets`, mounted as files at
/// `/run/secrets/<key>`, and `workload.lifecycle.v1` with `remove` deletes the
/// secrets of the container (decision 0008). Not a command: an older Sentinel
/// ignores the field and would start the container without its secrets.
pub const CAPABILITY_WORKLOAD_SECRETS: &str = "workload.secrets.v1";
/// `workload.lifecycle.v1` with `stop` or `remove` drains the endpoint from
/// ingress and internal DNS whenever another endpoint of the workload serves,
/// so Coolify can start a second container of a workload and then remove the
/// old one without failed requests (decision 0022). Not a command.
pub const CAPABILITY_WORKLOAD_ROLLING_DEPLOY: &str = "workload.rolling_deploy.v1";
pub const VOLUME_CAPABILITIES: [&str; 9] = [
    CAPABILITY_VOLUME_MOUNTS,
    CAPABILITY_VOLUME_DELETE,
    CAPABILITY_VOLUME_SERVE,
    CAPABILITY_VOLUME_RECEIVE,
    CAPABILITY_VOLUME_TRANSFER,
    CAPABILITY_VOLUME_VERIFY,
    CAPABILITY_WORKLOAD_STOP_TIMEOUT,
    CAPABILITY_VOLUME_BACKUP,
    CAPABILITY_VOLUME_RESTORE,
];
/// Runs one command in a managed container (decision 0018).
pub const CAPABILITY_WORKLOAD_EXEC: &str = "workload.exec.v1";
/// Opens an interactive shell in a managed container (decision 0018).
pub const CAPABILITY_WORKLOAD_TERMINAL: &str = "workload.terminal.v1";
pub const EXEC_CAPABILITIES: [&str; 2] = [CAPABILITY_WORKLOAD_EXEC, CAPABILITY_WORKLOAD_TERMINAL];
/// The cluster registry. Sentinel discovery DNS resolves it to the Node that
/// runs the registry.
pub const REGISTRY_HOST: &str = "registry.cluster.coolify.internal:5443";
pub const NETWORK_CAPABILITIES: [&str; 11] = [
    CAPABILITY_CLUSTER_LEAVE,
    CAPABILITY_WIREGUARD_KEY_ENSURE,
    CAPABILITY_WIREGUARD_INSPECT,
    CAPABILITY_WIREGUARD_RECONCILE,
    CAPABILITY_FIREWALL_INSPECT,
    CAPABILITY_FIREWALL_RECONCILE,
    CAPABILITY_CORROSION_INSPECT,
    CAPABILITY_CORROSION_RECONCILE,
    CAPABILITY_INGRESS_RECONCILE,
    CAPABILITY_INGRESS_TLS,
    CAPABILITY_INGRESS_ROUTES_V2,
];

pub mod control {
    pub mod v1 {
        tonic::include_proto!("coolify.sentinel.control.v1");

        impl std::fmt::Debug for ImageBuildRequest {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let redacted = |value: &str| if value.is_empty() { "" } else { "[redacted]" };
                formatter
                    .debug_struct("ImageBuildRequest")
                    .field("build_id", &self.build_id)
                    .field("builder_image", &self.builder_image)
                    .field("repository_url", &self.repository_url)
                    .field("commit_sha", &self.commit_sha)
                    .field("source_type", &self.source_type)
                    .field("base_directory", &self.base_directory)
                    .field("dockerfile_path", &self.dockerfile_path)
                    .field("image", &self.image)
                    .field("git_https_token", &redacted(&self.git_https_token))
                    .field("git_ssh_private_key", &redacted(&self.git_ssh_private_key))
                    .field("push_image", &self.push_image)
                    .field("push_username", &self.push_username)
                    .field("push_password", &redacted(&self.push_password))
                    .field(
                        "build_arg_keys",
                        &self.build_args.keys().collect::<Vec<_>>(),
                    )
                    .field(
                        "build_secret_keys",
                        &self.build_secrets.keys().collect::<Vec<_>>(),
                    )
                    .field("dockerfile_content_bytes", &self.dockerfile_content.len())
                    .finish()
            }
        }

        impl std::fmt::Debug for WorkloadDeployRequest {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let redacted = |value: &str| if value.is_empty() { "" } else { "[redacted]" };
                formatter
                    .debug_struct("WorkloadDeployRequest")
                    .field("name", &self.name)
                    .field("image", &self.image)
                    .field("environment_count", &self.environment.len())
                    .field("secret_count", &self.secrets.len())
                    .field("mount_count", &self.mounts.len())
                    .field("network_name", &self.network_name)
                    .field("container_ip", &self.container_ip)
                    .field("registry_username", &self.registry_username)
                    .field("registry_password", &redacted(&self.registry_password))
                    .finish_non_exhaustive()
            }
        }

        impl std::fmt::Debug for VolumeBackupPartUrl {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("VolumeBackupPartUrl")
                    .field("part_number", &self.part_number)
                    .field("url", &"[redacted]")
                    .finish()
            }
        }

        impl std::fmt::Debug for VolumeRestoreRequest {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("VolumeRestoreRequest")
                    .field("restore_id", &self.restore_id)
                    .field("step", &self.step)
                    .field("volume_name", &self.volume_name)
                    .field(
                        "url",
                        &if self.url.is_empty() {
                            ""
                        } else {
                            "[redacted]"
                        },
                    )
                    .field("sha256", &self.sha256)
                    .field("archive_bytes", &self.archive_bytes)
                    .field("target_volume_name", &self.target_volume_name)
                    .finish()
            }
        }
    }
}

/// Container names that Podman accepts and that Sentinel also uses for file
/// names: 1 to 128 ASCII letters, digits, `.`, `-` or `_`, starting with a
/// letter or digit (so never `.` or `..`).
pub fn valid_container_name(name: &str) -> bool {
    name.len() <= 128
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

pub fn select_protocol(
    local_min: u32,
    local_max: u32,
    remote_min: u32,
    remote_max: u32,
) -> Option<u32> {
    if local_min == 0 || remote_min == 0 || local_min > local_max || remote_min > remote_max {
        return None;
    }

    let minimum = local_min.max(remote_min);
    let maximum = local_max.min(remote_max);
    (minimum <= maximum).then_some(maximum)
}

pub fn intersect_capabilities(
    granted: &[String],
    advertised: &[String],
    supported: &[&str],
) -> Vec<String> {
    let granted: HashSet<&str> = granted.iter().map(String::as_str).collect();
    let advertised: HashSet<&str> = advertised.iter().map(String::as_str).collect();
    let mut selected = HashSet::new();

    supported
        .iter()
        .copied()
        .filter(|capability| {
            granted.contains(capability)
                && advertised.contains(capability)
                && selected.insert(*capability)
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests;
