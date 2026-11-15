//! Workload secrets (decision 0008): values that a container reads as files at
//! `/run/secrets/<key>`. Each value is a Podman secret of one revision, so a
//! secret never changes while a container uses it. Podman reads a secret at
//! each container start, so a secret of the running revision must stay until
//! the container is replaced or removed.

use std::collections::HashSet;
use std::path::Path;

use sentinel_protocol::control::v1::WorkloadDeployRequest;
use sha2::{Digest, Sha256};

use crate::commands::{PODMAN_QUERY_TIMEOUT, podman_failure, podman_runtime_variable};
use crate::network::output_with_timeout;

const MAX_SECRETS: usize = 128;
const MAX_VALUE_BYTES: usize = 512_000;
const MAX_ID: u32 = i32::MAX as u32;
const REVISION_LABEL: &str = "coolify.revision";
/// `podman secret create --env` reads the value from this variable of its own
/// process, so the value is never in a command line.
const VALUE_VARIABLE: &str = "COOLIFY_SECRET_VALUE";

/// The `--secret` arguments of `podman run`. Validates the secrets of the request.
pub(crate) fn mount_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    if request.secrets.is_empty() {
        return Ok(Vec::new());
    }
    if request.secrets.len() > MAX_SECRETS {
        return Err("The workload has too many secrets.".into());
    }
    let revision = revision(request)?;
    let mut keys = HashSet::new();
    let mut args = Vec::new();
    for secret in &request.secrets {
        if !valid_key(&secret.key) || !keys.insert(secret.key.as_str()) {
            return Err("A secret name is invalid.".into());
        }
        if secret.value.is_empty()
            || secret.value.len() > MAX_VALUE_BYTES
            || secret.value.contains('\0')
        {
            return Err(format!(
                "The secret {} must have 1 byte to 512 kB.",
                secret.key
            ));
        }
        let mut option = format!(
            "{},type=mount,target={}",
            secret_name(&request.name, revision, &secret.key),
            secret.key
        );
        for (field, id) in [("uid", secret.uid), ("gid", secret.gid)] {
            match id {
                Some(id) if id > MAX_ID => {
                    return Err(format!(
                        "The {field} of the secret {} is invalid.",
                        secret.key
                    ));
                }
                Some(id) => option.push_str(&format!(",{field}={id}")),
                None => {}
            }
        }
        match secret.mode {
            Some(mode) if mode > 0o777 => {
                return Err(format!("The mode of the secret {} is invalid.", secret.key));
            }
            // Podman reads the mode as an octal number.
            Some(mode) => option.push_str(&format!(",mode={mode:04o}")),
            None => {}
        }
        args.extend(["--secret".into(), option]);
    }
    Ok(args)
}

/// Creates the missing secrets of the request. Idempotent: a secret of one
/// revision and key always has the same value, so an existing one stays.
/// Podman 4.9 cannot `--replace` a secret that does not exist.
pub(crate) fn create(podman: &Path, request: &WorkloadDeployRequest) -> Result<(), String> {
    if request.secrets.is_empty() {
        return Ok(());
    }
    let revision = revision(request)?;
    for secret in &request.secrets {
        let name = secret_name(&request.name, revision, &secret.key);
        let exists = output_with_timeout(
            std::process::Command::new(podman).args(["secret", "exists", &name]),
            PODMAN_QUERY_TIMEOUT,
        )
        .map_err(|error| podman_failure(&error))?;
        match exists.status.code() {
            Some(0) => continue,
            Some(1) => {}
            _ => return Err("Podman could not check the workload secrets.".into()),
        }
        let mut command = std::process::Command::new(podman);
        command
            .args(["secret", "create", "--env"])
            .args(["--label", "coolify.managed=true"])
            .arg("--label")
            .arg(format!("coolify.container={}", request.name))
            .arg(&name)
            .arg(VALUE_VARIABLE)
            .env_clear()
            .envs(std::env::vars_os().filter(|(name, _)| {
                name.to_str()
                    .is_some_and(|name| podman_runtime_variable(name) && name != "NOTIFY_SOCKET")
            }))
            .env(VALUE_VARIABLE, &secret.value);
        let output = output_with_timeout(&mut command, PODMAN_QUERY_TIMEOUT)
            .map_err(|error| podman_failure(&error))?;
        if !output.status.success() {
            return Err(format!(
                "Podman could not create the secret {}.",
                secret.key
            ));
        }
    }
    Ok(())
}

/// Deletes the secrets of the container that the request does not use. Call
/// it only after the container of the request runs: a container that still
/// uses a deleted secret cannot start again.
pub(crate) fn delete_unused(podman: &Path, request: &WorkloadDeployRequest) -> Result<(), String> {
    let keep = match revision(request) {
        Ok(revision) => request
            .secrets
            .iter()
            .map(|secret| secret_name(&request.name, revision, &secret.key))
            .collect(),
        Err(_) => HashSet::new(),
    };
    delete(podman, &request.name, &keep)
}

/// Deletes every secret of the container. Succeeds when there is none.
pub(crate) fn delete_all(podman: &Path, container: &str) -> Result<(), String> {
    delete(podman, container, &HashSet::new())
}

fn delete(podman: &Path, container: &str, keep: &HashSet<String>) -> Result<(), String> {
    // Podman 4.9 cannot filter secrets by label, so the name prefix finds them.
    let listed = output_with_timeout(
        std::process::Command::new(podman).args(["secret", "ls", "--format", "{{.Name}}"]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if !listed.status.success() {
        return Err("Podman could not list the secrets.".into());
    }
    let prefix = container_prefix(container);
    let unused: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with(&prefix) && !keep.contains(*name))
        .map(str::to_string)
        .collect();
    if unused.is_empty() {
        return Ok(());
    }
    let removed = output_with_timeout(
        std::process::Command::new(podman)
            .args(["secret", "rm"])
            .args(&unused),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|error| podman_failure(&error))?;
    if !removed.status.success() {
        return Err("Podman could not delete the secrets of the workload.".into());
    }
    Ok(())
}

fn revision(request: &WorkloadDeployRequest) -> Result<&str, String> {
    request
        .labels
        .iter()
        .find(|label| label.key == REVISION_LABEL && !label.value.is_empty())
        .map(|label| label.value.as_str())
        .ok_or_else(|| "Secrets need the coolify.revision label.".into())
}

/// A file name in `/run/secrets`. A `,` would end the `--secret` option.
pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 255
        && key != "."
        && key != ".."
        && key
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
}

fn container_prefix(container: &str) -> String {
    format!("coolify-sec-{}-", short_hash(container))
}

/// `coolify-sec-<container>-<revision>-<key>`, each part a short SHA-256, so
/// the name has no value data and stays within the Podman name limit.
pub(crate) fn secret_name(container: &str, revision: &str, key: &str) -> String {
    format!(
        "{}{}-{}",
        container_prefix(container),
        short_hash(revision),
        short_hash(key)
    )
}

fn short_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))[..16].to_string()
}

#[cfg(test)]
mod tests {
    use sentinel_protocol::control::v1::{WorkloadLabel, WorkloadSecret};

    use super::*;

    fn request(secrets: Vec<WorkloadSecret>) -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-web".into(),
            labels: vec![WorkloadLabel {
                key: REVISION_LABEL.into(),
                value: "7".into(),
            }],
            secrets,
            ..Default::default()
        }
    }

    fn secret(uid: Option<u32>, gid: Option<u32>, mode: Option<u32>) -> WorkloadSecret {
        WorkloadSecret {
            key: "db_password".into(),
            value: "hunter2".into(),
            uid,
            gid,
            mode,
        }
    }

    fn option(secret: WorkloadSecret) -> Result<String, String> {
        let args = mount_args(&request(vec![secret]))?;
        assert_eq!(args[0], "--secret");
        let name = secret_name("coolify-web", "7", "db_password");
        Ok(args[1].strip_prefix(&name).unwrap().to_string())
    }

    #[test]
    fn mounts_a_secret_with_the_podman_defaults_without_owner_or_mode() {
        assert_eq!(
            option(secret(None, None, None)).unwrap(),
            ",type=mount,target=db_password"
        );
    }

    #[test]
    fn passes_each_owner_and_mode_field() {
        assert_eq!(
            option(secret(Some(1000), None, None)).unwrap(),
            ",type=mount,target=db_password,uid=1000"
        );
        assert_eq!(
            option(secret(None, Some(0), None)).unwrap(),
            ",type=mount,target=db_password,gid=0"
        );
        assert_eq!(
            option(secret(None, None, Some(0o400))).unwrap(),
            ",type=mount,target=db_password,mode=0400"
        );
        assert_eq!(
            option(secret(Some(2_147_483_647), Some(1000), Some(0o777))).unwrap(),
            ",type=mount,target=db_password,uid=2147483647,gid=1000,mode=0777"
        );
        assert_eq!(
            option(secret(None, None, Some(0))).unwrap(),
            ",type=mount,target=db_password,mode=0000"
        );
    }

    #[test]
    fn rejects_an_owner_or_mode_out_of_range() {
        assert_eq!(
            option(secret(Some(2_147_483_648), None, None)).unwrap_err(),
            "The uid of the secret db_password is invalid."
        );
        assert_eq!(
            option(secret(None, Some(u32::MAX), None)).unwrap_err(),
            "The gid of the secret db_password is invalid."
        );
        assert_eq!(
            option(secret(None, None, Some(0o1000))).unwrap_err(),
            "The mode of the secret db_password is invalid."
        );
    }

    #[test]
    fn keeps_the_secret_name_when_owner_or_mode_change() {
        let plain = mount_args(&request(vec![secret(None, None, None)])).unwrap();
        let owned = mount_args(&request(vec![secret(Some(1), Some(2), Some(0o400))])).unwrap();
        assert_eq!(plain[1].split(',').next(), owned[1].split(',').next());
    }
}
