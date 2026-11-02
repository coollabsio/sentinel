//! Named Podman volumes that Coolify manages (decision 0007): deploy mounts,
//! the volume inventory, and `volume.delete.v1`.

use std::path::{Component, Path};

use sentinel_protocol::control::v1::{
    VolumeDeleteRequest, VolumeDeleteResult, VolumeObservation, WorkloadVolumeMount,
};

use crate::commands::{PODMAN_QUERY_TIMEOUT, podman_failure};
use crate::network::output_with_timeout;

pub(crate) const VOLUME_PREFIX: &str = "coolify-vol-";
pub(crate) const MAX_VOLUMES: usize = 32;
const MANAGED_LABEL: &str = "coolify.managed";
const VOLUME_LABEL: &str = "coolify.volume";

/// `coolify-vol-<uuid>`, where the UUID is a Coolify CUID2: 1 to 64 lowercase
/// ASCII letters or digits.
pub(crate) fn valid_volume_name(name: &str) -> bool {
    name.strip_prefix(VOLUME_PREFIX).is_some_and(|uuid| {
        (1..=64).contains(&uuid.len())
            && uuid
                .chars()
                .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
    })
}

pub(crate) fn validate_names(names: &[String]) -> Result<(), String> {
    if names.is_empty() || names.len() > MAX_VOLUMES {
        return Err("The number of volumes is invalid.".into());
    }
    if names.iter().any(|name| !valid_volume_name(name)) {
        return Err("A volume name is invalid.".into());
    }
    let mut unique = names.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != names.len() {
        return Err("A volume is listed twice.".into());
    }
    Ok(())
}

fn valid_container_path(path: &str) -> bool {
    path.len() <= 4_096
        && path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains("//")
        && !path
            .chars()
            .any(|character| character == ',' || character.is_control())
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Validates the mounts and returns their `--mount` arguments.
pub(crate) fn mount_args(mounts: &[WorkloadVolumeMount]) -> Result<Vec<String>, String> {
    if mounts.len() > MAX_VOLUMES {
        return Err("The workload has too many volume mounts.".into());
    }
    let mut paths = Vec::with_capacity(mounts.len());
    let mut args = Vec::with_capacity(mounts.len() * 2);
    for mount in mounts {
        if !valid_volume_name(&mount.volume_name) {
            return Err("A volume name is invalid.".into());
        }
        if !valid_container_path(&mount.container_path) {
            return Err("A volume mount path is invalid.".into());
        }
        if paths.contains(&mount.container_path.as_str()) {
            return Err("Two volume mounts use the same path.".into());
        }
        paths.push(mount.container_path.as_str());
        args.push("--mount".into());
        args.push(format!(
            "type=volume,source={},target={}{}",
            mount.volume_name,
            mount.container_path,
            if mount.read_only { ",ro" } else { "" }
        ));
    }
    Ok(args)
}

fn podman_query(podman: &Path, args: &[&str]) -> Result<std::process::Output, String> {
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
        message.chars().take(2_000).collect()
    }
}

fn volume_exists(podman: &Path, name: &str) -> Result<bool, String> {
    let output = podman_query(podman, &["volume", "exists", name])?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(stderr_message(
            &output,
            "Podman could not check the volume.",
        )),
    }
}

/// Creates each volume that does not exist yet. Podman cannot change the
/// labels of an existing volume, so an existing volume stays as it is.
pub(crate) fn ensure_volumes<'a>(
    podman: &Path,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    for name in names {
        if volume_exists(podman, name)? {
            continue;
        }
        let uuid = name.strip_prefix(VOLUME_PREFIX).unwrap_or(name);
        let managed = format!("{MANAGED_LABEL}=true");
        let volume = format!("{VOLUME_LABEL}={uuid}");
        let output = podman_query(
            podman,
            &[
                "volume", "create", "--label", &managed, "--label", &volume, name,
            ],
        )?;
        // Another command can create the same volume in between.
        if !output.status.success() && !volume_exists(podman, name)? {
            return Err(stderr_message(
                &output,
                "Podman could not create the volume.",
            ));
        }
    }
    Ok(())
}

/// The host directory of a volume: its `_data` directory.
pub(crate) fn mountpoint(podman: &Path, name: &str) -> Result<String, String> {
    let output = podman_query(
        podman,
        &["volume", "inspect", "--format", "{{.Mountpoint}}", name],
    )?;
    if !output.status.success() {
        return Err(stderr_message(
            &output,
            "Podman could not inspect the volume.",
        ));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !path.starts_with('/') || path.contains('\n') {
        return Err("Podman returned an invalid volume mountpoint.".into());
    }
    Ok(path)
}

pub(crate) fn list(podman: &Path) -> Result<Vec<VolumeObservation>, &'static str> {
    let filter = format!("label={MANAGED_LABEL}=true");
    let output = output_with_timeout(
        std::process::Command::new(podman)
            .args(["volume", "ls", "--filter", &filter, "--format", "json"]),
        PODMAN_QUERY_TIMEOUT,
    )
    .map_err(|_| "Podman is unavailable or did not answer.")?;
    if !output.status.success() {
        return Err("Podman could not list volumes.");
    }
    parse_volumes(&output.stdout)
}

pub(crate) fn parse_volumes(output: &[u8]) -> Result<Vec<VolumeObservation>, &'static str> {
    // Podman prints nothing instead of `[]` in some versions.
    if output.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(output).map_err(|_| "Podman returned invalid volume data.")?;
    if values.len() > 10_000 {
        return Err("Podman returned too many volumes.");
    }
    let mut volumes = Vec::with_capacity(values.len());
    for value in &values {
        let name = value
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or("Podman returned a volume without a name.")?;
        let labels: std::collections::HashMap<String, String> = value
            .get("Labels")
            .and_then(serde_json::Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| {
                        value.as_str().map(|value| (key.clone(), value.into()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        // The filter already selects these; this keeps the contract if it ever does not.
        if labels.get(MANAGED_LABEL).map(String::as_str) != Some("true") {
            continue;
        }
        let created_at_unix_ms = value
            .get("CreatedAt")
            .and_then(serde_json::Value::as_str)
            .and_then(|created| {
                time::OffsetDateTime::parse(created, &time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .and_then(|created| i64::try_from(created.unix_timestamp_nanos() / 1_000_000).ok())
            .filter(|millis| *millis > 0);
        volumes.push(VolumeObservation {
            name: name.into(),
            labels,
            created_at_unix_ms,
        });
    }
    Ok(volumes)
}

pub(crate) fn validate_delete(request: &VolumeDeleteRequest) -> Result<(), String> {
    validate_names(&request.names)
}

/// Deletes volumes that no container uses. It checks every volume first, so a
/// rejected request deletes nothing.
pub(crate) fn delete(
    podman: &Path,
    request: &VolumeDeleteRequest,
) -> Result<VolumeDeleteResult, String> {
    validate_delete(request)?;
    let mut existing = Vec::new();
    let mut missing = Vec::new();
    for name in &request.names {
        if !volume_exists(podman, name)? {
            missing.push(name.clone());
            continue;
        }
        let filter = format!("volume={name}");
        let users = podman_query(
            podman,
            &["ps", "--all", "--filter", &filter, "--format", "{{.Names}}"],
        )?;
        if !users.status.success() {
            return Err(stderr_message(
                &users,
                "Podman could not list the containers of the volume.",
            ));
        }
        let users = String::from_utf8_lossy(&users.stdout).trim().to_string();
        if !users.is_empty() {
            return Err(format!(
                "The volume {name} is used by the container {}.",
                users.lines().collect::<Vec<_>>().join(", ")
            ));
        }
        existing.push(name.clone());
    }
    let mut deleted = Vec::new();
    for name in existing {
        // Without `--force`: Podman refuses a volume that a container started using in between.
        let output = podman_query(podman, &["volume", "rm", &name])?;
        if output.status.success() {
            deleted.push(name);
        } else if volume_exists(podman, &name)? {
            return Err(stderr_message(
                &output,
                "Podman could not delete the volume.",
            ));
        } else {
            missing.push(name);
        }
    }
    Ok(VolumeDeleteResult { deleted, missing })
}
