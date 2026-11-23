//! The host Podman socket in a workload (`workload.container_socket.v1`), for
//! Compose services that mount the Docker socket, such as Dozzle or Portainer.
//!
//! SECURITY: The socket gives the container root on the Node. Rootful Podman
//! starts any container that the socket client asks for, also with host
//! mounts. Coolify permits it only for admins.

use std::collections::HashSet;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use sentinel_protocol::control::v1::WorkloadDeployRequest;

/// The host path of the socket. PrepareNodeHost of Coolify enables
/// `podman.socket`, which listens here.
const HOST_SOCKET: &str = "/run/podman/podman.sock";
const MAX_PATHS: usize = 4;

/// Validates the socket paths of the request and returns their `--volume`
/// arguments. The mount is read-write, because the API clients must write to
/// the socket.
pub(crate) fn mount_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    let paths = &request.container_socket_paths;
    if paths.len() > MAX_PATHS {
        return Err("The workload has too many container socket paths.".into());
    }
    let used: HashSet<&str> = request
        .mounts
        .iter()
        .map(|mount| mount.container_path.as_str())
        .chain(request.files.iter().map(|file| file.path.as_str()))
        .collect();
    let mut seen = HashSet::with_capacity(paths.len());
    let mut args = Vec::with_capacity(paths.len() * 2);
    for path in paths {
        // `:` separates the parts of a `--volume` value.
        if !crate::files::valid_path(path) || path.contains(':') {
            return Err("A container socket path is invalid.".into());
        }
        if !seen.insert(path.as_str()) || used.contains(path.as_str()) {
            return Err(format!("The path {path} is used twice."));
        }
        args.push("--volume".into());
        args.push(format!("{HOST_SOCKET}:{path}"));
    }
    Ok(args)
}

/// Makes sure that the host socket is available when the request needs it.
/// `root` is the host root. Without the socket, Podman would create an empty
/// directory at the host path and the container would start without the API.
pub(crate) fn ensure_host_socket(
    root: &Path,
    request: &WorkloadDeployRequest,
) -> Result<(), String> {
    if request.container_socket_paths.is_empty() {
        return Ok(());
    }
    let path = root.join(HOST_SOCKET.trim_start_matches('/'));
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(()),
        _ => Err(format!(
            "The Podman socket {HOST_SOCKET} is not available on this server."
        )),
    }
}

#[cfg(test)]
mod tests {
    use sentinel_protocol::control::v1::{WorkloadFile, WorkloadVolumeMount};

    use super::*;

    fn request(paths: &[&str]) -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-p1test-main".into(),
            container_socket_paths: paths.iter().map(|path| path.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn mounts_the_host_socket_read_write_at_each_path() {
        assert_eq!(
            mount_args(&request(&["/var/run/docker.sock", "/run/podman.sock"])).unwrap(),
            [
                "--volume",
                "/run/podman/podman.sock:/var/run/docker.sock",
                "--volume",
                "/run/podman/podman.sock:/run/podman.sock",
            ]
        );
        assert!(mount_args(&request(&[])).unwrap().is_empty());
    }

    #[test]
    fn rejects_invalid_and_duplicate_paths() {
        for path in [
            "",
            "relative.sock",
            "/",
            "/var/run/",
            "/var//run/docker.sock",
            "/var/../docker.sock",
            "/a,b",
            "/a:b",
            "/a:/b:ro",
            "/a\nb",
            "/proc/docker.sock",
            "/sys/docker.sock",
            "/dev/docker.sock",
            "/run/secrets/docker.sock",
        ] {
            assert_eq!(
                mount_args(&request(&[path])).unwrap_err(),
                "A container socket path is invalid.",
                "{path:?}"
            );
        }
        assert!(mount_args(&request(&["/a.sock"; 5])).is_err());
        assert_eq!(
            mount_args(&request(&["/docker.sock", "/docker.sock"])).unwrap_err(),
            "The path /docker.sock is used twice."
        );
        let mut with_mount = request(&["/data"]);
        with_mount.mounts = vec![WorkloadVolumeMount {
            container_path: "/data".into(),
            ..Default::default()
        }];
        assert!(mount_args(&with_mount).is_err());
        let mut with_file = request(&["/etc/app.sock"]);
        with_file.files = vec![WorkloadFile {
            path: "/etc/app.sock".into(),
            ..Default::default()
        }];
        assert!(mount_args(&with_file).is_err());
    }

    #[test]
    fn fails_without_the_host_socket() {
        let root = tempfile::tempdir().unwrap();
        assert!(ensure_host_socket(root.path(), &request(&[])).is_ok());
        assert_eq!(
            ensure_host_socket(root.path(), &request(&["/var/run/docker.sock"])).unwrap_err(),
            "The Podman socket /run/podman/podman.sock is not available on this server."
        );
        let dir = root.path().join("run/podman");
        std::fs::create_dir_all(&dir).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(dir.join("podman.sock")).unwrap();
        assert!(ensure_host_socket(root.path(), &request(&["/var/run/docker.sock"])).is_ok());
    }
}
