//! Runtime options of a workload (`workload.runtime_options.v1`, decision
//! 0028): the Compose `shm_size`, `ulimits`, `tmpfs`, `stop_grace_period`,
//! `tty`, and `stdin_open`. Each value becomes a fixed `podman run` option.

use std::collections::HashSet;

use sentinel_protocol::control::v1::WorkloadDeployRequest;

/// 16 GiB, the largest `/dev/shm` and tmpfs size.
const MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ULIMITS: usize = 16;
const MAX_TMPFS: usize = 8;
pub(crate) const MAX_STOP_TIMEOUT_SECONDS: u32 = 600;
const ULIMIT_NAMES: [&str; 8] = [
    "nofile",
    "nproc",
    "memlock",
    "core",
    "stack",
    "msgqueue",
    "sigpending",
    "rtprio",
];

/// Validates the runtime options of the request and returns their arguments.
/// A field that is not set adds nothing, so the Podman default stays.
pub(crate) fn runtime_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    if let Some(bytes) = request.shm_size_bytes {
        memory_size(bytes, request, "The shared memory size")?;
        args.extend(["--shm-size".into(), format!("{bytes}b")]);
    }
    if request.ulimits.len() > MAX_ULIMITS {
        return Err("The workload has too many ulimits.".into());
    }
    let mut names = HashSet::with_capacity(request.ulimits.len());
    for ulimit in &request.ulimits {
        if !ULIMIT_NAMES.contains(&ulimit.name.as_str()) {
            return Err("A ulimit name is invalid.".into());
        }
        if !names.insert(ulimit.name.as_str()) {
            return Err(format!("The ulimit {} is set twice.", ulimit.name));
        }
        let valid = match (ulimit.soft, ulimit.hard) {
            (-1, -1) => true,
            (soft, -1) => soft >= 0,
            (soft, hard) => soft >= 0 && hard >= 0 && soft <= hard,
        };
        if !valid {
            return Err(format!("The ulimit {} is invalid.", ulimit.name));
        }
        args.extend([
            "--ulimit".into(),
            format!("{}={}:{}", ulimit.name, ulimit.soft, ulimit.hard),
        ]);
    }
    if request.tmpfs.len() > MAX_TMPFS {
        return Err("The workload has too many tmpfs mounts.".into());
    }
    let used: HashSet<&str> = request
        .mounts
        .iter()
        .map(|mount| mount.container_path.as_str())
        .chain(request.files.iter().map(|file| file.path.as_str()))
        .chain(request.container_socket_paths.iter().map(String::as_str))
        .collect();
    let mut paths = HashSet::with_capacity(request.tmpfs.len());
    for tmpfs in &request.tmpfs {
        // `:` separates the path from the options of a `--tmpfs` value.
        if !crate::files::valid_path(&tmpfs.path) || tmpfs.path.contains(':') {
            return Err("A tmpfs path is invalid.".into());
        }
        if !paths.insert(tmpfs.path.as_str()) || used.contains(tmpfs.path.as_str()) {
            return Err(format!("The path {} is used twice.", tmpfs.path));
        }
        if tmpfs.size_bytes == 0 {
            args.extend(["--tmpfs".into(), tmpfs.path.clone()]);
        } else {
            memory_size(tmpfs.size_bytes, request, "A tmpfs size")?;
            args.extend([
                "--tmpfs".into(),
                format!("{}:size={}", tmpfs.path, tmpfs.size_bytes),
            ]);
        }
    }
    if let Some(seconds) = request.stop_timeout_seconds {
        if !(1..=MAX_STOP_TIMEOUT_SECONDS).contains(&seconds) {
            return Err("The stop timeout must be 1 to 600 seconds.".into());
        }
        args.extend(["--stop-timeout".into(), seconds.to_string()]);
    }
    if request.tty {
        args.push("--tty".into());
    }
    if request.stdin_open {
        args.push("--interactive".into());
    }
    Ok(args)
}

/// A size in memory of the Node: 1 byte to 16 GiB, and at most the memory
/// limit of the container when it has one.
fn memory_size(bytes: u64, request: &WorkloadDeployRequest, what: &str) -> Result<(), String> {
    if bytes == 0 || bytes > MAX_MEMORY_BYTES {
        return Err(format!("{what} must be 1 byte to 16 GiB."));
    }
    if request
        .memory_limit_bytes
        .is_some_and(|limit| bytes > limit)
    {
        return Err(format!(
            "{what} must not be larger than the memory limit of the container."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::control::v1::{WorkloadFile, WorkloadTmpfs, WorkloadUlimit};

    fn base() -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-p1test-main".into(),
            ..Default::default()
        }
    }

    fn ulimit(name: &str, soft: i64, hard: i64) -> WorkloadUlimit {
        WorkloadUlimit {
            name: name.into(),
            soft,
            hard,
        }
    }

    fn tmpfs(path: &str, size_bytes: u64) -> WorkloadTmpfs {
        WorkloadTmpfs {
            path: path.into(),
            size_bytes,
        }
    }

    #[test]
    fn adds_nothing_without_a_value() {
        assert!(runtime_args(&base()).unwrap().is_empty());
    }

    #[test]
    fn gives_fixed_podman_options() {
        let request = WorkloadDeployRequest {
            shm_size_bytes: Some(256 * 1024 * 1024),
            ulimits: vec![ulimit("nofile", 65_535, 65_535), ulimit("memlock", -1, -1)],
            tmpfs: vec![tmpfs("/tmp", 0), tmpfs("/var/cache/app", 64 * 1024 * 1024)],
            stop_timeout_seconds: Some(120),
            tty: true,
            stdin_open: true,
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap(),
            [
                "--shm-size",
                "268435456b",
                "--ulimit",
                "nofile=65535:65535",
                "--ulimit",
                "memlock=-1:-1",
                "--tmpfs",
                "/tmp",
                "--tmpfs",
                "/var/cache/app:size=67108864",
                "--stop-timeout",
                "120",
                "--tty",
                "--interactive",
            ]
        );
    }

    #[test]
    fn limits_memory_sizes() {
        for bytes in [0, MAX_MEMORY_BYTES + 1] {
            let request = WorkloadDeployRequest {
                shm_size_bytes: Some(bytes),
                ..base()
            };
            assert_eq!(
                runtime_args(&request).unwrap_err(),
                "The shared memory size must be 1 byte to 16 GiB."
            );
        }
        let request = WorkloadDeployRequest {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            shm_size_bytes: Some(1024 * 1024 * 1024),
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap_err(),
            "The shared memory size must not be larger than the memory limit of the container."
        );
        let request = WorkloadDeployRequest {
            memory_limit_bytes: Some(512 * 1024 * 1024),
            tmpfs: vec![tmpfs("/tmp", 1024 * 1024 * 1024)],
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap_err(),
            "A tmpfs size must not be larger than the memory limit of the container."
        );
    }

    #[test]
    fn rejects_invalid_ulimits() {
        for (ulimits, error) in [
            (vec![ulimit("nofiles", 1, 1)], "A ulimit name is invalid."),
            (vec![ulimit("as", 1, 1)], "A ulimit name is invalid."),
            (vec![ulimit("", 1, 1)], "A ulimit name is invalid."),
            (
                vec![ulimit("nofile=1:1 --privileged", 1, 1)],
                "A ulimit name is invalid.",
            ),
            (
                vec![ulimit("nofile", 2, 1)],
                "The ulimit nofile is invalid.",
            ),
            (
                vec![ulimit("nofile", -1, 10)],
                "The ulimit nofile is invalid.",
            ),
            (
                vec![ulimit("nofile", -2, -1)],
                "The ulimit nofile is invalid.",
            ),
            (
                vec![ulimit("nofile", 1, -5)],
                "The ulimit nofile is invalid.",
            ),
            (
                vec![ulimit("nofile", 1, 1), ulimit("nofile", 2, 2)],
                "The ulimit nofile is set twice.",
            ),
            (
                (0..17).map(|_| ulimit("core", 0, 0)).collect(),
                "The workload has too many ulimits.",
            ),
        ] {
            let request = WorkloadDeployRequest { ulimits, ..base() };
            assert_eq!(runtime_args(&request).unwrap_err(), error);
        }
        let request = WorkloadDeployRequest {
            ulimits: vec![ulimit("nproc", 1024, -1)],
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap(),
            ["--ulimit", "nproc=1024:-1"]
        );
    }

    #[test]
    fn rejects_invalid_tmpfs_mounts() {
        for path in [
            "tmp",
            "/",
            "/tmp/",
            "/tmp/../etc",
            "/dev/shm",
            "/proc/x",
            "/run/secrets",
            "/tmp:rw,exec",
            "/tmp,exec",
            "/tm\np",
        ] {
            let request = WorkloadDeployRequest {
                tmpfs: vec![tmpfs(path, 0)],
                ..base()
            };
            assert_eq!(
                runtime_args(&request).unwrap_err(),
                "A tmpfs path is invalid.",
                "{path:?}"
            );
        }
        let request = WorkloadDeployRequest {
            tmpfs: vec![tmpfs("/tmp", 0), tmpfs("/tmp", 0)],
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap_err(),
            "The path /tmp is used twice."
        );
        let request = WorkloadDeployRequest {
            files: vec![WorkloadFile {
                path: "/etc/app".into(),
                directory: true,
                ..Default::default()
            }],
            tmpfs: vec![tmpfs("/etc/app", 0)],
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap_err(),
            "The path /etc/app is used twice."
        );
        let request = WorkloadDeployRequest {
            tmpfs: (0..9)
                .map(|index| tmpfs(&format!("/t{index}"), 0))
                .collect(),
            ..base()
        };
        assert_eq!(
            runtime_args(&request).unwrap_err(),
            "The workload has too many tmpfs mounts."
        );
    }

    #[test]
    fn limits_the_stop_timeout() {
        for seconds in [0, 601] {
            let request = WorkloadDeployRequest {
                stop_timeout_seconds: Some(seconds),
                ..base()
            };
            assert_eq!(
                runtime_args(&request).unwrap_err(),
                "The stop timeout must be 1 to 600 seconds."
            );
        }
        for seconds in [1, 600] {
            let request = WorkloadDeployRequest {
                stop_timeout_seconds: Some(seconds),
                ..base()
            };
            assert_eq!(
                runtime_args(&request).unwrap(),
                ["--stop-timeout".to_string(), seconds.to_string()]
            );
        }
    }
}
