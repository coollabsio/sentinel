//! Runtime options of a workload (`workload.runtime_options.v1`, decision
//! 0028): the Compose `shm_size`, `ulimits`, `tmpfs`, `stop_grace_period`,
//! `tty`, and `stdin_open`. And `workload.runtime_options.v2` (decision 0032):
//! user labels, `init`, `read_only`, `pids_limit`, `hostname`, `entrypoint`,
//! and `extra_hosts`. Each value becomes a fixed `podman run` option.

use std::collections::HashSet;

use sentinel_protocol::control::v1::WorkloadDeployRequest;

/// 16 GiB, the largest `/dev/shm` and tmpfs size.
const MAX_MEMORY_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ULIMITS: usize = 16;
const MAX_TMPFS: usize = 8;
pub(crate) const MAX_STOP_TIMEOUT_SECONDS: u32 = 600;
const MAX_USER_LABELS: usize = 64;
const MAX_PIDS_LIMIT: i64 = 4_194_304;
const MAX_ENTRYPOINT_WORDS: usize = 64;
const MAX_EXTRA_HOSTS: usize = 32;
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

/// Validates the options of `workload.runtime_options.v2` and returns their
/// arguments: `--init`, `--read-only`, `--pids-limit`, `--hostname`,
/// `--add-host`, and `--entrypoint`, in this order.
pub(crate) fn container_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    if request.init {
        args.push("--init".into());
    }
    if request.read_only {
        args.push("--read-only".into());
    }
    if let Some(limit) = request.pids_limit {
        if limit != -1 && !(1..=MAX_PIDS_LIMIT).contains(&limit) {
            return Err("The process limit must be -1 or 1 to 4194304.".into());
        }
        args.extend(["--pids-limit".into(), limit.to_string()]);
    }
    if !request.hostname.is_empty() {
        if !valid_dns_label(&request.hostname) {
            return Err("The hostname is invalid.".into());
        }
        args.extend(["--hostname".into(), request.hostname.clone()]);
    }
    if request.extra_hosts.len() > MAX_EXTRA_HOSTS {
        return Err("The workload has too many extra hosts.".into());
    }
    for host in &request.extra_hosts {
        if host.ip == "host-gateway" {
            return Err("An extra host cannot point to host-gateway.".into());
        }
        if !valid_dns_name(&host.name) {
            return Err("The name of an extra host is invalid.".into());
        }
        let Ok(ip) = host.ip.parse::<std::net::IpAddr>() else {
            return Err(format!(
                "The address of the extra host {} is invalid.",
                host.name
            ));
        };
        // Podman splits at the first `:`, so an IPv6 address needs no brackets.
        args.extend(["--add-host".into(), format!("{}:{ip}", host.name)]);
    }
    if !request.entrypoint.is_empty() {
        if request.entrypoint.len() > MAX_ENTRYPOINT_WORDS
            || request.entrypoint[0].is_empty()
            || request
                .entrypoint
                .iter()
                .any(|word| word.len() > 4_096 || word.contains('\0'))
        {
            return Err("The entrypoint is invalid.".into());
        }
        args.extend([
            "--entrypoint".into(),
            serde_json::to_string(&request.entrypoint)
                .map_err(|_| "The entrypoint is invalid.".to_string())?,
        ]);
    }
    Ok(args)
}

/// A label key that a user may not set, in `user_labels` or in `labels`:
/// Podman reads `io.containers.*`, `io.podman.*`, and `PODMAN_SYSTEMD_UNIT`.
pub(crate) fn podman_label_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.starts_with("io.containers.")
        || lower.starts_with("io.podman.")
        || lower == "podman_systemd_unit"
}

/// Validates the labels of the user and returns their `--label` arguments.
/// Their keys differ from the keys of `labels` and never start with
/// `coolify.`, the prefix of the labels that Sentinel reads for ownership.
pub(crate) fn user_label_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    if request.user_labels.len() > MAX_USER_LABELS {
        return Err("The workload has too many user labels.".into());
    }
    let own: HashSet<&str> = request
        .labels
        .iter()
        .map(|label| label.key.as_str())
        .collect();
    let mut keys = HashSet::with_capacity(request.user_labels.len());
    let mut args = Vec::with_capacity(request.user_labels.len() * 2);
    for label in &request.user_labels {
        let key = label.key.as_str();
        let valid = !key.is_empty()
            && key.len() <= 255
            && key.as_bytes()[0].is_ascii_alphanumeric()
            && key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte));
        if !valid || label.value.len() > 4_096 || label.value.contains('\0') {
            return Err("A user label is invalid.".into());
        }
        if key.to_ascii_lowercase().starts_with("coolify.") || podman_label_key(key) {
            return Err(format!("The label key {key} is reserved."));
        }
        if own.contains(key) || !keys.insert(key) {
            return Err(format!("The label {key} is set twice."));
        }
        args.extend(["--label".into(), format!("{key}={}", label.value)]);
    }
    Ok(args)
}

/// One DNS label: 1 to 63 of `[A-Za-z0-9-]`, without `-` at the start or the end.
fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// A DNS name of at most 253 characters, without a trailing dot.
fn valid_dns_name(name: &str) -> bool {
    name.len() <= 253 && name.split('.').all(valid_dns_label)
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
    use sentinel_protocol::control::v1::{
        WorkloadFile, WorkloadHost, WorkloadLabel, WorkloadTmpfs, WorkloadUlimit,
    };

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

    fn host(name: &str, ip: &str) -> WorkloadHost {
        WorkloadHost {
            name: name.into(),
            ip: ip.into(),
        }
    }

    fn label(key: &str, value: &str) -> WorkloadLabel {
        WorkloadLabel {
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn container_args_add_nothing_without_a_value() {
        assert!(container_args(&base()).unwrap().is_empty());
        assert!(user_label_args(&base()).unwrap().is_empty());
    }

    #[test]
    fn limits_the_processes() {
        for limit in [-1, 1, MAX_PIDS_LIMIT] {
            let request = WorkloadDeployRequest {
                pids_limit: Some(limit),
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap(),
                ["--pids-limit".to_string(), limit.to_string()]
            );
        }
        for limit in [0, -2, MAX_PIDS_LIMIT + 1] {
            let request = WorkloadDeployRequest {
                pids_limit: Some(limit),
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap_err(),
                "The process limit must be -1 or 1 to 4194304."
            );
        }
    }

    #[test]
    fn checks_the_hostname() {
        let long = "a".repeat(63);
        for hostname in ["web", "Web-1", "1", long.as_str()] {
            let request = WorkloadDeployRequest {
                hostname: hostname.into(),
                ..base()
            };
            assert_eq!(container_args(&request).unwrap(), ["--hostname", hostname]);
        }
        let too_long = "a".repeat(64);
        for hostname in [
            "-web",
            "web-",
            "web.example.com",
            "we_b",
            "web 1",
            too_long.as_str(),
        ] {
            let request = WorkloadDeployRequest {
                hostname: hostname.into(),
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap_err(),
                "The hostname is invalid.",
                "{hostname}"
            );
        }
    }

    #[test]
    fn checks_the_extra_hosts() {
        let request = WorkloadDeployRequest {
            extra_hosts: vec![host("db", "192.0.2.1"), host("v6.local", "::1")],
            ..base()
        };
        assert_eq!(
            container_args(&request).unwrap(),
            ["--add-host", "db:192.0.2.1", "--add-host", "v6.local:::1"]
        );
        let request = WorkloadDeployRequest {
            extra_hosts: vec![host("db", "host-gateway")],
            ..base()
        };
        assert_eq!(
            container_args(&request).unwrap_err(),
            "An extra host cannot point to host-gateway."
        );
        for name in ["", "db.", "-db", "a;b", "db:1", "a..b", &"a".repeat(254)] {
            let request = WorkloadDeployRequest {
                extra_hosts: vec![host(name, "192.0.2.1")],
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap_err(),
                "The name of an extra host is invalid.",
                "{name}"
            );
        }
        for ip in [
            "",
            "192.0.2",
            "[::1]",
            "fe80::1%eth0",
            "example.com",
            "192.0.2.1/32",
        ] {
            let request = WorkloadDeployRequest {
                extra_hosts: vec![host("db", ip)],
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap_err(),
                "The address of the extra host db is invalid.",
                "{ip}"
            );
        }
        let request = WorkloadDeployRequest {
            extra_hosts: (0..33).map(|_| host("db", "192.0.2.1")).collect(),
            ..base()
        };
        assert_eq!(
            container_args(&request).unwrap_err(),
            "The workload has too many extra hosts."
        );
    }

    #[test]
    fn checks_the_entrypoint() {
        let request = WorkloadDeployRequest {
            entrypoint: vec!["tini".into(), "--".into(), String::new()],
            ..base()
        };
        assert_eq!(
            container_args(&request).unwrap(),
            ["--entrypoint", r#"["tini","--",""]"#]
        );
        for entrypoint in [
            vec![String::new()],
            vec!["a\0".to_string()],
            vec!["a".repeat(4_097)],
            (0..65).map(|_| "a".to_string()).collect(),
        ] {
            let request = WorkloadDeployRequest {
                entrypoint,
                ..base()
            };
            assert_eq!(
                container_args(&request).unwrap_err(),
                "The entrypoint is invalid."
            );
        }
    }

    #[test]
    fn checks_the_user_labels() {
        let request = WorkloadDeployRequest {
            labels: vec![label("coolify.managed", "true")],
            user_labels: vec![label("com.example/app", "a=b"), label("9tier", "")],
            ..base()
        };
        assert_eq!(
            user_label_args(&request).unwrap(),
            ["--label", "com.example/app=a=b", "--label", "9tier="]
        );
        for key in [
            "coolify.managed",
            "Coolify.workload",
            "io.containers.autoupdate",
            "IO.PODMAN.x",
            "PODMAN_SYSTEMD_UNIT",
        ] {
            let request = WorkloadDeployRequest {
                user_labels: vec![label(key, "x")],
                ..base()
            };
            assert_eq!(
                user_label_args(&request).unwrap_err(),
                format!("The label key {key} is reserved.")
            );
        }
        for key in ["", ".app", "-app", "a=b", "a b", "a\0", &"a".repeat(256)] {
            let request = WorkloadDeployRequest {
                user_labels: vec![label(key, "x")],
                ..base()
            };
            assert_eq!(
                user_label_args(&request).unwrap_err(),
                "A user label is invalid."
            );
        }
        for value in ["a\0".to_string(), "a".repeat(4_097)] {
            let request = WorkloadDeployRequest {
                user_labels: vec![label("app", &value)],
                ..base()
            };
            assert_eq!(
                user_label_args(&request).unwrap_err(),
                "A user label is invalid."
            );
        }
        let request = WorkloadDeployRequest {
            labels: vec![label("app", "1")],
            user_labels: vec![label("app", "2")],
            ..base()
        };
        assert_eq!(
            user_label_args(&request).unwrap_err(),
            "The label app is set twice."
        );
        let request = WorkloadDeployRequest {
            user_labels: vec![label("app", "1"), label("app", "2")],
            ..base()
        };
        assert_eq!(
            user_label_args(&request).unwrap_err(),
            "The label app is set twice."
        );
        let request = WorkloadDeployRequest {
            user_labels: (0..65)
                .map(|index| label(&format!("l{index}"), ""))
                .collect(),
            ..base()
        };
        assert_eq!(
            user_label_args(&request).unwrap_err(),
            "The workload has too many user labels."
        );
    }
}
