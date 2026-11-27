//! The isolation options of a container: `--cap-add`, `--cap-drop`,
//! `--security-opt no-new-privileges`, and `--sysctl` (decisions 0032 and 0036
//! of Coolify). Sentinel accepts the values of tiers 1 and 2 and refuses the
//! rest. Coolify decides which users may set tier 2.

use std::collections::HashSet;

use sentinel_protocol::control::v1::WorkloadDeployRequest;

/// Tier 1 of `cap_add`: the capabilities of the Podman default set.
pub(crate) const TIER1_CAP_ADD: [&str; 11] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "NET_BIND_SERVICE",
    "SETFCAP",
    "SETGID",
    "SETPCAP",
    "SETUID",
    "SYS_CHROOT",
];
/// Tier 2 of `cap_add`: a team admin or owner only (Coolify checks the role).
pub(crate) const TIER2_CAP_ADD: [&str; 6] = [
    "NET_ADMIN",
    "NET_RAW",
    "SYS_PTRACE",
    "SYS_NICE",
    "SYS_RESOURCE",
    "IPC_LOCK",
];
/// The capabilities of the Linux kernel, the values of `cap_drop` besides `ALL`.
pub(crate) const LINUX_CAPABILITIES: [&str; 41] = [
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];
/// Tier 1 of `sysctls`.
pub(crate) const TIER1_SYSCTLS: [&str; 10] = [
    "net.core.somaxconn",
    "net.ipv4.ip_local_port_range",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range",
    "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.tcp_keepalive_time",
    "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes",
    "net.ipv4.tcp_fin_timeout",
    "kernel.shm_rmid_forced",
];
/// Tier 2 of `sysctls` without an interface.
pub(crate) const TIER2_SYSCTLS: [&str; 1] = ["net.ipv4.ip_forward"];
/// Tier 2 of `sysctls` with an interface: `<prefix><interface><suffix>`, where
/// the interface is `all`, `default`, or 1 to 15 of `[a-z0-9]`.
pub(crate) const TIER2_INTERFACE_SYSCTLS: [(&str, &str); 3] = [
    ("net.ipv4.conf.", ".src_valid_mark"),
    ("net.ipv4.conf.", ".forwarding"),
    ("net.ipv6.conf.", ".forwarding"),
];

const MAX_CAP_ADD: usize = 32;
const MAX_CAP_DROP: usize = 64;
const MAX_SYSCTLS: usize = 16;

pub(crate) fn allowed_cap_add(name: &str) -> bool {
    TIER1_CAP_ADD.contains(&name) || TIER2_CAP_ADD.contains(&name)
}

pub(crate) fn allowed_cap_drop(name: &str) -> bool {
    name == "ALL" || LINUX_CAPABILITIES.contains(&name)
}

pub(crate) fn allowed_sysctl(name: &str) -> bool {
    TIER1_SYSCTLS.contains(&name)
        || TIER2_SYSCTLS.contains(&name)
        || TIER2_INTERFACE_SYSCTLS.iter().any(|(prefix, suffix)| {
            name.strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .is_some_and(valid_interface)
        })
}

fn valid_interface(name: &str) -> bool {
    matches!(name, "all" | "default")
        || (!name.is_empty()
            && name.len() <= 15
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
}

/// One or two numbers of 1 to 10 digits, separated by one space.
pub(crate) fn valid_sysctl_value(value: &str) -> bool {
    let number = |part: &str| {
        !part.is_empty() && part.len() <= 10 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    match value.split_once(' ') {
        Some((first, second)) => number(first) && number(second),
        None => number(value),
    }
}

/// Validates the isolation options of the request and returns their arguments.
pub(crate) fn isolation_args(request: &WorkloadDeployRequest) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    if request.cap_drop.len() > MAX_CAP_DROP {
        return Err("The workload drops too many capabilities.".into());
    }
    let mut dropped = HashSet::with_capacity(request.cap_drop.len());
    for name in &request.cap_drop {
        if !allowed_cap_drop(name) {
            return Err("A dropped capability is invalid.".into());
        }
        if !dropped.insert(name.as_str()) {
            return Err(format!("The capability {name} is dropped twice."));
        }
        args.extend(["--cap-drop".into(), name.clone()]);
    }
    if request.cap_add.len() > MAX_CAP_ADD {
        return Err("The workload adds too many capabilities.".into());
    }
    let mut added = HashSet::with_capacity(request.cap_add.len());
    for name in &request.cap_add {
        if !allowed_cap_add(name) {
            return Err(format!(
                "The capability {} is not allowed.",
                printable(name)
            ));
        }
        if !added.insert(name.as_str()) {
            return Err(format!("The capability {name} is added twice."));
        }
        if dropped.contains(name.as_str()) {
            return Err(format!("The capability {name} is added and dropped."));
        }
        args.extend(["--cap-add".into(), name.clone()]);
    }
    if request.no_new_privileges {
        args.extend(["--security-opt".into(), "no-new-privileges".into()]);
    }
    if request.sysctls.len() > MAX_SYSCTLS {
        return Err("The workload has too many sysctls.".into());
    }
    let mut names = HashSet::with_capacity(request.sysctls.len());
    for sysctl in &request.sysctls {
        if !allowed_sysctl(&sysctl.name) {
            return Err(format!(
                "The sysctl {} is not allowed.",
                printable(&sysctl.name)
            ));
        }
        if !names.insert(sysctl.name.as_str()) {
            return Err(format!("The sysctl {} is set twice.", sysctl.name));
        }
        if !valid_sysctl_value(&sysctl.value) {
            return Err(format!(
                "The value of the sysctl {} is invalid.",
                sysctl.name
            ));
        }
        args.extend([
            "--sysctl".into(),
            format!("{}={}", sysctl.name, sysctl.value),
        ]);
    }
    Ok(args)
}

/// A refused value in an error message: at most 64 printable ASCII characters.
fn printable(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_graphic())
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::control::v1::WorkloadSysctl;

    fn base() -> WorkloadDeployRequest {
        WorkloadDeployRequest {
            name: "coolify-p1test-main".into(),
            ..Default::default()
        }
    }

    fn sysctl(name: &str, value: &str) -> WorkloadSysctl {
        WorkloadSysctl {
            name: name.into(),
            value: value.into(),
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn gives_fixed_podman_options_in_order() {
        let request = WorkloadDeployRequest {
            cap_drop: strings(&["ALL"]),
            cap_add: strings(&["CHOWN", "NET_ADMIN"]),
            no_new_privileges: true,
            sysctls: vec![
                sysctl("net.core.somaxconn", "1024"),
                sysctl("net.ipv4.ip_local_port_range", "1024 65000"),
                sysctl("net.ipv4.conf.wg0.src_valid_mark", "1"),
            ],
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap(),
            [
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "NET_ADMIN",
                "--security-opt",
                "no-new-privileges",
                "--sysctl",
                "net.core.somaxconn=1024",
                "--sysctl",
                "net.ipv4.ip_local_port_range=1024 65000",
                "--sysctl",
                "net.ipv4.conf.wg0.src_valid_mark=1",
            ]
        );
        assert!(isolation_args(&base()).unwrap().is_empty());
    }

    #[test]
    fn accepts_tiers_one_and_two_and_refuses_other_capabilities() {
        for name in TIER1_CAP_ADD.iter().chain(&TIER2_CAP_ADD) {
            let request = WorkloadDeployRequest {
                cap_add: strings(&[name]),
                ..base()
            };
            assert!(isolation_args(&request).is_ok(), "{name}");
        }
        for name in [
            "SYS_ADMIN",
            "ALL",
            "SYS_MODULE",
            "SYS_TIME",
            "SYS_RAWIO",
            "DAC_READ_SEARCH",
            "BPF",
            "CAP_CHOWN",
            "chown",
            "",
            "CHOWN --privileged",
        ] {
            let request = WorkloadDeployRequest {
                cap_add: strings(&[name]),
                ..base()
            };
            assert!(
                isolation_args(&request)
                    .unwrap_err()
                    .ends_with("is not allowed."),
                "{name:?}"
            );
        }
        let request = WorkloadDeployRequest {
            cap_add: strings(&["CHOWN", "CHOWN"]),
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap_err(),
            "The capability CHOWN is added twice."
        );
        let request = WorkloadDeployRequest {
            cap_add: strings(&["KILL"]),
            cap_drop: strings(&["KILL"]),
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap_err(),
            "The capability KILL is added and dropped."
        );
    }

    #[test]
    fn drops_any_linux_capability() {
        let request = WorkloadDeployRequest {
            cap_drop: LINUX_CAPABILITIES
                .iter()
                .map(|name| name.to_string())
                .collect(),
            ..base()
        };
        assert_eq!(isolation_args(&request).unwrap().len(), 82);
        for name in ["CAP_KILL", "kill", "FOO", ""] {
            let request = WorkloadDeployRequest {
                cap_drop: strings(&[name]),
                ..base()
            };
            assert_eq!(
                isolation_args(&request).unwrap_err(),
                "A dropped capability is invalid."
            );
        }
        let request = WorkloadDeployRequest {
            cap_drop: strings(&["ALL", "ALL"]),
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap_err(),
            "The capability ALL is dropped twice."
        );
    }

    #[test]
    fn accepts_allowed_sysctls_only() {
        for name in [
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.src_valid_mark",
            "net.ipv4.conf.default.forwarding",
            "net.ipv6.conf.eth0.forwarding",
            "kernel.shm_rmid_forced",
        ] {
            assert!(allowed_sysctl(name), "{name}");
        }
        for name in [
            "kernel.msgmax",
            "kernel.shmmax",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.Eth0.forwarding",
            "net.ipv4.conf.abcdefghijklmnop.forwarding",
            "net.ipv4.conf..forwarding",
            "net.ipv4.conf.a.b.forwarding",
            "net.ipv6.conf.all.src_valid_mark",
            "vm.overcommit_memory",
        ] {
            let request = WorkloadDeployRequest {
                sysctls: vec![sysctl(name, "1")],
                ..base()
            };
            assert!(
                isolation_args(&request)
                    .unwrap_err()
                    .ends_with("is not allowed."),
                "{name}"
            );
        }
        for value in ["", "1  2", " 1", "1 ", "a", "12345678901", "1 2 3", "1\n"] {
            let request = WorkloadDeployRequest {
                sysctls: vec![sysctl("net.core.somaxconn", value)],
                ..base()
            };
            assert_eq!(
                isolation_args(&request).unwrap_err(),
                "The value of the sysctl net.core.somaxconn is invalid.",
                "{value:?}"
            );
        }
        let request = WorkloadDeployRequest {
            sysctls: vec![
                sysctl("net.core.somaxconn", "1"),
                sysctl("net.core.somaxconn", "2"),
            ],
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap_err(),
            "The sysctl net.core.somaxconn is set twice."
        );
        let request = WorkloadDeployRequest {
            sysctls: (0..17).map(|_| sysctl("net.core.somaxconn", "1")).collect(),
            ..base()
        };
        assert_eq!(
            isolation_args(&request).unwrap_err(),
            "The workload has too many sysctls."
        );
    }
}
