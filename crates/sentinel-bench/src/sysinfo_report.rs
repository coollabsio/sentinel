//! Host / environment snapshot for benchmark results (BENCHMARK.md).
//!
//! Printed at the start of every harness run so results files always include
//! the machine configuration that produced the numbers.

use std::fs;
use std::process::Command;

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("").trim()
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn cmd_stdout(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() && out.stdout.is_empty() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn os_pretty_name() -> String {
    if let Some(raw) = read_trimmed("/etc/os-release") {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    "unknown".into()
}

fn cpu_model() -> String {
    if let Some(raw) = read_trimmed("/proc/cpuinfo") {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("model name") {
                return v.trim().trim_start_matches(':').trim().to_string();
            }
            // aarch64 often uses "Processor" or "Hardware"
            if let Some(v) = line.strip_prefix("Hardware") {
                return v.trim().trim_start_matches(':').trim().to_string();
            }
        }
    }
    cmd_stdout("uname", &["-p"]).unwrap_or_else(|| "unknown".into())
}

fn meminfo_kb(key: &str) -> Option<u64> {
    let raw = read_trimmed("/proc/meminfo")?;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let num = rest
                .trim_start_matches(':')
                .split_whitespace()
                .next()?;
            return num.parse().ok();
        }
    }
    None
}

fn fmt_bytes_from_kb(kb: u64) -> String {
    let mib = kb as f64 / 1024.0;
    if mib >= 1024.0 {
        format!("{:.2} GiB ({kb} kB)", mib / 1024.0)
    } else {
        format!("{mib:.0} MiB ({kb} kB)")
    }
}

fn logical_cpus() -> String {
    std::thread::available_parallelism()
        .map(|n| n.get().to_string())
        .unwrap_or_else(|_| {
            read_trimmed("/proc/cpuinfo")
                .map(|s| s.lines().filter(|l| l.starts_with("processor")).count())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unknown".into())
        })
}

fn online_cpu_list() -> Option<String> {
    read_trimmed("/sys/devices/system/cpu/online")
}

fn cgroup_v2() -> bool {
    fs::metadata("/sys/fs/cgroup/cgroup.controllers").is_ok()
        || read_trimmed("/proc/filesystems")
            .map(|s| s.contains("cgroup2"))
            .unwrap_or(false)
}

fn cgroup_limits() -> (String, String) {
    let cpu = read_cgroup_file("cpu.max").unwrap_or_else(|| "n/a".into());
    let mem = read_cgroup_file("memory.max").unwrap_or_else(|| "n/a".into());
    (cpu, mem)
}

fn read_cgroup_file(name: &str) -> Option<String> {
    // Try unified root first (common in containers with full cgroup access).
    if let Some(v) = read_trimmed(&format!("/sys/fs/cgroup/{name}")) {
        return Some(v);
    }
    // Parse /proc/self/cgroup for the relative path (cgroup v2: "0::/path").
    let cg = read_trimmed("/proc/self/cgroup")?;
    for line in cg.lines() {
        if let Some(path) = line.split("::").nth(1) {
            let p = path.trim();
            let full = if p == "/" {
                format!("/sys/fs/cgroup/{name}")
            } else {
                format!("/sys/fs/cgroup{p}/{name}")
            };
            if let Some(v) = read_trimmed(&full) {
                return Some(v);
            }
        }
    }
    None
}

fn loadavg() -> String {
    read_trimmed("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "n/a".into())
}

fn hostname() -> String {
    read_trimmed("/etc/hostname")
        .or_else(|| cmd_stdout("hostname", &[]))
        .unwrap_or_else(|| "unknown".into())
}

fn virt() -> String {
    cmd_stdout("systemd-detect-virt", &[])
        .or_else(|| {
            if let Ok(env) = fs::read("/proc/1/environ") {
                let s = String::from_utf8_lossy(&env);
                if s.contains("container=lxc") {
                    return Some("lxc".into());
                }
                if s.contains("container=docker") {
                    return Some("docker".into());
                }
            }
            if fs::metadata("/.dockerenv").is_ok() {
                return Some("docker".into());
            }
            None
        })
        .unwrap_or_else(|| "unknown".into())
}

/// Print a markdown-friendly key=value block of the host configuration.
pub fn print_system_config() {
    let uname = cmd_stdout("uname", &["-srm"]).unwrap_or_else(|| "unknown".into());
    let arch = cmd_stdout("uname", &["-m"]).unwrap_or_else(|| "unknown".into());
    let docker_ver = cmd_stdout(
        "docker",
        &["version", "--format", "{{.Server.Version}}"],
    )
    .unwrap_or_else(|| "n/a".into());
    let docker_info = cmd_stdout(
        "docker",
        &[
            "info",
            "--format",
            "driver={{.Driver}} cgroup_driver={{.CgroupDriver}} cgroup_version={{.CgroupVersion}} ncpu={{.NCPU}} mem_total={{.MemTotal}}",
        ],
    )
    .unwrap_or_else(|| "n/a".into());

    let mem_total = meminfo_kb("MemTotal").map(fmt_bytes_from_kb).unwrap_or_else(|| "n/a".into());
    let mem_avail = meminfo_kb("MemAvailable")
        .map(fmt_bytes_from_kb)
        .unwrap_or_else(|| "n/a".into());
    let (cpu_max, mem_max) = cgroup_limits();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // RFC3339-ish UTC without extra deps.
    let date_utc = cmd_stdout("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .unwrap_or_else(|| format!("unix:{now}"));

    println!("=== System configuration ===");
    println!("date_utc={date_utc}");
    println!("hostname={}", first_line(&hostname()));
    println!("uname={uname}");
    println!("os={}", os_pretty_name());
    println!("arch={arch}");
    println!("virt={}", first_line(&virt()));
    println!("cpu_model={}", cpu_model());
    println!("cpu_logical={}", logical_cpus());
    if let Some(online) = online_cpu_list() {
        println!("cpu_online={online}");
    }
    println!("mem_total={mem_total}");
    println!("mem_available={mem_avail}");
    println!("loadavg={}", loadavg());
    println!("cgroup_v2={}", cgroup_v2());
    println!("cgroup_cpu_max={cpu_max}");
    println!("cgroup_memory_max={mem_max}");
    println!("docker_server={docker_ver}");
    println!("docker_info={docker_info}");
    println!(
        "harness=sentinel-bench {}",
        env!("CARGO_PKG_VERSION")
    );
    println!("============================");
}
