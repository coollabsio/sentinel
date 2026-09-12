#![forbid(unsafe_code)]

use std::collections::HashSet;

pub const PROTOCOL_MIN: u32 = 1;
pub const PROTOCOL_MAX: u32 = 1;
pub const CAPABILITY_SYSTEM_PING: &str = "system.ping.v1";
pub const CAPABILITY_SYSTEM_INFO: &str = "system.info.v1";
pub const CAPABILITY_CONTAINER_LIST: &str = "container.list.v1";

pub mod control {
    pub mod v1 {
        tonic::include_proto!("coolify.sentinel.control.v1");
    }
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
