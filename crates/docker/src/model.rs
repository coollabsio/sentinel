use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ContainerSummary {
    pub id: String,
    pub names: Vec<String>,
    pub image: String,
    pub state: String,
    pub labels: HashMap<String, String>,
}

impl ContainerSummary {
    /// Name resolution ported from the Go collector: prefer the `coolify.name`
    /// label, then the first Docker name with its leading '/' stripped, then a
    /// 12-character truncation of the container id.
    pub fn display_name(&self) -> String {
        if let Some(n) = self.labels.get("coolify.name")
            && !n.is_empty()
        {
            return n.clone();
        }
        if let Some(first) = self.names.first()
            && !first.is_empty()
        {
            return first.trim_start_matches('/').to_string();
        }
        self.id.chars().take(12).collect()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ContainerStats {
    pub cpu_total: u64,
    pub pre_cpu_total: u64,
    pub system_usage: u64,
    pub pre_system_usage: u64,
    pub online_cpus: u32,
    /// Length of `cpu_stats.cpu_usage.percpu_usage`. Go's calculateCPUPercent
    /// falls back to this when `online_cpus` is 0 (cgroup v1 hosts and some
    /// Docker Engine builds don't populate `online_cpus`) — without this
    /// fallback, cpu_percent would silently report 0% on those hosts.
    pub percpu_usage_len: u32,
    pub mem_usage: u64,
    pub mem_limit: u64,
    pub inactive_file: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> ContainerSummary {
        ContainerSummary {
            id: "abcdef0123456789".into(),
            ..Default::default()
        }
    }

    #[test]
    fn prefers_coolify_name_label() {
        let mut c = summary();
        c.names = vec!["/docker-name".into()];
        c.labels.insert("coolify.name".into(), "my-app".into());
        assert_eq!(c.display_name(), "my-app");
    }

    #[test]
    fn falls_back_to_docker_name_without_leading_slash() {
        let mut c = summary();
        c.names = vec!["/docker-name".into()];
        assert_eq!(c.display_name(), "docker-name");
    }

    #[test]
    fn falls_back_to_truncated_id() {
        assert_eq!(summary().display_name(), "abcdef012345");
    }

    #[test]
    fn ignores_empty_label_and_empty_name() {
        let mut c = summary();
        c.labels.insert("coolify.name".into(), String::new());
        c.names = vec![String::new()];
        assert_eq!(c.display_name(), "abcdef012345");
    }
}
