// This crate defaults to forbid; env mutation in the test-only EnvGuard below
// is unsafe as of the 2024 edition, so this one crate uses deny + a narrowly
// scoped #[allow(unsafe_code)] instead (see Global Constraints).
#![deny(unsafe_code)]

use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;

// Mirrors the Go implementation's build-time `-ldflags -X ...Version=...`
// override (used by scripts/coolify-dev.sh and the Dockerfile's ARG VERSION
// to tag dev builds as e.g. "1.0.0-dev+9b1cd1a.dirty", distinguishing them
// from release builds in logs and /api/version). SENTINEL_BUILD_VERSION is
// set via the Dockerfile's `ENV SENTINEL_BUILD_VERSION=$VERSION` in the
// builder stage, so it's visible to option_env! at compile time; unset, this
// falls back to the crate's own Cargo.toml version, matching a plain
// `cargo build`.
pub const VERSION: &str = match option_env!("SENTINEL_BUILD_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("TOKEN environment variable is required")]
    MissingToken,
    #[error("PUSH_ENDPOINT environment variable is required")]
    MissingEndpoint,
    #[error("PUSH_ENDPOINT must be a valid HTTP or HTTPS URL")]
    InvalidEndpoint,
    #[error("PORT must be an integer between 1 and 65535")]
    InvalidPort,
    #[error("{0} must be a positive integer")]
    NotPositive(&'static str),
    #[error("invalid {0}: must be true or false")]
    InvalidBool(&'static str),
}

/// Traffic-analytics subsystem configuration (spec §5). Inert unless
/// `enabled` (TRAFFIC_ENABLED) is set and the binary is built with the
/// `traffic` feature. All fields have safe defaults so the zero-config path
/// is opt-out-clean.
#[derive(Debug, Clone)]
pub struct TrafficSettings {
    pub enabled: bool,
    pub access_log_path: PathBuf,
    pub proxy_type: String,
    pub topn: u32,
    pub sample_threshold: u32,
    pub retention_1m_hours: u32,
    pub retention_1h_days: u32,
    pub retention_1d_days: u32,
    pub analytics_file: PathBuf,
    pub geoip_enabled: bool,
    /// Explicit source URL override. When `None`, the default resolution chain
    /// (mirror → DB-IP fallback, or MaxMind if a key is set) applies. See §6.
    pub geoip_db_url: Option<String>,
    pub geoip_maxmind_key: Option<String>,
    pub geoip_maxmind_edition: String,
    pub geoip_refresh_days: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: String,
    pub debug: bool,
    pub refresh_rate_seconds: u64,
    pub push_enabled: bool,
    pub push_interval_seconds: u64,
    pub push_path: String,
    pub push_url: String,
    pub token: String,
    pub endpoint: String,
    pub metrics_file: PathBuf,
    pub collector_enabled: bool,
    pub collector_retention_period_days: u32,
    pub bind_addr: SocketAddr,
    pub storage_enabled: bool,
    pub storage_refresh_rate_seconds: u64,
    pub storage_volumes_enabled: bool,
    pub storage_volumes_refresh_rate_seconds: u64,
    pub host_mount_prefix: String,
    pub traffic: TrafficSettings,
}

impl Config {
    pub fn load(development: bool) -> Result<Self, ConfigError> {
        let metrics_file = if development {
            PathBuf::from("./db/metrics.sqlite")
        } else {
            PathBuf::from("/app/db/metrics.sqlite")
        };

        let debug = bool_from_env("DEBUG", false)?;
        let collector_enabled = bool_from_env("COLLECTOR_ENABLED", false)?;
        let push_interval_seconds = positive_from_env("PUSH_INTERVAL_SECONDS", 60)?;
        let refresh_rate_seconds = positive_from_env("COLLECTOR_REFRESH_RATE_SECONDS", 5)?;
        let collector_retention_period_days =
            u32::try_from(positive_from_env("COLLECTOR_RETENTION_PERIOD_DAYS", 7)?)
                .map_err(|_| ConfigError::NotPositive("COLLECTOR_RETENTION_PERIOD_DAYS"))?;

        let storage_enabled = bool_from_env("STORAGE_ENABLED", true)?;
        let storage_refresh_rate_seconds = positive_from_env("STORAGE_REFRESH_RATE_SECONDS", 300)?;
        let storage_volumes_enabled = bool_from_env("STORAGE_VOLUMES_ENABLED", true)?;
        let storage_volumes_refresh_rate_seconds =
            positive_from_env("STORAGE_VOLUMES_REFRESH_RATE_SECONDS", 900)?;
        let host_mount_prefix = non_empty("HOST_MOUNT_PREFIX").unwrap_or_default();

        let analytics_file = if development {
            PathBuf::from("./db/analytics.sqlite")
        } else {
            PathBuf::from("/app/db/analytics.sqlite")
        };
        let traffic = TrafficSettings {
            enabled: bool_from_env("TRAFFIC_ENABLED", false)?,
            access_log_path: PathBuf::from(
                non_empty("TRAFFIC_ACCESS_LOG_PATH")
                    .unwrap_or_else(|| "/data/coolify/proxy/access.log".to_string()),
            ),
            proxy_type: non_empty("TRAFFIC_PROXY_TYPE").unwrap_or_else(|| "auto".to_string()),
            topn: u32_from_env("TRAFFIC_TOPN", 50)?,
            // Sampling is off by default; 0 is a valid "disabled" sentinel, so it
            // uses a non-positive-tolerant parse rather than positive_from_env.
            sample_threshold: u32_nonneg_from_env("TRAFFIC_SAMPLE_THRESHOLD", 0)?,
            retention_1m_hours: u32_from_env("TRAFFIC_RETENTION_1M_HOURS", 48)?,
            retention_1h_days: u32_from_env("TRAFFIC_RETENTION_1H_DAYS", 30)?,
            retention_1d_days: u32_from_env("TRAFFIC_RETENTION_1D_DAYS", 395)?,
            analytics_file,
            geoip_enabled: bool_from_env("GEOIP_ENABLED", true)?,
            geoip_db_url: non_empty("GEOIP_DB_URL"),
            geoip_maxmind_key: non_empty("GEOIP_MAXMIND_LICENSE_KEY"),
            geoip_maxmind_edition: non_empty("GEOIP_MAXMIND_EDITION")
                .unwrap_or_else(|| "GeoLite2-Country".to_string()),
            geoip_refresh_days: u32_from_env("GEOIP_REFRESH_DAYS", 30)?,
        };

        let port: u16 = match non_empty("PORT") {
            None => 8888,
            Some(v) => v.parse().map_err(|_| ConfigError::InvalidPort)?,
        };
        if port == 0 {
            return Err(ConfigError::InvalidPort);
        }
        // Bind the unspecified IPv6 address so the listener is dual-stack on
        // Linux (net.ipv6.bindv6only=0 by default), matching Go's
        // net.Listen("tcp", ":PORT"), which accepts both IPv4 and IPv6. On
        // hosts with IPv6 disabled this bind fails, and main.rs falls back to
        // 0.0.0.0 — again mirroring Go's transparent IPv4 fallback.
        let bind_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));

        let token = non_empty("TOKEN").ok_or(ConfigError::MissingToken)?;

        let mut endpoint = non_empty("PUSH_ENDPOINT")
            .map(|e| e.trim_end_matches('/').to_string())
            .unwrap_or_default();
        if endpoint.is_empty() && development {
            endpoint = "http://localhost:8000".to_string();
        }
        if endpoint.is_empty() {
            return Err(ConfigError::MissingEndpoint);
        }
        validate_endpoint(&endpoint)?;

        let push_path = "/api/v1/sentinel/push".to_string();
        let push_url = format!("{endpoint}{push_path}");

        Ok(Config {
            version: VERSION.to_string(),
            debug,
            refresh_rate_seconds,
            push_enabled: true,
            push_interval_seconds,
            push_path,
            push_url,
            token,
            endpoint,
            metrics_file,
            collector_enabled,
            collector_retention_period_days,
            bind_addr,
            storage_enabled,
            storage_refresh_rate_seconds,
            storage_volumes_enabled,
            storage_volumes_refresh_rate_seconds,
            host_mount_prefix,
            traffic,
        })
    }

    /// Minimal valid config for tests in downstream crates.
    pub fn load_for_test() -> Self {
        Config {
            version: VERSION.to_string(),
            debug: false,
            refresh_rate_seconds: 5,
            push_enabled: false,
            push_interval_seconds: 60,
            push_path: "/api/v1/sentinel/push".to_string(),
            push_url: "http://localhost:8000/api/v1/sentinel/push".to_string(),
            token: "test-token".to_string(),
            endpoint: "http://localhost:8000".to_string(),
            metrics_file: PathBuf::from(":memory:"),
            collector_enabled: false,
            collector_retention_period_days: 7,
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8888)),
            storage_enabled: false,
            storage_refresh_rate_seconds: 300,
            storage_volumes_enabled: false,
            storage_volumes_refresh_rate_seconds: 900,
            host_mount_prefix: String::new(),
            traffic: TrafficSettings {
                enabled: false,
                access_log_path: PathBuf::from("/data/coolify/proxy/access.log"),
                proxy_type: "auto".to_string(),
                topn: 50,
                sample_threshold: 0,
                retention_1m_hours: 48,
                retention_1h_days: 30,
                retention_1d_days: 395,
                analytics_file: PathBuf::from(":memory:"),
                geoip_enabled: true,
                geoip_db_url: None,
                geoip_maxmind_key: None,
                geoip_maxmind_edition: "GeoLite2-Country".to_string(),
                geoip_refresh_days: 30,
            },
        }
    }
}

fn non_empty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn bool_from_env(key: &'static str, fallback: bool) -> Result<bool, ConfigError> {
    match non_empty(key) {
        None => Ok(fallback),
        // Go's strconv.ParseBool accepts these spellings.
        Some(v) => match v.as_str() {
            "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
            "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
            _ => Err(ConfigError::InvalidBool(key)),
        },
    }
}

fn positive_from_env(key: &'static str, fallback: u64) -> Result<u64, ConfigError> {
    match non_empty(key) {
        None => Ok(fallback),
        Some(v) => match v.parse::<i64>() {
            Ok(n) if n > 0 => Ok(n as u64),
            _ => Err(ConfigError::NotPositive(key)),
        },
    }
}

/// A strictly-positive `u32` env var (rejects 0, negatives, and overflow).
fn u32_from_env(key: &'static str, fallback: u32) -> Result<u32, ConfigError> {
    let n = positive_from_env(key, fallback as u64)?;
    u32::try_from(n).map_err(|_| ConfigError::NotPositive(key))
}

/// A non-negative `u32` env var: 0 is accepted (it is a valid "disabled"
/// sentinel, e.g. TRAFFIC_SAMPLE_THRESHOLD=0 means "never sample").
fn u32_nonneg_from_env(key: &'static str, fallback: u32) -> Result<u32, ConfigError> {
    match non_empty(key) {
        None => Ok(fallback),
        Some(v) => match v.parse::<i64>() {
            Ok(n) if n >= 0 => u32::try_from(n).map_err(|_| ConfigError::NotPositive(key)),
            _ => Err(ConfigError::NotPositive(key)),
        },
    }
}

// Mirrors validateEndpoint in pkg/config/config.go: scheme must be http/https,
// host must be present, and userinfo/query/fragment are all rejected.
//
// Go's check is `parsed.User != nil`, which only looks at the authority
// component (before the host) — a literal '@' later in the path, like
// "https://example.com/path/@handle", is valid there. Scanning the whole
// remainder for '@' would reject that URL incorrectly, so the userinfo
// check is scoped to the authority: everything up to the first '/', '?',
// or '#'. Query and fragment are rejected anywhere after the authority,
// since neither can legitimately appear in a bare path segment.
fn validate_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    let rest = match endpoint.split_once("://") {
        Some(("http", rest)) | Some(("https", rest)) => rest,
        _ => return Err(ConfigError::InvalidEndpoint),
    };
    if rest.is_empty() {
        return Err(ConfigError::InvalidEndpoint);
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.starts_with(':') {
        return Err(ConfigError::InvalidEndpoint);
    }
    let remainder = &rest[authority_end..];
    if remainder.contains('?') || remainder.contains('#') {
        return Err(ConfigError::InvalidEndpoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env access is process-global, so these tests must not run concurrently.
    // Each locks the same mutex and restores the env afterwards.
    use std::sync::{Mutex, OnceLock};
    fn env_lock() -> &'static Mutex<()> {
        static L: OnceLock<Mutex<()>> = OnceLock::new();
        L.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard(Vec<(String, Option<String>)>);
    impl EnvGuard {
        #[allow(unsafe_code)]
        fn set(vars: &[(&str, &str)]) -> Self {
            let saved = vars
                .iter()
                .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
                .collect();
            for (k, v) in vars {
                // SAFETY: test-only process env mutation, serialized by env_lock()
                // above so no other thread reads/writes these vars concurrently.
                unsafe { std::env::set_var(k, v) };
            }
            Self(saved)
        }
    }
    impl Drop for EnvGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            for (k, v) in &self.0 {
                // SAFETY: see EnvGuard::set — same serialization guarantee.
                match v {
                    Some(v) => unsafe { std::env::set_var(k, v) },
                    None => unsafe { std::env::remove_var(k) },
                }
            }
        }
    }

    #[test]
    fn requires_token() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", ""), ("PUSH_ENDPOINT", "https://example.com")]);
        assert!(matches!(
            Config::load(false),
            Err(ConfigError::MissingToken)
        ));
    }

    #[test]
    fn requires_push_endpoint() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", "")]);
        assert!(matches!(
            Config::load(false),
            Err(ConfigError::MissingEndpoint)
        ));
    }

    #[test]
    fn builds_push_url_and_trims_trailing_slash() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", "https://example.com///")]);
        let c = Config::load(false).unwrap();
        assert_eq!(c.endpoint, "https://example.com");
        assert_eq!(c.push_url, "https://example.com/api/v1/sentinel/push");
    }

    #[test]
    fn rejects_non_http_endpoint() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", "ftp://example.com")]);
        assert!(matches!(
            Config::load(false),
            Err(ConfigError::InvalidEndpoint)
        ));
    }

    #[test]
    fn rejects_endpoint_with_userinfo_query_or_fragment() {
        for bad in [
            "https://u:p@example.com",
            "https://example.com?a=1",
            "https://example.com#f",
            "https://u:p@example.com/some/path",
        ] {
            let _l = env_lock().lock().unwrap();
            let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", bad)]);
            assert!(
                matches!(Config::load(false), Err(ConfigError::InvalidEndpoint)),
                "expected {bad} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_at_sign_in_path_query_or_fragment_free_urls() {
        // '@' here is not userinfo (it's not before the host), so this must
        // NOT be rejected. Matches Go's `parsed.User != nil`, which only
        // looks at the authority component.
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[
            ("TOKEN", "t"),
            ("PUSH_ENDPOINT", "https://example.com/path/@handle"),
        ]);
        assert!(Config::load(false).is_ok());
    }

    #[test]
    fn rejects_zero_and_negative_intervals() {
        for var in [
            "PUSH_INTERVAL_SECONDS",
            "COLLECTOR_REFRESH_RATE_SECONDS",
            "COLLECTOR_RETENTION_PERIOD_DAYS",
            "STORAGE_REFRESH_RATE_SECONDS",
            "STORAGE_VOLUMES_REFRESH_RATE_SECONDS",
        ] {
            let _l = env_lock().lock().unwrap();
            let _g = EnvGuard::set(&[
                ("TOKEN", "t"),
                ("PUSH_ENDPOINT", "https://example.com"),
                (var, "0"),
            ]);
            assert!(matches!(
                Config::load(false),
                Err(ConfigError::NotPositive(_))
            ));
        }
    }

    #[test]
    fn rejects_retention_period_above_u32_max() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[
            ("TOKEN", "t"),
            ("PUSH_ENDPOINT", "https://example.com"),
            ("COLLECTOR_RETENTION_PERIOD_DAYS", "4294967296"),
        ]);
        assert!(matches!(
            Config::load(false),
            Err(ConfigError::NotPositive("COLLECTOR_RETENTION_PERIOD_DAYS"))
        ));
    }

    #[test]
    fn rejects_endpoint_without_a_host() {
        for bad in ["http://:443", "https://:8443/path"] {
            let _l = env_lock().lock().unwrap();
            let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", bad)]);
            assert!(matches!(
                Config::load(false),
                Err(ConfigError::InvalidEndpoint)
            ));
        }
    }

    #[test]
    fn rejects_out_of_range_port() {
        for bad in ["0", "65536", "abc"] {
            let _l = env_lock().lock().unwrap();
            let _g = EnvGuard::set(&[
                ("TOKEN", "t"),
                ("PUSH_ENDPOINT", "https://example.com"),
                ("PORT", bad),
            ]);
            assert!(matches!(Config::load(false), Err(ConfigError::InvalidPort)));
        }
    }

    #[test]
    fn defaults_match_go_implementation() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[
            ("TOKEN", "t"),
            ("PUSH_ENDPOINT", "https://example.com"),
            ("PORT", ""),
            ("DEBUG", ""),
            ("COLLECTOR_ENABLED", ""),
            ("PUSH_INTERVAL_SECONDS", ""),
            ("COLLECTOR_REFRESH_RATE_SECONDS", ""),
            ("COLLECTOR_RETENTION_PERIOD_DAYS", ""),
            ("STORAGE_ENABLED", ""),
            ("STORAGE_REFRESH_RATE_SECONDS", ""),
            ("STORAGE_VOLUMES_ENABLED", ""),
            ("STORAGE_VOLUMES_REFRESH_RATE_SECONDS", ""),
            ("HOST_MOUNT_PREFIX", ""),
        ]);
        let c = Config::load(false).unwrap();
        assert_eq!(c.refresh_rate_seconds, 5);
        assert_eq!(c.push_interval_seconds, 60);
        assert_eq!(c.collector_retention_period_days, 7);
        assert!(!c.collector_enabled);
        assert!(!c.debug);
        assert_eq!(c.bind_addr.port(), 8888);
        assert_eq!(c.metrics_file.to_str().unwrap(), "/app/db/metrics.sqlite");
        // Storage collection defaults on; the expensive volume walk too, but is
        // inert until host paths are mounted (see HOST_MOUNT_PREFIX).
        assert!(c.storage_enabled);
        assert_eq!(c.storage_refresh_rate_seconds, 300);
        assert!(c.storage_volumes_enabled);
        assert_eq!(c.storage_volumes_refresh_rate_seconds, 900);
        assert_eq!(c.host_mount_prefix, "");
    }

    #[test]
    fn development_uses_local_db_path() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", "")]);
        let c = Config::load(true).unwrap();
        // development supplies a default endpoint
        assert_eq!(c.endpoint, "http://localhost:8000");
        assert_eq!(c.metrics_file.to_str().unwrap(), "./db/metrics.sqlite");
        // analytics DB mirrors the metrics_file dev/prod split
        assert_eq!(c.traffic.analytics_file.to_str().unwrap(), "./db/analytics.sqlite");
    }

    #[test]
    fn traffic_defaults() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[
            ("TOKEN", "t"),
            ("PUSH_ENDPOINT", "https://example.com"),
            ("TRAFFIC_ENABLED", ""),
            ("TRAFFIC_PROXY_TYPE", ""),
            ("TRAFFIC_TOPN", ""),
            ("TRAFFIC_SAMPLE_THRESHOLD", ""),
            ("GEOIP_ENABLED", ""),
            ("GEOIP_DB_URL", ""),
            ("GEOIP_REFRESH_DAYS", ""),
            ("GEOIP_MAXMIND_LICENSE_KEY", ""),
            ("GEOIP_MAXMIND_EDITION", ""),
        ]);
        let c = Config::load(false).unwrap();
        assert!(!c.traffic.enabled);
        assert_eq!(c.traffic.proxy_type, "auto");
        assert_eq!(c.traffic.topn, 50);
        assert_eq!(c.traffic.sample_threshold, 0);
        assert_eq!(c.traffic.retention_1m_hours, 48);
        assert_eq!(c.traffic.retention_1h_days, 30);
        assert_eq!(c.traffic.retention_1d_days, 395);
        assert_eq!(c.traffic.geoip_refresh_days, 30);
        assert!(c.traffic.geoip_enabled);
        assert!(c.traffic.geoip_db_url.is_none());
        assert!(c.traffic.geoip_maxmind_key.is_none());
        assert_eq!(c.traffic.geoip_maxmind_edition, "GeoLite2-Country");
        assert_eq!(
            c.traffic.analytics_file.to_str().unwrap(),
            "/app/db/analytics.sqlite"
        );
        assert_eq!(
            c.traffic.access_log_path.to_str().unwrap(),
            "/data/coolify/proxy/access.log"
        );
    }

    #[test]
    fn traffic_reads_env() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[
            ("TOKEN", "t"),
            ("PUSH_ENDPOINT", "https://example.com"),
            ("TRAFFIC_ENABLED", "true"),
            ("TRAFFIC_TOPN", "200"),
            ("TRAFFIC_SAMPLE_THRESHOLD", "1000"),
            ("GEOIP_MAXMIND_LICENSE_KEY", "abc123"),
            ("GEOIP_DB_URL", "https://cdn.example/geo.mmdb.gz"),
            ("GEOIP_REFRESH_DAYS", "3"),
        ]);
        let c = Config::load(false).unwrap();
        assert!(c.traffic.enabled);
        assert_eq!(c.traffic.topn, 200);
        assert_eq!(c.traffic.sample_threshold, 1000);
        assert_eq!(c.traffic.geoip_maxmind_key.as_deref(), Some("abc123"));
        assert_eq!(
            c.traffic.geoip_db_url.as_deref(),
            Some("https://cdn.example/geo.mmdb.gz")
        );
        assert_eq!(c.traffic.geoip_refresh_days, 3);
    }

    #[test]
    fn traffic_rejects_zero_topn_and_retention() {
        for var in [
            "TRAFFIC_TOPN",
            "TRAFFIC_RETENTION_1M_HOURS",
            "TRAFFIC_RETENTION_1H_DAYS",
            "TRAFFIC_RETENTION_1D_DAYS",
            "GEOIP_REFRESH_DAYS",
        ] {
            let _l = env_lock().lock().unwrap();
            let _g = EnvGuard::set(&[
                ("TOKEN", "t"),
                ("PUSH_ENDPOINT", "https://example.com"),
                (var, "0"),
            ]);
            assert!(
                matches!(Config::load(false), Err(ConfigError::NotPositive(_))),
                "expected {var}=0 to be rejected"
            );
        }
    }
}
