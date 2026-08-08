// This crate defaults to forbid; env mutation in the test-only EnvGuard below
// is unsafe as of the 2024 edition, so this one crate uses deny + a narrowly
// scoped #[allow(unsafe_code)] instead (see Global Constraints).
#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
            positive_from_env("COLLECTOR_RETENTION_PERIOD_DAYS", 7)? as u32;

        let port: u16 = match non_empty("PORT") {
            None => 8888,
            Some(v) => v.parse().map_err(|_| ConfigError::InvalidPort)?,
        };
        if port == 0 {
            return Err(ConfigError::InvalidPort);
        }
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));

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
    if authority.is_empty() || authority.contains('@') {
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
        ]);
        let c = Config::load(false).unwrap();
        assert_eq!(c.refresh_rate_seconds, 5);
        assert_eq!(c.push_interval_seconds, 60);
        assert_eq!(c.collector_retention_period_days, 7);
        assert!(!c.collector_enabled);
        assert!(!c.debug);
        assert_eq!(c.bind_addr.port(), 8888);
        assert_eq!(c.metrics_file.to_str().unwrap(), "/app/db/metrics.sqlite");
    }

    #[test]
    fn development_uses_local_db_path() {
        let _l = env_lock().lock().unwrap();
        let _g = EnvGuard::set(&[("TOKEN", "t"), ("PUSH_ENDPOINT", "")]);
        let c = Config::load(true).unwrap();
        // development supplies a default endpoint
        assert_eq!(c.endpoint, "http://localhost:8000");
        assert_eq!(c.metrics_file.to_str().unwrap(), "./db/metrics.sqlite");
    }
}
