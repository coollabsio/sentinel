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
    assert_eq!(
        c.traffic.analytics_file.to_str().unwrap(),
        "./db/analytics.sqlite"
    );
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
