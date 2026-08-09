#![forbid(unsafe_code)]

//! HTTP access log parser for traffic analytics.

pub mod traefik;

/// Which reverse-proxy access-log format to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyType {
    /// Traefik JSON access logs.
    Traefik,
    /// Caddy JSON access logs.
    Caddy,
    /// Auto-detect the format from the log content.
    #[default]
    Auto,
}

/// Extract the Coolify app UUID from a Traefik `RouterName` such as
/// `https-0-jc4wsgs@docker` -> `jc4wsgs`, or `http-12-abc-def@docker` -> `abc-def`.
///
/// Returns `None` when the router name doesn't have the `scheme-index-uuid`
/// shape (e.g. `api@internal`, Traefik's internal API router).
pub fn parse_app_uuid(router_name: &str) -> Option<&str> {
    let before_at = match router_name.split_once('@') {
        Some((prefix, _)) => prefix,
        None => router_name,
    };

    let first_dash = before_at.find('-')?;
    let scheme = &before_at[..first_dash];
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let rest_after_scheme = &before_at[first_dash + 1..];
    let second_dash = rest_after_scheme.find('-')?;
    let uuid = &rest_after_scheme[second_dash + 1..];
    if uuid.is_empty() {
        return None;
    }

    Some(uuid)
}
