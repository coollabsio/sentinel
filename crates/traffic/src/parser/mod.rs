#![forbid(unsafe_code)]

//! HTTP access log parser for traffic analytics.

pub mod caddy;
pub mod traefik;

use crate::event::RequestEvent;

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

/// Detect which reverse-proxy produced a given access-log line by inspecting
/// its top-level JSON shape.
///
/// Traefik lines have a top-level `RouterName` or `RequestMethod` key. Caddy
/// lines nest the request under a top-level `request` object containing a
/// `uri` key. Returns `None` when the line is malformed JSON or matches
/// neither known shape.
pub fn detect(line: &[u8]) -> Option<ProxyType> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    let obj = value.as_object()?;

    if obj.contains_key("RouterName") || obj.contains_key("RequestMethod") {
        return Some(ProxyType::Traefik);
    }

    if obj
        .get("request")
        .and_then(|r| r.as_object())
        .is_some_and(|r| r.contains_key("uri"))
    {
        return Some(ProxyType::Caddy);
    }

    None
}

/// Parse a single access-log line into a [`RequestEvent`], dispatching to
/// the parser for `proxy`.
///
/// For [`ProxyType::Auto`], the format is first detected via [`detect`]; if
/// detection fails to recognize the line, `None` is returned rather than
/// guessing.
pub fn parse_line(proxy: ProxyType, line: &[u8]) -> Option<RequestEvent<'_>> {
    match proxy {
        ProxyType::Traefik => traefik::parse(line),
        ProxyType::Caddy => caddy::parse(line),
        ProxyType::Auto => match detect(line)? {
            ProxyType::Traefik => traefik::parse(line),
            ProxyType::Caddy => caddy::parse(line),
            ProxyType::Auto => None,
        },
    }
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
