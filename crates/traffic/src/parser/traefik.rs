#![forbid(unsafe_code)]

//! Traefik JSON access-log parser.

use std::borrow::Cow;

use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::event::RequestEvent;

use super::parse_app_uuid;

/// Raw shape of a single Traefik JSON access-log line.
///
/// Only the fields `RequestEvent` needs are declared here; serde's derived
/// `Deserialize` silently ignores any other keys present in the real
/// Traefik log line (e.g. `ClientAddr`, `OriginStatus`, `ServiceName`,
/// `entryPointName`, `level`, `msg`, `time`, ...).
#[derive(Debug, Deserialize)]
struct Raw<'a> {
    #[serde(rename = "StartUTC", borrow)]
    start_utc: &'a str,
    #[serde(rename = "RequestMethod", borrow)]
    request_method: &'a str,
    #[serde(rename = "RequestPath", borrow)]
    request_path: &'a str,
    #[serde(rename = "RequestHost", borrow)]
    request_host: &'a str,
    #[serde(rename = "DownstreamStatus")]
    downstream_status: u16,
    #[serde(rename = "RequestContentSize", default)]
    request_content_size: u64,
    #[serde(rename = "DownstreamContentSize", default)]
    downstream_content_size: u64,
    #[serde(rename = "Duration")]
    duration: i64,
    #[serde(rename = "RequestProtocol", borrow)]
    request_protocol: &'a str,
    #[serde(rename = "RequestScheme", borrow)]
    request_scheme: &'a str,
    #[serde(rename = "TLSVersion", borrow, default)]
    tls_version: Option<&'a str>,
    #[serde(rename = "ClientHost", borrow, default)]
    client_host: Option<&'a str>,
    #[serde(rename = "RouterName", borrow)]
    router_name: &'a str,
    #[serde(rename = "request_User-Agent", borrow, default)]
    user_agent: Option<&'a str>,
    #[serde(rename = "request_Referer", borrow, default)]
    referer: Option<&'a str>,
    #[serde(rename = "request_X-Forwarded-For", borrow, default)]
    xff: Option<&'a str>,
    #[serde(rename = "request_Cf-Connecting-Ip", borrow, default)]
    cf_connecting_ip: Option<&'a str>,
    #[serde(rename = "request_Cf-Ipcountry", borrow, default)]
    cf_country: Option<&'a str>,
    #[serde(rename = "request_Cf-Cache-Status", borrow, default)]
    cf_cache_status: Option<&'a str>,
}

/// Parse a single Traefik JSON access-log line into a [`RequestEvent`].
///
/// Returns `None` on any malformed input (invalid JSON, missing required
/// fields, or an unparseable `StartUTC` timestamp) — callers should skip
/// the line and move on rather than treat this as fatal.
pub fn parse(line: &[u8]) -> Option<RequestEvent<'_>> {
    let raw: Raw = serde_json::from_slice(line).ok()?;

    let ts = OffsetDateTime::parse(raw.start_utc, &Rfc3339).ok()?;
    let ts_ms = (ts.unix_timestamp_nanos() / 1_000_000) as i64;

    let path = raw
        .request_path
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(raw.request_path);

    let app = parse_app_uuid(raw.router_name).unwrap_or(raw.router_name);

    Some(RequestEvent {
        ts_ms,
        app: Cow::Borrowed(app),
        host: Cow::Borrowed(raw.request_host),
        method: raw.request_method,
        path,
        status: raw.downstream_status,
        bytes_in: raw.request_content_size,
        bytes_out: raw.downstream_content_size,
        duration_ms: raw.duration as f64 / 1_000_000.0,
        protocol: raw.request_protocol,
        scheme: raw.request_scheme,
        tls_version: raw.tls_version.map(Cow::Borrowed),
        client_ip: raw.client_host,
        xff: raw.xff,
        user_agent: raw.user_agent,
        referer: raw.referer,
        cf_connecting_ip: raw.cf_connecting_ip,
        cf_country: raw.cf_country,
        cf_cache_status: raw.cf_cache_status,
        cf_verified_bot: None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_traefik_line() {
        let line = include_bytes!("../../tests/fixtures/traefik.jsonl")
            .split(|b| *b == b'\n')
            .next()
            .unwrap();
        let ev = super::parse(line).expect("parse");
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.status, 200);
        assert_eq!(ev.app, "jc4wsgs"); // stripped from https-0-jc4wsgs@docker
        assert!((ev.duration_ms - 12.5).abs() < 0.01); // 12_500_000 ns
        assert_eq!(ev.cf_country, Some("US"));
    }

    #[test]
    fn parse_app_uuid_strips_scheme_index_provider() {
        assert_eq!(
            super::super::parse_app_uuid("https-0-jc4wsgs@docker"),
            Some("jc4wsgs")
        );
        assert_eq!(
            super::super::parse_app_uuid("http-12-abc-def@docker"),
            Some("abc-def")
        );
        assert_eq!(super::super::parse_app_uuid("api@internal"), None); // not an app router
    }

    #[test]
    fn strips_query_from_path() {
        let line = include_bytes!("../../tests/fixtures/traefik.jsonl")
            .split(|b| *b == b'\n')
            .nth(1)
            .unwrap();
        let ev = super::parse(line).expect("parse");
        assert_eq!(ev.path, "/x");
        assert_eq!(ev.status, 404);
        assert_eq!(ev.cf_country, None);
    }

    #[test]
    fn malformed_line_returns_none() {
        assert!(super::parse(b"not json").is_none());
    }
}
