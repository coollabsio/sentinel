#![forbid(unsafe_code)]

//! Caddy JSON access-log parser.

use std::borrow::Cow;

use serde::Deserialize;

use crate::event::RequestEvent;

use super::strip_query;

/// Raw shape of the `request.headers` object in a Caddy access-log line.
///
/// Caddy represents each header as an array of values; only the first value
/// is used. Only the headers `RequestEvent` needs are declared here — serde's
/// derived `Deserialize` silently ignores any other headers present in the
/// real log line.
///
/// See [`Raw`] for why every string is a `Cow`, not a `&'a str`.
#[derive(Debug, Deserialize)]
struct Headers<'a> {
    #[serde(rename = "User-Agent", borrow, default)]
    user_agent: Option<Vec<Cow<'a, str>>>,
    #[serde(rename = "Referer", borrow, default)]
    referer: Option<Vec<Cow<'a, str>>>,
    #[serde(rename = "X-Forwarded-For", borrow, default)]
    xff: Option<Vec<Cow<'a, str>>>,
    #[serde(rename = "Cf-Connecting-Ip", borrow, default)]
    cf_connecting_ip: Option<Vec<Cow<'a, str>>>,
    #[serde(rename = "Cf-Ipcountry", borrow, default)]
    cf_country: Option<Vec<Cow<'a, str>>>,
    #[serde(rename = "Cf-Cache-Status", borrow, default)]
    cf_cache_status: Option<Vec<Cow<'a, str>>>,
}

/// Raw shape of the `request.tls` object in a Caddy access-log line.
#[derive(Debug, Deserialize)]
struct Tls {
    version: u16,
}

/// Raw shape of the `request` object in a Caddy access-log line.
#[derive(Debug, Deserialize)]
struct Req<'a> {
    #[serde(borrow)]
    method: Cow<'a, str>,
    #[serde(borrow)]
    uri: Cow<'a, str>,
    #[serde(borrow)]
    host: Cow<'a, str>,
    #[serde(borrow)]
    proto: Cow<'a, str>,
    #[serde(borrow, default)]
    remote_ip: Option<Cow<'a, str>>,
    #[serde(default)]
    tls: Option<Tls>,
    headers: Headers<'a>,
}

/// Raw shape of a single Caddy JSON access-log line.
///
/// Only the fields `RequestEvent` needs are declared here; serde's derived
/// `Deserialize` silently ignores any other keys present in the real Caddy
/// log line (e.g. `level`, `logger`, `msg`, `user_id`, `resp_headers`, ...).
///
/// Every string field is `Cow<'a, str>` rather than `&'a str` because
/// `serde_json` cannot produce a borrowed `&str` for a JSON string that needs
/// unescaping — and a `uri` query string, a `Referer` header, or any header
/// value may legitimately contain `\"`, `\\` or a `\uXXXX` escape. With
/// `&'a str` fields such a line fails to deserialize *as a whole* and the
/// request is dropped silently; with `Cow` the common unescaped case still
/// borrows and only the escaped minority allocates.
#[derive(Debug, Deserialize)]
struct Raw<'a> {
    ts: f64,
    status: u16,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    bytes_read: u64,
    duration: f64,
    #[serde(borrow)]
    request: Req<'a>,
}

/// Map a Caddy/TLS numeric protocol version to its human-readable name.
fn tls_version_name(version: u16) -> Option<&'static str> {
    match version {
        769 => Some("1.0"),
        770 => Some("1.1"),
        771 => Some("1.2"),
        772 => Some("1.3"),
        _ => None,
    }
}

/// Parse a single Caddy JSON access-log line into a [`RequestEvent`].
///
/// Returns `None` on any malformed input (invalid JSON or missing required
/// fields) — callers should skip the line and move on rather than treat this
/// as fatal. Caddy has no router-name/UUID concept, so attribution is purely
/// host-based: `app` and `host` both borrow `request.host`.
pub fn parse(line: &[u8]) -> Option<RequestEvent<'_>> {
    let raw: Raw = serde_json::from_slice(line).ok()?;

    let ts_ms = (raw.ts * 1000.0) as i64;
    let duration_ms = raw.duration * 1000.0;

    let path = strip_query(raw.request.uri);

    let scheme = if raw.request.tls.is_some() {
        "https"
    } else {
        "http"
    };

    let tls_version = raw
        .request
        .tls
        .as_ref()
        .and_then(|tls| tls_version_name(tls.version))
        .map(Cow::Borrowed);

    let headers = raw.request.headers;

    Some(RequestEvent {
        ts_ms,
        app: raw.request.host.clone(),
        host: raw.request.host,
        method: raw.request.method,
        path,
        status: raw.status,
        bytes_in: raw.bytes_read,
        bytes_out: raw.size,
        duration_ms,
        protocol: raw.request.proto,
        scheme: Cow::Borrowed(scheme),
        tls_version,
        client_ip: raw.request.remote_ip,
        xff: first_value(headers.xff),
        user_agent: first_value(headers.user_agent),
        referer: first_value(headers.referer),
        cf_connecting_ip: first_value(headers.cf_connecting_ip),
        cf_country: first_value(headers.cf_country),
        cf_cache_status: first_value(headers.cf_cache_status),
        cf_verified_bot: None,
    })
}

/// Takes ownership of a header's first value, if it has one.
///
/// Consumes the `Vec` rather than borrowing from it, so an owned (unescaped)
/// value survives past the end of `parse` instead of being tied to a local.
fn first_value(values: Option<Vec<Cow<'_, str>>>) -> Option<Cow<'_, str>> {
    values?.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::super::{ProxyType, detect};

    #[test]
    fn parses_caddy_line() {
        let line = include_bytes!("../../tests/fixtures/caddy.jsonl")
            .split(|b| *b == b'\n')
            .next()
            .unwrap();
        let ev = super::parse(line).unwrap();
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.host, "app.example.com");
        assert_eq!(ev.app, ev.host); // host-based attribution
        assert_eq!(ev.tls_version.as_deref(), Some("1.3")); // 772
        assert_eq!(ev.scheme, "https");
        assert!(ev.duration_ms > 0.0);
        assert_eq!(ev.path, "/api/status");
        assert_eq!(ev.status, 200);
        assert_eq!(ev.cf_country.as_deref(), Some("DE"));
        assert!((ev.duration_ms - 1.234).abs() < 0.001);
    }

    #[test]
    fn plain_http_line_has_no_tls() {
        let line = include_bytes!("../../tests/fixtures/caddy.jsonl")
            .split(|b| *b == b'\n')
            .nth(1)
            .unwrap();
        let ev = super::parse(line).unwrap();
        assert_eq!(ev.scheme, "http");
        assert!(ev.tls_version.is_none());
        assert_eq!(ev.method, "POST");
        assert_eq!(ev.status, 500);
        assert_eq!(ev.path, "/webhook");
    }

    /// Same class of bug as the Traefik one: a `uri` or header value that
    /// needs unescaping cannot fill a borrowed `&str`, so with `&'a str`
    /// fields the whole line failed to deserialize and the request was
    /// dropped. Caddy does not HTML-escape by default the way Go's
    /// `encoding/json` does for logrus, but a quote or backslash anywhere in
    /// a URI or `Referer` reaches the same failure.
    #[test]
    fn json_escaped_fields_still_parse_and_decode() {
        let line = include_bytes!("../../tests/fixtures/caddy.jsonl")
            .split(|b| *b == b'\n')
            .nth(2)
            .unwrap();

        let ev = super::parse(line).expect("a JSON-escaped Caddy line must still parse");

        assert_eq!(ev.path, "/search");
        assert_eq!(ev.host, "app.example.com");
        assert_eq!(
            ev.referer.as_deref(),
            Some(r#"https://ref.example.com/a?x=1&y=2 "quoted" back\slash"#),
            "escapes must be decoded, not passed through verbatim"
        );
        assert_eq!(ev.status, 200);
    }

    #[test]
    fn detect_distinguishes_proxies() {
        let t = include_bytes!("../../tests/fixtures/traefik.jsonl")
            .split(|b| *b == b'\n')
            .next()
            .unwrap();
        let c = include_bytes!("../../tests/fixtures/caddy.jsonl")
            .split(|b| *b == b'\n')
            .next()
            .unwrap();
        assert!(matches!(detect(t), Some(ProxyType::Traefik)));
        assert!(matches!(detect(c), Some(ProxyType::Caddy)));
    }
}
