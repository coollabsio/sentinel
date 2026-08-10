#![forbid(unsafe_code)]

//! Traefik JSON access-log parser.

use std::borrow::Cow;

use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::event::RequestEvent;

use super::{parse_app_uuid, strip_query};

/// Raw shape of a single Traefik JSON access-log line. Only the fields
/// `RequestEvent` needs are declared; serde ignores the rest (`ClientAddr`,
/// `OriginStatus`, `level`, `time`, ...). Fields are `Cow`, not `&str` — see
/// [`RequestEvent`] for why that is load-bearing for correctness.
#[derive(Debug, Deserialize)]
struct Raw<'a> {
    #[serde(rename = "StartUTC", borrow)]
    start_utc: Cow<'a, str>,
    #[serde(rename = "RequestMethod", borrow)]
    request_method: Cow<'a, str>,
    #[serde(rename = "RequestPath", borrow)]
    request_path: Cow<'a, str>,
    #[serde(rename = "RequestHost", borrow)]
    request_host: Cow<'a, str>,
    #[serde(rename = "DownstreamStatus")]
    downstream_status: u16,
    #[serde(rename = "RequestContentSize", default)]
    request_content_size: u64,
    #[serde(rename = "DownstreamContentSize", default)]
    downstream_content_size: u64,
    #[serde(rename = "Duration")]
    duration: i64,
    #[serde(rename = "RequestProtocol", borrow)]
    request_protocol: Cow<'a, str>,
    #[serde(rename = "RequestScheme", borrow)]
    request_scheme: Cow<'a, str>,
    #[serde(rename = "TLSVersion", borrow, default)]
    tls_version: Option<Cow<'a, str>>,
    #[serde(rename = "ClientHost", borrow, default)]
    client_host: Option<Cow<'a, str>>,
    #[serde(rename = "RouterName", borrow)]
    router_name: Cow<'a, str>,
    #[serde(rename = "request_User-Agent", borrow, default)]
    user_agent: Option<Cow<'a, str>>,
    #[serde(rename = "request_Referer", borrow, default)]
    referer: Option<Cow<'a, str>>,
    #[serde(rename = "request_X-Forwarded-For", borrow, default)]
    xff: Option<Cow<'a, str>>,
    #[serde(rename = "request_Cf-Connecting-Ip", borrow, default)]
    cf_connecting_ip: Option<Cow<'a, str>>,
    #[serde(rename = "request_Cf-Ipcountry", borrow, default)]
    cf_country: Option<Cow<'a, str>>,
    #[serde(rename = "request_Cf-Cache-Status", borrow, default)]
    cf_cache_status: Option<Cow<'a, str>>,
}

/// Parse a single Traefik JSON access-log line into a [`RequestEvent`].
///
/// Returns `None` on any malformed input (invalid JSON, missing required
/// fields, an unparseable `StartUTC` timestamp, or a `RouterName` that does
/// not resolve to a Coolify app UUID, e.g. Traefik's own internal routers
/// like `api@internal`) — callers should skip the line and move on rather
/// than treat this as fatal. This avoids misattributing Traefik's own
/// dashboard/API traffic to a fake "app" bucket.
pub fn parse(line: &[u8]) -> Option<RequestEvent<'_>> {
    let raw: Raw = serde_json::from_slice(line).ok()?;

    let ts = OffsetDateTime::parse(&raw.start_utc, &Rfc3339).ok()?;
    let ts_ms = (ts.unix_timestamp_nanos() / 1_000_000) as i64;

    let path = strip_query(raw.request_path);

    // Keep the UUID borrowed from the source buffer when the router name was
    // borrowable, and only copy the (short) UUID substring when serde had to
    // unescape the router name into an owned `String` that dies with `raw`.
    let app = match raw.router_name {
        Cow::Borrowed(name) => Cow::Borrowed(parse_app_uuid(name)?),
        Cow::Owned(ref name) => Cow::Owned(parse_app_uuid(name)?.to_string()),
    };

    Some(RequestEvent {
        ts_ms,
        app,
        host: raw.request_host,
        method: raw.request_method,
        path,
        status: raw.downstream_status,
        bytes_in: raw.request_content_size,
        bytes_out: raw.downstream_content_size,
        duration_ms: raw.duration as f64 / 1_000_000.0,
        protocol: raw.request_protocol,
        scheme: raw.request_scheme,
        tls_version: raw.tls_version,
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
mod tests;
