#![forbid(unsafe_code)]

use std::borrow::Cow;

/// Represents a single HTTP request event with traffic analytics data.
///
/// Every string field is a [`Cow`], not a plain `&'a str`, and that is
/// load-bearing rather than stylistic. `serde_json` can only fill a borrowed
/// `&str` when the JSON string needs *no* unescaping — the moment a log line
/// contains `&` (Go's `encoding/json`, and therefore Traefik's
/// `logrus.JSONFormatter`, HTML-escapes `&` in every query string by
/// default), `\"` or `\\`, deserializing into `&str` fails for the *whole*
/// struct and the request would be dropped entirely. With `Cow` serde still
/// borrows on the common unescaped fast path and only allocates for the
/// lines that genuinely need decoding.
pub struct RequestEvent<'a> {
    /// Timestamp in milliseconds since UNIX epoch.
    pub ts_ms: i64,
    /// Coolify app UUID (Traefik) or host (Caddy).
    pub app: Cow<'a, str>,
    /// Request host header.
    pub host: Cow<'a, str>,
    /// HTTP method (GET, POST, etc).
    pub method: Cow<'a, str>,
    /// Request path with query string stripped.
    pub path: Cow<'a, str>,
    /// HTTP status code.
    pub status: u16,
    /// Request body size in bytes.
    pub bytes_in: u64,
    /// Response body size in bytes.
    pub bytes_out: u64,
    /// Request duration in milliseconds.
    pub duration_ms: f64,
    /// HTTP protocol version ("HTTP/1.1", "HTTP/2.0", "HTTP/3.0").
    pub protocol: Cow<'a, str>,
    /// Scheme ("http" or "https").
    pub scheme: Cow<'a, str>,
    /// TLS version if applicable (e.g. "1.3"), normalized.
    pub tls_version: Option<Cow<'a, str>>,
    /// Best real client IP (pre-CF precedence: raw connection IP).
    pub client_ip: Option<Cow<'a, str>>,
    /// X-Forwarded-For header raw value.
    pub xff: Option<Cow<'a, str>>,
    /// User-Agent header.
    pub user_agent: Option<Cow<'a, str>>,
    /// Referer header.
    pub referer: Option<Cow<'a, str>>,
    /// Cloudflare CF-Connecting-IP header.
    pub cf_connecting_ip: Option<Cow<'a, str>>,
    /// Cloudflare CF-Country header.
    pub cf_country: Option<Cow<'a, str>>,
    /// Cloudflare CF-Cache-Status header.
    pub cf_cache_status: Option<Cow<'a, str>>,
    /// Cloudflare CF-Verified-Bot header.
    pub cf_verified_bot: Option<Cow<'a, str>>,
}

/// HTTP status code class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    /// 2xx status codes.
    S2xx,
    /// 3xx status codes.
    S3xx,
    /// 4xx status codes.
    S4xx,
    /// 5xx status codes.
    S5xx,
    /// Any other status code (1xx, 6xx+, etc).
    Other,
}

/// Classify an HTTP status code into a StatusClass.
pub fn status_class(status: u16) -> StatusClass {
    match status {
        200..=299 => StatusClass::S2xx,
        300..=399 => StatusClass::S3xx,
        400..=499 => StatusClass::S4xx,
        500..=599 => StatusClass::S5xx,
        _ => StatusClass::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_status() {
        assert_eq!(status_class(204), StatusClass::S2xx);
        assert_eq!(status_class(301), StatusClass::S3xx);
        assert_eq!(status_class(404), StatusClass::S4xx);
        assert_eq!(status_class(503), StatusClass::S5xx);
        assert_eq!(status_class(101), StatusClass::Other);
    }
}
