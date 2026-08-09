#![forbid(unsafe_code)]

use std::borrow::Cow;

/// Represents a single HTTP request event with traffic analytics data.
pub struct RequestEvent<'a> {
    /// Timestamp in milliseconds since UNIX epoch.
    pub ts_ms: i64,
    /// Coolify app UUID (Traefik) or host (Caddy).
    pub app: Cow<'a, str>,
    /// Request host header.
    pub host: Cow<'a, str>,
    /// HTTP method (GET, POST, etc).
    pub method: &'a str,
    /// Request path with query string stripped.
    pub path: &'a str,
    /// HTTP status code.
    pub status: u16,
    /// Request body size in bytes.
    pub bytes_in: u64,
    /// Response body size in bytes.
    pub bytes_out: u64,
    /// Request duration in milliseconds.
    pub duration_ms: f64,
    /// HTTP protocol version ("HTTP/1.1", "HTTP/2.0", "HTTP/3.0").
    pub protocol: &'a str,
    /// Scheme ("http" or "https").
    pub scheme: &'a str,
    /// TLS version if applicable (e.g. "1.3"), normalized.
    pub tls_version: Option<Cow<'a, str>>,
    /// Best real client IP (pre-CF precedence: raw connection IP).
    pub client_ip: Option<&'a str>,
    /// X-Forwarded-For header raw value.
    pub xff: Option<&'a str>,
    /// User-Agent header.
    pub user_agent: Option<&'a str>,
    /// Referer header.
    pub referer: Option<&'a str>,
    /// Cloudflare CF-Connecting-IP header.
    pub cf_connecting_ip: Option<&'a str>,
    /// Cloudflare CF-Country header.
    pub cf_country: Option<&'a str>,
    /// Cloudflare CF-Cache-Status header.
    pub cf_cache_status: Option<&'a str>,
    /// Cloudflare CF-Verified-Bot header.
    pub cf_verified_bot: Option<&'a str>,
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
