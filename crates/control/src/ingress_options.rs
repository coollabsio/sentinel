//! The proxy options of an ingress route (`ingress.route_options.v1`,
//! decision 0031 of Coolify): basic auth, an IP allow list, request and
//! response headers, and compression. Each option becomes a fixed Caddy
//! handler. A value is never inserted as Caddyfile or JSON text: it is a JSON
//! string in a fixed place, and a header value cannot hold a placeholder.

use std::net::IpAddr;

use sentinel_protocol::control::v1::{IngressHeader, IngressRoute};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_ALLOWED_IPS: usize = 32;
const MAX_HEADERS: usize = 16;
const MAX_HEADER_NAME: usize = 64;
const MAX_HEADER_VALUE: usize = 1024;
const MAX_USERNAME: usize = 64;
/// Connection, framing, proxy, and forwarding headers. Caddy or the proxy
/// sets them, and a fixed value would break or spoof a request.
const FORBIDDEN_HEADERS: [&str; 14] = [
    "host",
    "connection",
    "upgrade",
    "keep-alive",
    "transfer-encoding",
    "content-length",
    "content-encoding",
    "te",
    "trailer",
    "forwarded",
    "via",
    "x-real-ip",
    "alt-svc",
    "http2-settings",
];
const FORBIDDEN_HEADER_PREFIXES: [&str; 2] = ["proxy-", "x-forwarded-"];

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Header {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// The options of one route, as Sentinel stores them in Corrosion. An unknown
/// field fails the parse, so a route is never served without an option that
/// a newer Sentinel wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteOptions {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) basic_auth_username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) basic_auth_password_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) request_headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) response_headers: Vec<Header>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) compress: bool,
}

fn headers(list: &[IngressHeader]) -> Vec<Header> {
    list.iter()
        .map(|header| Header {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect()
}

impl RouteOptions {
    pub(crate) fn of(route: &IngressRoute) -> Self {
        Self {
            basic_auth_username: route.basic_auth_username.clone(),
            basic_auth_password_hash: route.basic_auth_password_hash.clone(),
            allowed_ips: route.allowed_ips.clone(),
            request_headers: headers(&route.request_headers),
            response_headers: headers(&route.response_headers),
            compress: route.compress,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The stored form: empty without options, else canonical JSON.
    pub(crate) fn stored(&self) -> String {
        if self.is_empty() {
            String::new()
        } else {
            serde_json::to_string(self).unwrap_or_default()
        }
    }

    /// Parses and validates a stored value again, so a changed row in
    /// Corrosion cannot render unchecked text.
    pub(crate) fn parse_stored(value: &str) -> Result<Self, String> {
        if value.is_empty() {
            return Ok(Self::default());
        }
        let options = serde_json::from_str::<Self>(value)
            .map_err(|_| "The stored route options are invalid.".to_string())?;
        if options.is_empty() {
            return Err("The stored route options are invalid.".into());
        }
        options.validate()?;
        Ok(options)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        match (
            self.basic_auth_username.is_empty(),
            self.basic_auth_password_hash.is_empty(),
        ) {
            (true, true) => {}
            (false, false) => {
                if !valid_username(&self.basic_auth_username) {
                    return Err("The basic auth username of an ingress route is invalid.".into());
                }
                if !valid_bcrypt_hash(&self.basic_auth_password_hash) {
                    return Err(
                        "The basic auth password of an ingress route must be a bcrypt hash with a cost of 10 to 12."
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "Basic auth of an ingress route needs a username and a password hash.".into(),
                );
            }
        }
        if self.allowed_ips.len() > MAX_ALLOWED_IPS {
            return Err(format!(
                "An ingress route allows at most {MAX_ALLOWED_IPS} IP addresses or ranges."
            ));
        }
        let mut ranges = std::collections::HashSet::new();
        for range in &self.allowed_ips {
            if !valid_ip_range(range) {
                return Err(format!(
                    "{range} is not an IP address or a CIDR range without host bits."
                ));
            }
            if !ranges.insert(range) {
                return Err(format!("{range} is in the IP allow list more than once."));
            }
        }
        for (list, label) in [
            (&self.request_headers, "request"),
            (&self.response_headers, "response"),
        ] {
            validate_headers(list, label)?;
        }
        Ok(())
    }

    /// The Caddy handlers before the proxy, in the order of decision 0031:
    /// IP allow list, basic auth, then the headers. `noindex` is a response
    /// header that comes before the headers of the user.
    pub(crate) fn handlers(&self, noindex: bool) -> Vec<Value> {
        let mut handlers = Vec::new();
        if !self.allowed_ips.is_empty() {
            handlers.push(json!({
                "handler": "subroute",
                "routes": [{
                    "match": [{"not": [{"remote_ip": {"ranges": self.allowed_ips}}]}],
                    "handle": [super::ingress::static_response(403, "Forbidden\n")],
                }],
            }));
        }
        if !self.basic_auth_username.is_empty() {
            handlers.push(json!({
                "handler": "authentication",
                "providers": {"http_basic": {
                    "accounts": [{
                        "username": self.basic_auth_username,
                        "password": self.basic_auth_password_hash,
                    }],
                    "hash": {"algorithm": "bcrypt"},
                    "hash_cache": {},
                    "realm": "restricted",
                }},
            }));
        }
        if noindex {
            handlers.push(json!({
                "handler": "headers",
                "response": {"set": {"X-Robots-Tag": ["noindex, nofollow"]}},
            }));
        }
        if !self.request_headers.is_empty() || !self.response_headers.is_empty() {
            let set = |list: &[Header]| {
                list.iter()
                    .map(|header| (header.name.clone(), json!([header.value])))
                    .collect::<serde_json::Map<_, _>>()
            };
            let mut handler = json!({"handler": "headers"});
            if !self.request_headers.is_empty() {
                handler["request"] = json!({"set": set(&self.request_headers)});
            }
            if !self.response_headers.is_empty() {
                // Deferred, so a header of the workload does not win.
                handler["response"] = json!({"set": set(&self.response_headers), "deferred": true});
            }
            handlers.push(handler);
        }
        if self.compress {
            handlers.push(json!({
                "handler": "encode",
                "encodings": {"zstd": {}, "gzip": {}},
                "prefer": ["zstd", "gzip"],
            }));
        }
        handlers
    }
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USERNAME
        && value
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b':')
}

/// `$2a$`, `$2b$`, or `$2y$`, a cost of 10 to 12, and 53 characters of the
/// bcrypt base64 alphabet.
fn valid_bcrypt_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 60
        && bytes.starts_with(b"$2")
        && matches!(bytes[2], b'a' | b'b' | b'y')
        && bytes[3] == b'$'
        && matches!(&value[4..7], "10$" | "11$" | "12$")
        && bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/'))
}

fn valid_ip_range(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    // The canonical form only, so the same range has one spelling.
    if address.to_string() != value.split('/').next().unwrap_or_default() {
        return false;
    }
    let Some(prefix) = prefix else {
        return true;
    };
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) || prefix.len() > 3 {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match address {
        IpAddr::V4(address) => {
            prefix <= 32 && {
                let bits = u32::from(address);
                prefix == 32 || bits & (u32::MAX >> prefix) == 0
            }
        }
        IpAddr::V6(address) => {
            prefix <= 128 && {
                let bits = u128::from(address);
                prefix == 128 || bits & (u128::MAX >> prefix) == 0
            }
        }
    }
}

/// An HTTP token (RFC 9110).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HEADER_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

fn forbidden_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    FORBIDDEN_HEADERS.contains(&name.as_str())
        || FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

fn validate_headers(list: &[Header], label: &str) -> Result<(), String> {
    if list.len() > MAX_HEADERS {
        return Err(format!(
            "An ingress route sets at most {MAX_HEADERS} {label} headers."
        ));
    }
    let mut names = std::collections::HashSet::new();
    for header in list {
        if !valid_header_name(&header.name) {
            return Err(format!(
                "A {label} header name of an ingress route is invalid."
            ));
        }
        if forbidden_header(&header.name) {
            return Err(format!(
                "The {label} header {} cannot be set on an ingress route.",
                header.name
            ));
        }
        if !names.insert(header.name.to_ascii_lowercase()) {
            return Err(format!(
                "The {label} header {} is set more than once.",
                header.name
            ));
        }
        if header.value.len() > MAX_HEADER_VALUE
            || !header
                .value
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte) && !matches!(byte, b'{' | b'}'))
        {
            return Err(format!(
                "The value of the {label} header {} must have at most {MAX_HEADER_VALUE} printable ASCII characters without {{ or }}.",
                header.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "$2y$10$abcdefghijklmnopqrstuuVwXyZ0123456789./ABCDEFGHIJKLMN";

    fn options() -> RouteOptions {
        RouteOptions {
            basic_auth_username: "admin".into(),
            basic_auth_password_hash: HASH.into(),
            allowed_ips: vec![
                "203.0.113.0/24".into(),
                "2001:db8::/32".into(),
                "198.51.100.7".into(),
            ],
            request_headers: vec![Header {
                name: "X-Team".into(),
                value: "a b".into(),
            }],
            response_headers: vec![Header {
                name: "Strict-Transport-Security".into(),
                value: "max-age=31536000".into(),
            }],
            compress: true,
        }
    }

    #[test]
    fn accepts_valid_options_and_round_trips_the_stored_form() {
        assert_eq!(HASH.len(), 60);
        let options = options();
        assert_eq!(options.validate(), Ok(()));
        assert_eq!(RouteOptions::parse_stored(&options.stored()), Ok(options));
        assert_eq!(RouteOptions::default().stored(), "");
        assert_eq!(RouteOptions::parse_stored(""), Ok(RouteOptions::default()));
    }

    #[test]
    fn rejects_invalid_basic_auth() {
        for (username, hash) in [
            ("admin", ""),
            ("", HASH),
            ("ad:min", HASH),
            (&"a".repeat(65), HASH),
            ("admin", "plain-password"),
            ("admin", &HASH.replace("$10$", "$04$")),
            ("admin", &HASH.replace("$10$", "$13$")),
            ("admin", &HASH.replacen("$2y$", "$argon2id$", 1)),
            ("admin", &format!("{}\"", &HASH[..59])),
        ] {
            let options = RouteOptions {
                basic_auth_username: username.into(),
                basic_auth_password_hash: hash.into(),
                ..RouteOptions::default()
            };
            assert!(options.validate().is_err(), "{username} {hash}");
        }
    }

    #[test]
    fn rejects_invalid_ip_ranges() {
        for range in [
            "10.0.0.1/8",
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "010.0.0.1",
            "2001:DB8::/32",
            "2001:db8::1/32",
            "example.com",
            "10.0.0.0/8 ",
        ] {
            let options = RouteOptions {
                allowed_ips: vec![range.into()],
                ..RouteOptions::default()
            };
            assert!(options.validate().is_err(), "{range}");
        }
        let too_many = RouteOptions {
            allowed_ips: (0..33).map(|index| format!("10.0.0.{index}")).collect(),
            ..RouteOptions::default()
        };
        assert!(too_many.validate().is_err());
        let duplicate = RouteOptions {
            allowed_ips: vec!["10.0.0.1".into(), "10.0.0.1".into()],
            ..RouteOptions::default()
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn rejects_forbidden_and_invalid_headers() {
        for (name, value) in [
            ("Host", "other.example.com"),
            ("connection", "close"),
            ("Proxy-Authorization", "x"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("Content-Length", "1"),
            ("X Bad", "x"),
            ("X-Ok", "{http.request.remote}"),
            ("X-Ok", "line\r\nInjected: 1"),
            ("X-Ok", &"a".repeat(1025)),
        ] {
            let options = RouteOptions {
                request_headers: vec![Header {
                    name: name.into(),
                    value: value.into(),
                }],
                ..RouteOptions::default()
            };
            assert!(options.validate().is_err(), "{name}: {value}");
        }
        let duplicate = RouteOptions {
            response_headers: vec![
                Header {
                    name: "X-A".into(),
                    value: "1".into(),
                },
                Header {
                    name: "x-a".into(),
                    value: "2".into(),
                },
            ],
            ..RouteOptions::default()
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn stored_options_with_unknown_or_invalid_fields_fail() {
        assert!(RouteOptions::parse_stored(r#"{"compress":true,"rate_limit":5}"#).is_err());
        assert!(RouteOptions::parse_stored(r#"{"allowed_ips":["10.0.0.1/8"]}"#).is_err());
        assert!(RouteOptions::parse_stored("{}").is_err());
        assert!(RouteOptions::parse_stored("not json").is_err());
    }

    #[test]
    fn renders_fixed_handlers_in_order() {
        let handlers = options().handlers(true);
        let names = handlers
            .iter()
            .map(|handler| handler["handler"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            ["subroute", "authentication", "headers", "headers", "encode"]
        );
        assert_eq!(
            handlers[0]["routes"][0]["match"][0]["not"][0]["remote_ip"]["ranges"],
            json!(["203.0.113.0/24", "2001:db8::/32", "198.51.100.7"])
        );
        assert_eq!(handlers[0]["routes"][0]["handle"][0]["status_code"], 403);
        let accounts = &handlers[1]["providers"]["http_basic"]["accounts"];
        assert_eq!(accounts, &json!([{"username": "admin", "password": HASH}]));
        assert_eq!(
            handlers[1]["providers"]["http_basic"]["hash"]["algorithm"],
            "bcrypt"
        );
        assert_eq!(handlers[3]["request"]["set"]["X-Team"], json!(["a b"]));
        assert_eq!(
            handlers[3]["response"],
            json!({"set": {"Strict-Transport-Security": ["max-age=31536000"]}, "deferred": true})
        );
        assert!(RouteOptions::default().handlers(false).is_empty());
    }
}
