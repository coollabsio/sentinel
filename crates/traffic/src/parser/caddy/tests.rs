use super::super::{ProxyType, detect};

#[test]
fn parses_caddy_line() {
    let line = include_bytes!("../../../tests/fixtures/caddy.jsonl")
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
    let line = include_bytes!("../../../tests/fixtures/caddy.jsonl")
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

/// A `uri` or `Referer` carrying a quote/backslash escape must still parse
/// and decode — the same regression the `Cow` fields exist for. See
/// `event::RequestEvent`.
#[test]
fn json_escaped_fields_still_parse_and_decode() {
    let line = include_bytes!("../../../tests/fixtures/caddy.jsonl")
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
    let t = include_bytes!("../../../tests/fixtures/traefik.jsonl")
        .split(|b| *b == b'\n')
        .next()
        .unwrap();
    let c = include_bytes!("../../../tests/fixtures/caddy.jsonl")
        .split(|b| *b == b'\n')
        .next()
        .unwrap();
    assert!(matches!(detect(t), Some(ProxyType::Traefik)));
    assert!(matches!(detect(c), Some(ProxyType::Caddy)));
}
