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

/// A Coolify-injected `coolify_app_id` keys attribution by UUID (mirroring
/// Traefik), while `host` stays the served hostname.
#[test]
fn coolify_app_id_overrides_host_attribution() {
    let line = include_bytes!("../../../tests/fixtures/caddy.jsonl")
        .split(|b| *b == b'\n')
        .nth(3)
        .unwrap();
    let ev = super::parse(line).unwrap();
    assert_eq!(ev.host, "app.example.com");
    assert_eq!(ev.app, "jc4wsgs", "coolify_app_id must key attribution");
    assert_ne!(ev.app, ev.host);
}

/// An empty `coolify_app_id` counts as absent — attribution falls back to host,
/// exactly as a hand-configured Caddy site (no such field) does.
#[test]
fn empty_coolify_app_id_falls_back_to_host() {
    let line = br#"{"ts":1.0,"status":200,"duration":0.001,"coolify_app_id":"","request":{"method":"GET","uri":"/","host":"h.example.com","proto":"HTTP/1.1","headers":{}}}"#;
    let ev = super::parse(line).unwrap();
    assert_eq!(ev.app, "h.example.com");
    assert_eq!(ev.app, ev.host);
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
