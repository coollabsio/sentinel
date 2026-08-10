#[test]
fn parses_traefik_line() {
    let line = include_bytes!("../../../tests/fixtures/traefik.jsonl")
        .split(|b| *b == b'\n')
        .next()
        .unwrap();
    let ev = super::parse(line).expect("parse");
    assert_eq!(ev.method, "GET");
    assert_eq!(ev.status, 200);
    assert_eq!(ev.app, "jc4wsgs"); // stripped from https-0-jc4wsgs@docker
    assert!((ev.duration_ms - 12.5).abs() < 0.01); // 12_500_000 ns
    assert_eq!(ev.cf_country.as_deref(), Some("US"));
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
    let line = include_bytes!("../../../tests/fixtures/traefik.jsonl")
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

/// A `RequestPath`/`Referer` carrying HTML-escaped `&` (Traefik via Go's
/// `encoding/json`) or a quote/backslash must still parse and decode — the
/// regression the `Cow` fields exist for. See `event::RequestEvent`.
#[test]
fn json_escaped_fields_still_parse_and_decode() {
    let line = include_bytes!("../../../tests/fixtures/traefik.jsonl")
        .split(|b| *b == b'\n')
        .nth(2)
        .unwrap();

    let ev = super::parse(line).expect("a JSON-escaped Traefik line must still parse");

    // The query string is stripped, but only after `&` decoded to a
    // real `&` — a failure to unescape would have dropped the line.
    assert_eq!(ev.path, "/search");
    assert_eq!(ev.app, "jc4wsgs");
    assert_eq!(
        ev.referer.as_deref(),
        Some(r#"https://ref.example.com/a?x=1&y=2<b> "quoted" back\slash"#),
        "escapes must be decoded, not passed through verbatim"
    );
    assert_eq!(ev.method, "GET");
    assert_eq!(ev.status, 200);
}

#[test]
fn internal_router_is_dropped() {
    let line = br#"{"ClientAddr":"10.0.0.5:54321","ClientHost":"10.0.0.5","DownstreamContentSize":512,"DownstreamStatus":200,"Duration":1000000,"RequestContentSize":0,"RequestHost":"traefik.example.com","RequestMethod":"GET","RequestPath":"/dashboard/","RequestProtocol":"HTTP/1.1","RequestScheme":"https","RouterName":"api@internal","StartUTC":"2026-08-09T12:00:10.000000000Z","time":"2026-08-09T12:00:10Z"}"#;
    assert!(super::parse(line).is_none());
}
