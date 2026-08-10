use super::*;

/// A fake `CountryLookup` that always resolves to "ZZ", for tests.
struct FakeGeo;

impl CountryLookup for FakeGeo {
    fn country(&self, _ip: IpAddr) -> Option<String> {
        Some("ZZ".to_string())
    }
}

fn base_event() -> RequestEvent<'static> {
    RequestEvent {
        ts_ms: 0,
        app: "".into(),
        host: "".into(),
        method: "".into(),
        path: "".into(),
        status: 0,
        bytes_in: 0,
        bytes_out: 0,
        duration_ms: 0.0,
        protocol: "".into(),
        scheme: "".into(),
        tls_version: None,
        client_ip: None,
        xff: None,
        user_agent: None,
        referer: None,
        cf_connecting_ip: None,
        cf_country: None,
        cf_cache_status: None,
        cf_verified_bot: None,
    }
}

#[test]
fn cf_country_wins_over_geoip() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    let mut ev = base_event();
    ev.cf_country = Some("US".into());
    ev.client_ip = Some("1.2.3.4".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.country, Some("US".to_string()));
}

#[test]
fn falls_back_to_geoip_when_no_cf() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    let mut ev = base_event();
    ev.cf_country = None;
    ev.client_ip = Some("1.2.3.4".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.country, Some("ZZ".to_string()));
}

#[test]
fn client_ip_precedence() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);

    // cf_connecting_ip beats xff and client_ip.
    let mut ev = base_event();
    ev.cf_connecting_ip = Some("10.0.0.1".into());
    ev.xff = Some("10.0.0.2, 10.0.0.3".into());
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.1".parse::<IpAddr>().unwrap())
    );

    // xff beats client_ip when cf_connecting_ip is absent.
    let mut ev = base_event();
    ev.xff = Some("10.0.0.2, 10.0.0.3".into());
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.2".parse::<IpAddr>().unwrap())
    );

    // client_ip used when neither cf_connecting_ip nor xff present.
    let mut ev = base_event();
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.4".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn detects_bot_via_woothee() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.user_agent =
        Some("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)".into());

    let result = enricher.enrich(&ev);

    assert!(result.bot, "expected googlebot UA to be detected as a bot");
}

#[test]
fn ua_cache_memoizes() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.user_agent = Some(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            .into(),
    );

    let first = enricher.enrich(&ev);
    let second = enricher.enrich(&ev);

    assert_eq!(first.ua.browser, second.ua.browser);
    assert!(!first.ua.browser.is_empty());
}
