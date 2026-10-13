use super::*;

/// A fake `GeoLookup` that always resolves to country "ZZ", for tests.
struct FakeGeo;

impl GeoLookup for FakeGeo {
    fn locate(&self, _ip: IpAddr) -> Option<GeoLocation> {
        Some(GeoLocation {
            country: Some("ZZ".to_string()),
            ..GeoLocation::default()
        })
    }
}

/// A fake `GeoLookup` that returns one fixed location.
struct FixedGeo(GeoLocation);

impl GeoLookup for FixedGeo {
    fn locate(&self, _ip: IpAddr) -> Option<GeoLocation> {
        Some(self.0.clone())
    }
}

fn berlin() -> GeoLocation {
    GeoLocation {
        country: Some("DE".to_string()),
        subdivision: Some("BE".to_string()),
        city: Some("Berlin".to_string()),
        lat: Some(52.52),
        lon: Some(13.405),
    }
}

fn enrich_with(location: GeoLocation) -> Enriched {
    let mut ev = base_event();
    ev.client_ip = Some("1.2.3.4".into());
    Enricher::new(Arc::new(FixedGeo(location)), 8).enrich(&ev)
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
        forwarded_ip: None,
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
    ev.client_ip = Some("172.18.0.1".into());

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

    // cf_connecting_ip beats forwarded_ip and client_ip.
    let mut ev = base_event();
    ev.cf_connecting_ip = Some("10.0.0.1".into());
    ev.forwarded_ip = Some("10.0.0.2, 10.0.0.3".into());
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.1".parse::<IpAddr>().unwrap())
    );

    // The first forwarded_ip entry beats client_ip when cf_connecting_ip is absent.
    let mut ev = base_event();
    ev.forwarded_ip = Some("10.0.0.2, 10.0.0.3".into());
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.2".parse::<IpAddr>().unwrap())
    );

    // client_ip used when neither cf_connecting_ip nor forwarded_ip present.
    let mut ev = base_event();
    ev.client_ip = Some("10.0.0.4".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.client_ip,
        Some("10.0.0.4".parse::<IpAddr>().unwrap())
    );
}

fn ip(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

/// A third-party proxy with a public IP (Hetzner LB, a CDN, nginx on another
/// VPS) that the proxy itself trusts: its forwarded IP is used, not the proxy's.
#[test]
fn public_peer_forwarded_ip_is_used() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("8.8.8.8".into());
    ev.forwarded_ip = Some("1.2.3.4, 8.8.8.8".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("1.2.3.4"));
}

#[test]
fn public_peer_ignores_spoofed_cloudflare_headers() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("8.8.8.8".into());
    ev.cf_connecting_ip = Some("1.2.3.4".into());
    ev.cf_country = Some("US".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("8.8.8.8"));
    assert_eq!(result.country, Some("ZZ".to_string()));
}

#[test]
fn public_peer_spoofed_cf_ip_falls_back_to_forwarded_ip() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("8.8.8.8".into());
    ev.cf_connecting_ip = Some("1.2.3.4".into());
    ev.forwarded_ip = Some("5.6.7.8".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("5.6.7.8"));
}

#[test]
fn cloudflare_peer_trusts_cf_connecting_ip_and_country() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("172.70.1.1".into());
    ev.cf_connecting_ip = Some("1.2.3.4".into());
    ev.cf_country = Some("US".into());
    ev.forwarded_ip = Some("5.6.7.8".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("1.2.3.4"));
    assert_eq!(result.country, Some("US".to_string()));
}

#[test]
fn ipv6_cloudflare_peer_trusts_cf_connecting_ip() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("2606:4700:10::1".into());
    ev.cf_connecting_ip = Some("2001:db8::7".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("2001:db8::7"));
}

#[test]
fn local_peers_trust_cloudflare_headers() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    for peer in [
        "172.18.0.1",
        "127.0.0.1",
        "::1",
        "fd00::1",
        "::ffff:10.0.0.1",
    ] {
        let mut ev = base_event();
        ev.client_ip = Some(peer.into());
        ev.cf_connecting_ip = Some("1.2.3.4".into());
        ev.cf_country = Some("US".into());

        let result = enricher.enrich(&ev);

        assert_eq!(result.client_ip, ip("1.2.3.4"), "peer {peer}");
        assert_eq!(result.country, Some("US".to_string()), "peer {peer}");
    }
}

#[test]
fn ipv4_mapped_public_peer_is_untrusted() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("::ffff:8.8.8.8".into());
    ev.cf_connecting_ip = Some("1.2.3.4".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("::ffff:8.8.8.8"));
}

#[test]
fn missing_peer_ignores_cloudflare_headers() {
    let enricher = Enricher::new(Arc::new(FakeGeo), 8);
    let mut ev = base_event();
    ev.cf_connecting_ip = Some("1.2.3.4".into());
    ev.cf_country = Some("US".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, None);
    assert_eq!(result.country, None);
}

#[test]
fn unparseable_peer_ignores_cloudflare_headers() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("not-an-ip".into());
    ev.cf_connecting_ip = Some("1.2.3.4".into());
    ev.forwarded_ip = Some("5.6.7.8".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("5.6.7.8"));
}

#[test]
fn unparseable_header_ip_falls_back_to_peer() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.client_ip = Some("10.0.0.4".into());
    ev.cf_connecting_ip = Some("garbage".into());
    ev.forwarded_ip = Some("also-garbage".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.client_ip, ip("10.0.0.4"));
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
fn known_agent_detected_from_ua_substring() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.user_agent =
        Some("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot".into());

    let result = enricher.enrich(&ev);

    assert_eq!(
        result.agent_name.as_deref(),
        Some("GPTBot"),
        "a UA containing GPTBot must resolve to the canonical agent name"
    );
    assert!(result.bot, "a matched known agent must imply bot traffic");
}

#[test]
fn known_agent_prefers_more_specific_token_over_its_substring() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);

    let mut ev = base_event();
    ev.user_agent =
        Some("Mozilla/5.0 (Applebot-Extended/0.1; +http://www.apple.com/go/applebot)".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.agent_name.as_deref(),
        Some("Applebot-Extended"),
        "Applebot-Extended must not be masked by the plain Applebot token"
    );

    let mut ev = base_event();
    ev.user_agent = Some("Mozilla/5.0 (compatible; GrokBot/1.0)".into());
    let result = enricher.enrich(&ev);
    assert_eq!(
        result.agent_name.as_deref(),
        Some("GrokBot"),
        "GrokBot must resolve to its own canonical name"
    );
}

#[test]
fn known_agent_does_not_false_positive_on_unrelated_products_containing_grok() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.user_agent = Some(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NotGrokClient/1.0 AppleWebKit/537.36 Chrome/91.0"
            .into(),
    );

    let result = enricher.enrich(&ev);

    assert_eq!(
        result.agent_name, None,
        "there is no bare 'grok' token, so an unrelated product name containing \
         'grok' must not be misclassified as the xAI crawler"
    );
}

#[test]
fn known_agent_covers_recently_added_ai_labs() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);

    let cases = [
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "ClaudeBot",
        ),
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; MistralAI-User/1.0; +https://docs.mistral.ai/robots)",
            "MistralAI-User",
        ),
        (
            "DeepSeekBot/1.0 (+https://deepseek.com/deepseekbot)",
            "DeepSeekBot",
        ),
        (
            "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
            "PerplexityBot",
        ),
        (
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Meta-ExternalFetcher/1.1)",
            "Meta-ExternalFetcher",
        ),
        ("bigsur.ai (+https://www.bigsur.ai)", "bigsur.ai"),
    ];

    for (ua, expected) in cases {
        let mut ev = base_event();
        ev.user_agent = Some(ua.into());
        let result = enricher.enrich(&ev);
        assert_eq!(
            result.agent_name.as_deref(),
            Some(expected),
            "UA {ua:?} should resolve to {expected}"
        );
    }
}

#[test]
fn normal_browser_has_no_agent_name_and_is_not_a_bot() {
    let enricher = Enricher::new(Arc::new(NoGeo), 8);
    let mut ev = base_event();
    ev.user_agent = Some(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            .into(),
    );

    let result = enricher.enrich(&ev);

    assert_eq!(
        result.agent_name, None,
        "a normal Chrome UA matches no agent"
    );
    assert!(!result.bot);
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

#[test]
fn city_key_joins_the_parts_and_replaces_pipes() {
    assert_eq!(city_key("DE", Some("BE"), "Berlin"), "DE|BE|Berlin");
    assert_eq!(city_key("SG", None, "Singapore"), "SG||Singapore");
    assert_eq!(city_key("US", Some("A|B"), "C|D"), "US|A B|C D");
}

#[test]
fn city_comes_from_the_lookup_with_coordinates() {
    let result = enrich_with(berlin());

    assert_eq!(result.country, Some("DE".to_string()));
    assert_eq!(
        result.city,
        Some(CityHit {
            key: "DE|BE|Berlin".to_string(),
            coords: Some((52.52, 13.405)),
        })
    );
}

/// A country-only database, or a network with no city, gives no city row.
#[test]
fn a_country_with_no_city_gives_no_city() {
    let mut location = berlin();
    location.city = None;

    let result = enrich_with(location);

    assert_eq!(result.country, Some("DE".to_string()));
    assert_eq!(result.city, None);
}

#[test]
fn no_country_gives_no_city() {
    let mut location = berlin();
    location.country = None;

    assert_eq!(enrich_with(location).city, None);
}

#[test]
fn coordinates_that_are_not_finite_are_dropped() {
    let mut location = berlin();
    location.lat = Some(f64::NAN);

    let city = enrich_with(location).city.unwrap();

    assert_eq!(city.key, "DE|BE|Berlin");
    assert_eq!(city.coords, None);
}

#[test]
fn one_missing_coordinate_drops_both() {
    let mut location = berlin();
    location.lon = None;

    assert_eq!(enrich_with(location).city.unwrap().coords, None);
}

/// The Cloudflare header sets the country dimension only. The city key keeps
/// the country of the lookup, so it agrees with the coordinates.
#[test]
fn the_cf_country_header_does_not_change_the_city_key() {
    let enricher = Enricher::new(Arc::new(FixedGeo(berlin())), 8);
    let mut ev = base_event();
    ev.cf_country = Some("US".into());
    ev.client_ip = Some("172.18.0.1".into());

    let result = enricher.enrich(&ev);

    assert_eq!(result.country, Some("US".to_string()));
    assert_eq!(result.city.unwrap().key, "DE|BE|Berlin");
}

#[test]
fn no_geo_gives_no_city() {
    let mut ev = base_event();
    ev.client_ip = Some("1.2.3.4".into());

    let result = Enricher::new(Arc::new(NoGeo), 8).enrich(&ev);

    assert_eq!(result.city, None);
}

#[test]
fn coordinates_outside_the_map_range_are_dropped() {
    for (lat, lon) in [(90.1, 0.0), (-90.1, 0.0), (0.0, 180.1), (0.0, -180.1)] {
        let mut location = berlin();
        location.lat = Some(lat);
        location.lon = Some(lon);
        assert_eq!(enrich_with(location).city.unwrap().coords, None);
    }
    for (lat, lon) in [(90.0, 180.0), (-90.0, -180.0)] {
        let mut location = berlin();
        location.lat = Some(lat);
        location.lon = Some(lon);
        assert_eq!(enrich_with(location).city.unwrap().coords, Some((lat, lon)));
    }
}
