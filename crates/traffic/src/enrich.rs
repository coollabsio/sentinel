#![forbid(unsafe_code)]

//! Enriches events using Cloudflare headers, GeoIP, and a bounded User-Agent
//! parse cache. Cloudflare headers are trusted only from a local proxy or
//! Cloudflare peer; the forwarded client IP is vetted by the proxy itself (see
//! [`Enricher::enrich`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::event::RequestEvent;

/// Looks up a country code for an IP address (e.g. backed by a GeoIP database).
pub trait CountryLookup: Send + Sync {
    /// Return an ISO country code for `ip`, or `None` if unknown.
    fn country(&self, ip: IpAddr) -> Option<String>;
}

/// A no-op `CountryLookup` that never resolves a country.
pub struct NoGeo;

impl CountryLookup for NoGeo {
    fn country(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

/// Parsed User-Agent metadata.
#[derive(Clone, Default)]
pub struct UaInfo {
    /// Browser name (e.g. "Chrome").
    pub browser: String,
    /// Operating system (e.g. "Linux").
    pub os: String,
    /// Device category (woothee's `category`, e.g. "pc", "smartphone", "crawler").
    pub device: String,
    /// Whether the UA was classified as a crawler/bot.
    pub is_bot: bool,
}

/// Well-known bot / AI-agent User-Agent tokens and their canonical display
/// names, matched case-insensitively as a substring of the raw User-Agent.
/// This catches AI crawlers even when Cloudflare's verified-bot header is
/// absent (self-hosted, non-CF deployments), or when Cloudflare hasn't
/// verified a given crawler yet.
///
/// Grouped by operator; within a group, a token that is itself a substring of
/// another token in the same group (e.g. `applebot` inside
/// `applebot-extended`) is listed *after* the longer, more specific token so
/// the specific one wins — the first hit in list order wins overall.
/// Sourced from each operator's own crawler docs plus the community-maintained
/// <https://github.com/ai-robots-txt/ai.robots.txt> registry.
static KNOWN_AGENTS: &[(&str, &str)] = &[
    // OpenAI
    ("gptbot", "GPTBot"),
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-operator", "ChatGPT-Operator"),
    ("chatgpt-user", "ChatGPT-User"),
    // Anthropic
    ("claude-code", "Claude-Code"),
    ("claude-searchbot", "Claude-SearchBot"),
    ("claude-user", "Claude-User"),
    ("claude-web", "Claude-Web"),
    ("claudebot", "ClaudeBot"),
    ("anthropic-ai", "anthropic-ai"),
    // Google
    ("google-extended", "Google-Extended"),
    ("googleother", "GoogleOther"),
    ("googlebot", "Googlebot"),
    // Meta
    ("meta-externalagent", "Meta-ExternalAgent"),
    ("meta-externalfetcher", "Meta-ExternalFetcher"),
    ("facebookexternalhit", "facebookexternalhit"),
    // Perplexity
    ("perplexity-user", "Perplexity-User"),
    ("perplexitybot", "PerplexityBot"),
    // Mistral
    ("mistralai-user", "MistralAI-User"),
    // xAI. No bare "grok" token: xAI's documented crawlers rarely send an
    // identifiable UA in practice (they largely spoof browser UAs instead),
    // and a bare substring match would false-positive on unrelated products
    // whose name merely contains "grok" (e.g. Logstash's Grok filters).
    ("grokbot", "GrokBot"),
    // DeepSeek
    ("deepseekbot", "DeepSeekBot"),
    // Amazon
    ("amazonbot", "Amazonbot"),
    // Apple
    ("applebot-extended", "Applebot-Extended"),
    ("applebot", "Applebot"),
    // ByteDance
    ("bytespider", "Bytespider"),
    ("tiktokspider", "TikTokSpider"),
    // Common Crawl (training data used by many labs)
    ("ccbot", "CCBot"),
    // Cohere
    (
        "cohere-training-data-crawler",
        "cohere-training-data-crawler",
    ),
    ("cohere-ai", "cohere-ai"),
    // Allen Institute for AI
    ("ai2bot-dolma", "Ai2Bot-Dolma"),
    ("ai2bot", "AI2Bot"),
    // Other AI-specific crawlers
    ("bigsur.ai", "bigsur.ai"),
    ("digitaloceangenai-crawler", "DigitalOceanGenAI-Crawler"),
    ("linerbot", "LinerBot"),
    ("mycentralaiscraperbot", "MyCentralAIScraperBot"),
    ("pangubot", "PanguBot"),
    ("sbintuitionsbot", "SBIntuitionsBot"),
    ("youbot", "YouBot"),
    ("diffbot", "Diffbot"),
    ("img2dataset", "img2dataset"),
    ("quillbot", "QuillBot"),
    // Search engines with an AI-assist crawler
    ("duckassistbot", "DuckAssistBot"),
    ("duckduckbot", "DuckDuckBot"),
    ("bingbot", "Bingbot"),
    ("yandexbot", "YandexBot"),
];

/// Returns the canonical name of the first [`KNOWN_AGENTS`] token found as a
/// case-insensitive substring of `ua`, or `None` when no known agent matches.
fn detect_known_agent(ua: &str) -> Option<&'static str> {
    let lower = ua.to_ascii_lowercase();
    KNOWN_AGENTS
        .iter()
        .find(|(token, _)| lower.contains(token))
        .map(|(_, name)| *name)
}

/// Networks whose peers may set Cloudflare headers as local proxies (cloudflared,
/// load balancers, the Docker bridge): loopback, private, unique-local,
/// link-local, and CGNAT.
const LOCAL_PROXY_NETS: &[(IpAddr, u8)] = &[
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
];

/// Cloudflare edge networks, from <https://www.cloudflare.com/ips-v4/> and
/// <https://www.cloudflare.com/ips-v6/>.
const CLOUDFLARE_NETS: &[(IpAddr, u8)] = &[
    (IpAddr::V4(Ipv4Addr::new(173, 245, 48, 0)), 20),
    (IpAddr::V4(Ipv4Addr::new(103, 21, 244, 0)), 22),
    (IpAddr::V4(Ipv4Addr::new(103, 22, 200, 0)), 22),
    (IpAddr::V4(Ipv4Addr::new(103, 31, 4, 0)), 22),
    (IpAddr::V4(Ipv4Addr::new(141, 101, 64, 0)), 18),
    (IpAddr::V4(Ipv4Addr::new(108, 162, 192, 0)), 18),
    (IpAddr::V4(Ipv4Addr::new(190, 93, 240, 0)), 20),
    (IpAddr::V4(Ipv4Addr::new(188, 114, 96, 0)), 20),
    (IpAddr::V4(Ipv4Addr::new(197, 234, 240, 0)), 22),
    (IpAddr::V4(Ipv4Addr::new(198, 41, 128, 0)), 17),
    (IpAddr::V4(Ipv4Addr::new(162, 158, 0, 0)), 15),
    (IpAddr::V4(Ipv4Addr::new(104, 16, 0, 0)), 13),
    (IpAddr::V4(Ipv4Addr::new(104, 24, 0, 0)), 14),
    (IpAddr::V4(Ipv4Addr::new(172, 64, 0, 0)), 13),
    (IpAddr::V4(Ipv4Addr::new(131, 0, 72, 0)), 22),
    (
        IpAddr::V6(Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0)),
        32,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0)),
        29,
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0)),
        32,
    ),
];

/// Returns true when `ip` lies inside `net`/`prefix` (same address family only).
fn in_net(ip: IpAddr, (net, prefix): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// Returns true when `peer` may set CF-Connecting-IP and CF-IPCountry: a local
/// proxy or a Cloudflare edge. IPv4-mapped IPv6 addresses are checked as IPv4.
fn trusts_cf_headers(peer: IpAddr) -> bool {
    let peer = peer.to_canonical();
    LOCAL_PROXY_NETS
        .iter()
        .chain(CLOUDFLARE_NETS)
        .any(|&net| in_net(peer, net))
}

fn parse_ip(value: Option<&str>) -> Option<IpAddr> {
    value.and_then(|s| s.trim().parse().ok())
}

/// Result of enriching a `RequestEvent`.
pub struct Enriched {
    /// Resolved country code, if any.
    pub country: Option<String>,
    /// Parsed User-Agent metadata.
    pub ua: UaInfo,
    /// Resolved client IP address, if any.
    pub client_ip: Option<IpAddr>,
    /// Cloudflare cache status, if present.
    pub cache: Option<String>,
    /// Whether the request is attributed to a bot.
    pub bot: bool,
    /// Canonical name of a recognized bot / AI-agent (e.g. "GPTBot",
    /// "ClaudeBot"), from the [`KNOWN_AGENTS`] substring match, or `None`.
    /// A match here also forces [`Self::bot`] true.
    pub agent_name: Option<String>,
}

/// Enriches `RequestEvent`s with geolocation, UA parsing, and the client IP.
/// Cloudflare headers are trusted only when the TCP peer is a local proxy or Cloudflare.
pub struct Enricher {
    geo: Arc<dyn CountryLookup>,
    ua_cache: Mutex<LruCache<String, UaInfo>>,
}

impl Enricher {
    /// Create a new `Enricher` backed by `geo` for country lookups, with a UA-parse
    /// cache holding up to `ua_cache_cap` entries. A `ua_cache_cap` of `0` degrades
    /// to a 1-entry cache rather than panicking.
    pub fn new(geo: Arc<dyn CountryLookup>, ua_cache_cap: usize) -> Self {
        let cap = NonZeroUsize::new(ua_cache_cap).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            geo,
            ua_cache: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Enrich `ev`, applying client-IP, country, UA, and bot precedence rules.
    /// Client IP: CF-Connecting-IP (local or Cloudflare peer only), then the
    /// first proxy-vetted forwarded IP, then the peer. Country: CF-IPCountry
    /// (same peer rule), then GeoIP of the client IP.
    pub fn enrich(&self, ev: &RequestEvent) -> Enriched {
        let peer = parse_ip(ev.client_ip.as_deref());
        let cf_trusted = peer.is_some_and(trusts_cf_headers);

        let cf_ip = parse_ip(ev.cf_connecting_ip.as_deref().filter(|_| cf_trusted));
        let forwarded_ip = || {
            let first = ev.forwarded_ip.as_deref()?.split(',').next();
            parse_ip(first)
        };
        let client_ip = cf_ip.or_else(forwarded_ip).or(peer);

        let country = ev
            .cf_country
            .as_deref()
            .filter(|_| cf_trusted)
            .map(String::from)
            .or_else(|| client_ip.and_then(|ip| self.geo.country(ip)));

        let ua = match ev.user_agent.as_deref() {
            Some(ua_str) => self.parse_ua_cached(ua_str),
            None => UaInfo::default(),
        };

        // A known-agent substring match is derived from the *raw* UA, not
        // woothee's parse, so AI crawlers are caught even where woothee has no
        // rule for them. A match implies bot traffic, OR'd into the existing
        // detection so neither signal can regress the other.
        let agent_name = ev
            .user_agent
            .as_deref()
            .and_then(detect_known_agent)
            .map(String::from);

        let bot = ev.cf_verified_bot.is_some() || ua.is_bot || agent_name.is_some();

        let cache = ev.cf_cache_status.as_deref().map(String::from);

        Enriched {
            country,
            ua,
            client_ip,
            cache,
            bot,
            agent_name,
        }
    }

    fn parse_ua_cached(&self, ua_str: &str) -> UaInfo {
        let mut cache = self.ua_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(hit) = cache.get(ua_str) {
            return hit.clone();
        }
        let parsed = woothee::parser::Parser::new()
            .parse(ua_str)
            .map(|r| UaInfo {
                browser: r.name.to_string(),
                os: r.os.to_string(),
                device: r.category.to_string(),
                is_bot: r.category == "crawler",
            })
            .unwrap_or_default();
        cache.put(ua_str.to_string(), parsed.clone());
        parsed
    }
}

#[cfg(test)]
mod tests;
