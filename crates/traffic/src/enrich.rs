#![forbid(unsafe_code)]

//! Enriches events using Cloudflare headers, GeoIP, and a bounded User-Agent
//! parse cache. Header values take precedence over derived values.

use std::net::IpAddr;
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

/// Enriches `RequestEvent`s with geolocation, UA parsing, and CF-header precedence.
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
    pub fn enrich(&self, ev: &RequestEvent) -> Enriched {
        let client_ip_str: Option<&str> = ev
            .cf_connecting_ip
            .as_deref()
            .or_else(|| {
                ev.xff
                    .as_deref()
                    .and_then(|xff| xff.split(',').next().map(str::trim))
            })
            .or(ev.client_ip.as_deref());
        let client_ip: Option<IpAddr> = client_ip_str.and_then(|s| s.parse().ok());

        let country = ev
            .cf_country
            .as_deref()
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
