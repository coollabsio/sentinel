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

        let bot = ev.cf_verified_bot.is_some() || ua.is_bot;

        let cache = ev.cf_cache_status.as_deref().map(String::from);

        Enriched {
            country,
            ua,
            client_ip,
            cache,
            bot,
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
