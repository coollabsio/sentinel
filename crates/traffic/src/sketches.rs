#![forbid(unsafe_code)]

//! Probabilistic data structures (HyperLogLog, t-digest) for streaming analytics.
//!
//! Three mergeable sketch types, sized for periodic time-bucket compaction:
//! - [`LatencyDigest`]: approximate quantiles over request durations (t-digest).
//! - [`Uniques`]: approximate distinct-IP counting (HyperLogLog++).
//! - [`TopN`]: exact counts, capped to the top-N entries with an `__other__` bucket.

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::net::IpAddr;

use hyperloglogplus::{HyperLogLog, HyperLogLogPlus};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use siphasher::sip::SipHasher13;
use tdigests::{Centroid, TDigest};

use crate::TrafficError;

/// Maximum number of centroids a [`LatencyDigest`] retains after compression.
///
/// Bounds the digest's memory footprint / serialized size independent of how
/// many raw values have been folded in.
const MAX_CENTROIDS: usize = 100;

/// HyperLogLog++ precision (number of register-index bits). Must be identical
/// across every [`Uniques`] instance that might ever be merged together.
const HLL_PRECISION: u8 = 14;

/// Deterministic hasher-builder for [`Uniques`]: always seeds `SipHasher13`
/// with the same (zero) key via `BuildHasherDefault`, so serialized sketches
/// are stable across process restarts and mergeable across instances —
/// unlike `std::collections::hash_map::RandomState`, which reseeds every
/// process and has no serde impl at all.
///
/// This thin wrapper exists only because `hyperloglogplus::HyperLogLogPlus`
/// derives `Serialize`/`Deserialize` with a `B: Serialize + Deserialize`
/// bound on its hasher-builder field, and the plain
/// `std::hash::BuildHasherDefault<SipHasher13>` has no serde impl in this
/// serde version. Since a default-seeded builder carries no actual state,
/// serializing/deserializing it is a no-op (encoded as `()`).
#[derive(Clone, Debug, Default)]
struct HllHasherBuilder(BuildHasherDefault<SipHasher13>);

impl BuildHasher for HllHasherBuilder {
    type Hasher = SipHasher13;

    fn build_hasher(&self) -> SipHasher13 {
        self.0.build_hasher()
    }
}

impl Serialize for HllHasherBuilder {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for HllHasherBuilder {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <()>::deserialize(deserializer)?;
        Ok(Self::default())
    }
}

type HllType = HyperLogLogPlus<[u8; 16], HllHasherBuilder>;

/// Mergeable approximate-quantile sketch over non-negative, finite latency values.
///
/// `None` means "no values have ever been added" — this avoids ever calling
/// the underlying `tdigests` crate's `from_values`/`from_centroids`, both of
/// which panic on empty input.
pub struct LatencyDigest(Option<TDigest>);

/// Local serializable mirror of `tdigests::Centroid`, which has no serde impl.
#[derive(Serialize, Deserialize)]
struct CentroidData {
    mean: f64,
    weight: f64,
}

impl LatencyDigest {
    /// Creates an empty digest.
    pub fn new() -> Self {
        Self(None)
    }

    /// Folds `values` into the digest, sanitizing away NaN/infinite/negative
    /// entries first. A no-op if every value is filtered out.
    pub fn add(&mut self, values: &[f64]) {
        let clean: Vec<f64> = values
            .iter()
            .copied()
            .filter(|v| v.is_finite() && *v >= 0.0)
            .collect();

        if clean.is_empty() {
            return;
        }

        let new_digest = TDigest::from_values(clean);
        let mut combined = match self.0.take() {
            Some(existing) => existing.merge(&new_digest),
            None => new_digest,
        };
        combined.compress(MAX_CENTROIDS);
        self.0 = Some(combined);
    }

    /// Merges multiple digests into one by pooling all centroids and building
    /// a single fresh digest from them (cheaper and more accurate than
    /// repeated pairwise merges). Returns an empty digest if every input is
    /// empty.
    pub fn merge(sketches: &[LatencyDigest]) -> LatencyDigest {
        let all_centroids: Vec<Centroid> = sketches
            .iter()
            .filter_map(|s| s.0.as_ref())
            .flat_map(|d| d.centroids().iter().cloned())
            .collect();

        if all_centroids.is_empty() {
            return LatencyDigest(None);
        }

        let mut digest = TDigest::from_centroids(all_centroids);
        digest.compress(MAX_CENTROIDS);
        LatencyDigest(Some(digest))
    }

    /// Estimates the value at quantile `q` (0.0..=1.0). Returns `0.0` for an
    /// empty digest.
    pub fn quantile(&self, q: f64) -> f64 {
        match &self.0 {
            Some(digest) => digest.estimate_quantile(q),
            None => 0.0,
        }
    }

    /// Postcard-encodes the digest's centroids. Returns an empty `Vec` for an
    /// empty digest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data: Vec<CentroidData> = match &self.0 {
            Some(digest) => digest
                .centroids()
                .iter()
                .map(|c| CentroidData {
                    mean: c.mean,
                    weight: c.weight,
                })
                .collect(),
            None => Vec::new(),
        };
        postcard::to_stdvec(&data).unwrap_or_default()
    }

    /// Decodes a digest previously produced by [`Self::to_bytes`]. An empty
    /// payload decodes to an empty digest (`Self(None)`), never calling
    /// `TDigest::from_centroids` with zero centroids.
    ///
    /// Also guards against corrupted/malformed blobs (e.g. a partially
    /// overwritten SQLite page) that decode to a structurally valid but
    /// semantically empty `Vec<CentroidData>` — every entry with
    /// `weight <= 0.0` or a NaN `mean`. `tdigests::TDigest::from_centroids`
    /// filters those out internally with the *same* predicate used below and
    /// then `assert!`s the remainder is non-empty, which would panic on such
    /// input. Filtering here first lets us fall back to the empty
    /// representation instead of crashing.
    pub fn from_bytes(b: &[u8]) -> Result<Self, TrafficError> {
        let data: Vec<CentroidData> =
            postcard::from_bytes(b).map_err(|e| TrafficError::Codec(e.to_string()))?;

        // Mirrors tdigests' internal `retain(|c| c.weight > 0.0 && !c.mean.is_nan())`.
        let centroids: Vec<Centroid> = data
            .into_iter()
            .filter(|c| c.weight > 0.0 && !c.mean.is_nan())
            .map(|c| Centroid {
                mean: c.mean,
                weight: c.weight,
            })
            .collect();

        if centroids.is_empty() {
            return Ok(Self(None));
        }

        Ok(Self(Some(TDigest::from_centroids(centroids))))
    }
}

impl Default for LatencyDigest {
    fn default() -> Self {
        Self::new()
    }
}

/// Mergeable approximate distinct-count sketch over client IP addresses.
///
/// Uses HyperLogLog++ with a deterministic hasher (`SipHasher13` via
/// `BuildHasherDefault`, never `RandomState`) so serialized sketches are
/// stable across process restarts and mergeable across instances.
pub struct Uniques(HllType);

impl Uniques {
    /// Creates an empty sketch at the crate-wide fixed precision.
    pub fn new() -> Self {
        let builder = HllHasherBuilder::default();
        let hll = HyperLogLogPlus::new(HLL_PRECISION, builder)
            .expect("HLL_PRECISION is a fixed, valid constant");
        Self(hll)
    }

    /// Adds an IP address to the multiset, mapping v4 addresses into the
    /// v6-mapped `[u8;16]` space so v4 and v6 hashing is consistent.
    pub fn add_ip(&mut self, ip: IpAddr) {
        let bytes: [u8; 16] = match ip {
            IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
            IpAddr::V6(a) => a.octets(),
        };
        self.0.insert(&bytes);
    }

    /// Merges `other`'s multiset into `self`. Both sketches are expected to
    /// share the same precision (guaranteed in the happy path, since
    /// `HLL_PRECISION` is a single crate-wide constant); merge is exact (a
    /// true set union), not approximate on top of the estimate.
    ///
    /// `HyperLogLogPlus`'s derived `Deserialize` does not validate the
    /// `precision` field, so a corrupted blob (or a future `HLL_PRECISION`
    /// change mixing old and new persisted rows) can produce a sketch whose
    /// precision genuinely differs from `self`'s. [`Self::from_bytes`]
    /// rejects that at decode time, but this is defense-in-depth: if an
    /// incompatible sketch ever gets here anyway, degrade gracefully (log
    /// and skip incorporating `other`'s data) instead of panicking.
    pub fn merge_from(&mut self, other: &Uniques) {
        if let Err(err) = self.0.merge(&other.0) {
            tracing::warn!(
                error = %err,
                "Uniques::merge_from: incompatible sketch, skipping merge"
            );
        }
    }

    /// Estimates the number of distinct IPs seen.
    pub fn count(&mut self) -> u64 {
        self.0.count().round() as u64
    }

    /// Postcard-encodes the sketch.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self.0).unwrap_or_default()
    }

    /// Decodes a sketch previously produced by [`Self::to_bytes`].
    ///
    /// `HyperLogLogPlus`'s derived `Deserialize` does not validate the
    /// `precision` field against the crate's valid range (4..=18), nor
    /// against `HLL_PRECISION` — only its `new()` constructor checks that. A
    /// corrupted blob (or stale data from a since-changed `HLL_PRECISION`)
    /// could otherwise carry a precision that later makes `merge`,
    /// `add_ip`/`insert`, or `count` panic or behave unsoundly (e.g.
    /// register-index overflow). Guard against that here by probing a merge
    /// against a freshly-constructed, known-good sketch: `merge` is the one
    /// operation that explicitly validates precision compatibility, so a
    /// successful probe proves the decoded sketch is safe to use.
    pub fn from_bytes(b: &[u8]) -> Result<Self, TrafficError> {
        let hll: HllType =
            postcard::from_bytes(b).map_err(|e| TrafficError::Codec(e.to_string()))?;

        let mut probe = Uniques::new();
        probe
            .0
            .merge(&hll)
            .map_err(|e| TrafficError::Codec(format!("incompatible HLL precision: {e}")))?;

        Ok(Self(hll))
    }
}

impl Default for Uniques {
    fn default() -> Self {
        Self::new()
    }
}

/// Longest aggregation key retained, in bytes.
///
/// Keys are attacker-controlled — a path, a `Referer`, a Cloudflare header
/// value — and nothing upstream bounds their length, so without this a
/// request can pin an arbitrarily large `String` in the aggregator's map for
/// a whole window. 512 bytes is generously above any path or header worth
/// distinguishing in a top-N; two URLs identical for their first 512 bytes
/// are the same line item for reporting purposes.
pub const MAX_KEY_BYTES: usize = 512;

/// Multiple of `topn` at which [`TopN::add_bounded`] trims mid-window.
const SOFT_CAP_TRIGGER: usize = 8;

/// Multiple of `topn` that a mid-window trim keeps. See
/// [`TopN::add_bounded`] for why this is wider than `topn` itself.
const SOFT_CAP_KEEP: usize = 4;

/// Truncate `key` to at most [`MAX_KEY_BYTES`], on a UTF-8 character boundary.
///
/// Slicing a `&str` at a byte offset that lands mid-codepoint panics, and
/// these keys are arbitrary bytes from the wire, so the cut has to be found
/// rather than assumed. Borrows unchanged in the overwhelmingly common case.
pub fn truncate_key(key: &str) -> &str {
    if key.len() <= MAX_KEY_BYTES {
        return key;
    }
    // The last boundary at or below the limit. `char_indices` yields only
    // valid boundaries, so this can never split a multi-byte character.
    let end = key
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_KEY_BYTES)
        .last()
        .unwrap_or(0);
    &key[..end]
}

/// Exact per-key request/byte counters, capped to the top-N keys by request
/// count with everything else folded into `other`.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct TopN {
    /// key -> (requests, bytes_out).
    pub counts: HashMap<String, (u64, u64)>,
    /// Aggregate (requests, bytes_out) for keys evicted by [`Self::cap`].
    pub other: (u64, u64),
}

impl TopN {
    /// Adds `reqs` requests and `bytes` bytes-out to `key`'s running totals.
    ///
    /// `key` is truncated to [`MAX_KEY_BYTES`] first: paths, referers and
    /// Cloudflare header values all come straight off the wire, and nothing
    /// upstream bounds their length.
    pub fn add(&mut self, key: &str, reqs: u64, bytes: u64) {
        let entry = self
            .counts
            .entry(truncate_key(key).to_string())
            .or_insert((0, 0));
        entry.0 += reqs;
        entry.1 += bytes;
    }

    /// [`Self::add`], plus a soft cap that bounds the map *within* the window
    /// instead of only at its end.
    ///
    /// `cap` normally runs once, at drain time — once a minute. Until then the
    /// map is unbounded, so a flood of requests carrying distinct attacker-
    /// chosen paths or headers can grow it freely for a whole window. This
    /// keeps `counts.len()` under `topn × `[`SOFT_CAP_TRIGGER`].
    ///
    /// It trims down to `topn × `[`SOFT_CAP_KEEP`], not to `topn`: bounding
    /// memory to the same order either way, but retaining a far wider set of
    /// candidates, so a key that is mid-table now and a leader by the end of
    /// the window can still get there. Under any normal cardinality the
    /// trigger is never reached and this is exactly [`Self::add`].
    pub fn add_bounded(&mut self, key: &str, reqs: u64, bytes: u64, topn: usize) {
        self.add(key, reqs, bytes);

        // `max(1)`: a configured top-N of 0 would otherwise make the trigger 0
        // and fold every single key straight into `__other__`.
        let topn = topn.max(1);
        if self.counts.len() > topn.saturating_mul(SOFT_CAP_TRIGGER) {
            self.cap(topn.saturating_mul(SOFT_CAP_KEEP));
        }
    }

    /// Sums `other`'s counters into `self`, key by key, plus its `other`
    /// bucket. Deliberately does NOT cap — callers must merge every input at
    /// full resolution for a compaction level, then call [`Self::cap`] once,
    /// so that entries only just outside the top-N in each partial input
    /// still get a chance to be reunited above the threshold before capping.
    pub fn merge(&mut self, other: &TopN) {
        for (key, (reqs, bytes)) in &other.counts {
            let entry = self.counts.entry(key.clone()).or_insert((0, 0));
            entry.0 += reqs;
            entry.1 += bytes;
        }
        self.other.0 += other.other.0;
        self.other.1 += other.other.1;
    }

    /// Keeps only the `n` keys with the highest request counts, folding the
    /// rest into `other`.
    pub fn cap(&mut self, n: usize) {
        if self.counts.len() <= n {
            return;
        }

        let mut entries: Vec<(String, (u64, u64))> = self.counts.drain().collect();
        entries.sort_by_key(|(_, (reqs, _))| std::cmp::Reverse(*reqs));

        let tail = entries.split_off(n);
        for (_, (reqs, bytes)) in tail {
            self.other.0 += reqs;
            self.other.1 += bytes;
        }
        self.counts = entries.into_iter().collect();
    }

    /// Postcard-encodes the counters.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Decodes counters previously produced by [`Self::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, TrafficError> {
        postcard::from_bytes(b).map_err(|e| TrafficError::Codec(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn latency_merge_matches_union() {
        let mut a = LatencyDigest::new();
        a.add(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let mut b = LatencyDigest::new();
        b.add(&[6.0, 7.0, 8.0, 9.0, 10.0]);
        let m = LatencyDigest::merge(&[a, b]);
        assert!((m.quantile(0.5) - 5.5).abs() < 1.0); // approx median of 1..10
    }

    #[test]
    fn latency_roundtrip() {
        let mut a = LatencyDigest::new();
        a.add(&[10.0, 20.0, 30.0]);
        let b = LatencyDigest::from_bytes(&a.to_bytes()).unwrap();
        assert!((a.quantile(0.9) - b.quantile(0.9)).abs() < 1e-9);
    }

    #[test]
    fn latency_empty_digest_does_not_panic() {
        let empty = LatencyDigest::new();
        assert_eq!(empty.quantile(0.5), 0.0);
        let bytes = empty.to_bytes();
        let restored = LatencyDigest::from_bytes(&bytes).unwrap();
        assert_eq!(restored.quantile(0.5), 0.0);
        // merging only-empty inputs must not panic (from_centroids([]) would panic if called directly)
        let merged = LatencyDigest::merge(&[LatencyDigest::new(), LatencyDigest::new()]);
        assert_eq!(merged.quantile(0.5), 0.0);
    }

    #[test]
    fn uniques_merge_is_union() {
        let mut a = Uniques::new();
        for i in 0..1000u32 {
            a.add_ip(IpAddr::V4(Ipv4Addr::from(i)));
        }
        let mut b = Uniques::new();
        for i in 500..1500u32 {
            b.add_ip(IpAddr::V4(Ipv4Addr::from(i)));
        }
        a.merge_from(&b);
        let count = a.count() as f64;
        let expected = 1500.0;
        let error = (count - expected).abs() / expected;
        assert!(
            error < 0.02,
            "merged count {count} too far from expected {expected} (error {error})"
        );
    }

    #[test]
    fn topn_merge_then_cap_preserves_tail() {
        let mut a = TopN::default();
        a.add("x", 3, 30);
        a.add("y", 1, 10);
        let mut b = TopN::default();
        b.add("x", 1, 10);
        b.add("y", 2, 20);
        b.add("z", 1, 10);
        a.merge(&b);
        a.cap(2);
        assert_eq!(a.counts.get("x").unwrap().0, 4); // merged before cap
        assert_eq!(a.counts.get("y").unwrap().0, 3);
        assert!(!a.counts.contains_key("z"));
        assert_eq!(a.other.0, 1); // z folded into __other__
    }

    /// Keys come off the wire (a path, a `Referer`, a CF header) with no
    /// upstream length bound, so an attacker could otherwise pin arbitrarily
    /// large `String`s in the map for a whole window.
    #[test]
    fn topn_truncates_oversized_keys() {
        let mut t = TopN::default();
        let huge = "a".repeat(MAX_KEY_BYTES * 4);
        t.add(&huge, 1, 10);

        let (key, _) = t.counts.iter().next().unwrap();
        assert_eq!(key.len(), MAX_KEY_BYTES);

        // Two keys sharing their first MAX_KEY_BYTES bytes collapse into one
        // line item, which is the intended reporting behaviour.
        t.add(&format!("{huge}different-tail"), 1, 10);
        assert_eq!(t.counts.len(), 1);
        assert_eq!(t.counts.values().next().unwrap().0, 2);
    }

    /// Truncation must land on a character boundary — slicing a `&str`
    /// mid-codepoint panics, and these keys are arbitrary bytes from the wire.
    #[test]
    fn topn_truncates_multibyte_keys_without_panicking() {
        // "€" is 3 bytes, so no multiple of 3 lands exactly on 512: the cut
        // has to be found, not assumed.
        let mut t = TopN::default();
        let key = "€".repeat(MAX_KEY_BYTES);
        t.add(&key, 1, 10);

        let stored = t.counts.keys().next().unwrap();
        assert!(stored.len() <= MAX_KEY_BYTES);
        assert!(stored.len() > MAX_KEY_BYTES - 3, "should fill the budget");
        // Round-trips as valid UTF-8, i.e. nothing was split.
        assert!(stored.chars().all(|c| c == '€'));
    }

    /// `cap` normally runs once per window, at drain time; until then the map
    /// is unbounded and a flood of distinct attacker-chosen keys can grow it
    /// freely for a full minute. `add_bounded` trims mid-window instead.
    #[test]
    fn add_bounded_caps_growth_within_the_window() {
        const TOPN: usize = 10;
        let mut t = TopN::default();

        for i in 0..10_000u64 {
            t.add_bounded(&format!("/k{i}"), 1, 1, TOPN);
            assert!(
                t.counts.len() <= TOPN * SOFT_CAP_TRIGGER,
                "map grew past the soft cap at key {i}: {}",
                t.counts.len()
            );
        }

        // Nothing is lost, only demoted: evicted keys land in `__other__`.
        let kept: u64 = t.counts.values().map(|(reqs, _)| reqs).sum();
        assert_eq!(kept + t.other.0, 10_000);
    }

    /// The soft cap must be invisible under normal cardinality — an app with
    /// fewer distinct keys than the trigger behaves exactly as before.
    #[test]
    fn add_bounded_is_a_no_op_below_the_trigger() {
        const TOPN: usize = 50;
        let mut t = TopN::default();
        for i in 0..TOPN * SOFT_CAP_TRIGGER {
            t.add_bounded(&format!("/k{i}"), 1, 1, TOPN);
        }
        assert_eq!(t.counts.len(), TOPN * SOFT_CAP_TRIGGER);
        assert_eq!(t.other, (0, 0), "nothing should have been demoted yet");
    }

    /// A configured top-N of 0 must not make the trigger 0 and fold every
    /// single key straight into `__other__`.
    #[test]
    fn add_bounded_tolerates_a_zero_topn() {
        let mut t = TopN::default();
        t.add_bounded("/a", 1, 1, 0);
        assert_eq!(t.counts.get("/a").unwrap().0, 1);
    }

    #[test]
    fn uniques_roundtrip() {
        let mut a = Uniques::new();
        for i in 0..250u32 {
            a.add_ip(IpAddr::V4(Ipv4Addr::from(i)));
        }
        let before = a.count();
        let mut restored = Uniques::from_bytes(&a.to_bytes()).unwrap();
        let after = restored.count();
        assert!(
            (before as i64 - after as i64).abs() <= 1,
            "roundtrip changed count: {before} -> {after}"
        );
    }

    /// A corrupted BLOB that decodes to a structurally valid but
    /// semantically empty `Vec<CentroidData>` (every entry has
    /// `weight == 0.0`) must not panic in `TDigest::from_centroids`'s
    /// internal `assert!(!centroids.is_empty())` after its own filtering.
    /// `from_bytes` must filter these out itself and fall back to the empty
    /// representation.
    #[test]
    fn latency_from_bytes_all_zero_weight_centroids_does_not_panic() {
        let bad_data = vec![
            CentroidData {
                mean: 1.0,
                weight: 0.0,
            },
            CentroidData {
                mean: 2.0,
                weight: 0.0,
            },
        ];
        let bad_bytes = postcard::to_stdvec(&bad_data).unwrap();

        let restored = LatencyDigest::from_bytes(&bad_bytes).unwrap();
        assert!(restored.0.is_none());
        assert_eq!(restored.quantile(0.5), 0.0);
    }

    /// A NaN-mean centroid is also filtered out (mirrors tdigests' own
    /// `!c.mean.is_nan()` predicate), independent of weight validity.
    #[test]
    fn latency_from_bytes_nan_mean_centroid_does_not_panic() {
        let bad_data = vec![CentroidData {
            mean: f64::NAN,
            weight: 1.0,
        }];
        let bad_bytes = postcard::to_stdvec(&bad_data).unwrap();

        let restored = LatencyDigest::from_bytes(&bad_bytes).unwrap();
        assert!(restored.0.is_none());
    }

    /// A mix of valid and invalid centroids keeps only the valid ones
    /// instead of failing the whole decode.
    #[test]
    fn latency_from_bytes_filters_invalid_keeps_valid() {
        let data = vec![
            CentroidData {
                mean: 5.0,
                weight: 0.0, // invalid, dropped
            },
            CentroidData {
                mean: 10.0,
                weight: 1.0, // valid, kept
            },
        ];
        let bytes = postcard::to_stdvec(&data).unwrap();

        let restored = LatencyDigest::from_bytes(&bytes).unwrap();
        assert!(restored.0.is_some());
        assert!((restored.quantile(0.5) - 10.0).abs() < 1e-9);
    }

    /// A sketch persisted with a different HLL precision than the crate's
    /// current `HLL_PRECISION` (e.g. from corruption, or a pre-change row
    /// after a future `HLL_PRECISION` bump) must be rejected at decode time
    /// with an `Err`, not accepted and later panic inside `merge_from`'s
    /// `.expect` (now removed) or misbehave in `add_ip`/`count`.
    #[test]
    fn uniques_from_bytes_rejects_incompatible_precision() {
        let other_precision_hll: HllType =
            HyperLogLogPlus::new(HLL_PRECISION + 1, HllHasherBuilder::default())
                .expect("valid precision within 4..=18");
        let bytes = postcard::to_stdvec(&other_precision_hll).unwrap();

        let result = Uniques::from_bytes(&bytes);
        assert!(
            result.is_err(),
            "expected incompatible-precision sketch to be rejected"
        );
    }

    /// Defense-in-depth: even if an incompatible sketch somehow reaches
    /// `merge_from` directly (bypassing `from_bytes`'s validation), it must
    /// degrade gracefully (skip the merge) rather than panic.
    #[test]
    fn uniques_merge_from_incompatible_precision_does_not_panic() {
        let mut a = Uniques::new();
        a.add_ip(IpAddr::V4(Ipv4Addr::from(1u32)));
        let before = a.count();

        let other_precision_hll: HllType =
            HyperLogLogPlus::new(HLL_PRECISION + 1, HllHasherBuilder::default())
                .expect("valid precision within 4..=18");
        let incompatible = Uniques(other_precision_hll);

        // Must not panic.
        a.merge_from(&incompatible);
        assert_eq!(a.count(), before, "incompatible merge should be a no-op");
    }
}
