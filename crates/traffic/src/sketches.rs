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
    pub fn from_bytes(b: &[u8]) -> Result<Self, TrafficError> {
        let data: Vec<CentroidData> =
            postcard::from_bytes(b).map_err(|e| TrafficError::Codec(e.to_string()))?;

        if data.is_empty() {
            return Ok(Self(None));
        }

        let centroids: Vec<Centroid> = data
            .into_iter()
            .map(|c| Centroid {
                mean: c.mean,
                weight: c.weight,
            })
            .collect();
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

    /// Merges `other`'s multiset into `self`. Both sketches must share the
    /// same precision (guaranteed here since `HLL_PRECISION` is a single
    /// crate-wide constant); merge is exact (a true set union), not
    /// approximate on top of the estimate.
    pub fn merge_from(&mut self, other: &Uniques) {
        self.0
            .merge(&other.0)
            .expect("Uniques always uses the fixed HLL_PRECISION, so precision always matches");
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
    pub fn from_bytes(b: &[u8]) -> Result<Self, TrafficError> {
        let hll: HllType =
            postcard::from_bytes(b).map_err(|e| TrafficError::Codec(e.to_string()))?;
        Ok(Self(hll))
    }
}

impl Default for Uniques {
    fn default() -> Self {
        Self::new()
    }
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
    pub fn add(&mut self, key: &str, reqs: u64, bytes: u64) {
        let entry = self.counts.entry(key.to_string()).or_insert((0, 0));
        entry.0 += reqs;
        entry.1 += bytes;
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
}
