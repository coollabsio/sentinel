#![forbid(unsafe_code)]

//! Probabilistic data structures (HyperLogLog, t-digest) for streaming analytics.
//!
//! Three mergeable sketch types, sized for periodic time-bucket compaction:
//! - [`LatencyDigest`]: approximate quantiles over request durations (t-digest).
//! - [`Uniques`]: approximate distinct-IP counting (HyperLogLog++).
//! - [`TopN`]: exact counts, capped to the top-N entries with an `__other__` bucket.

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault};
use std::net::IpAddr;

use foldhash::fast::RandomState;
use hyperloglogplus::{HyperLogLog, HyperLogLogPlus};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use siphasher::sip::SipHasher13;
use tdigests::{Centroid, TDigest};

use crate::TrafficError;

/// Max centroids a [`LatencyDigest`] retains after compression, bounding its
/// memory/serialized size independent of how many values were folded in.
const MAX_CENTROIDS: usize = 100;

/// Values [`LatencyDigest::add`] buffers before folding them into the
/// t-digest with one merge and compress, instead of one per value.
const ADD_BATCH: usize = 256;

/// HyperLogLog++ precision (number of register-index bits). Must be identical
/// across every [`Uniques`] instance that might ever be merged together.
const HLL_PRECISION: u8 = 14;

/// Deterministic hasher-builder for [`Uniques`]: seeds `SipHasher13` with a
/// fixed key via `BuildHasherDefault`, so serialized sketches are stable across
/// restarts and mergeable across instances (unlike `RandomState`, which
/// reseeds and has no serde impl). This wrapper exists only to supply the serde
/// impl `HyperLogLogPlus` requires on its hasher-builder field; a default-seeded
/// builder is stateless, so it (de)serializes as a no-op `()`.
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

/// Mergeable approximate-quantile sketch over non-negative, finite latencies.
#[derive(Default)]
pub struct LatencyDigest {
    /// `None` means "nothing folded yet", avoiding the `tdigests` crate's
    /// `from_values`/`from_centroids`, which both panic on empty input.
    digest: Option<TDigest>,
    /// Sanitized values not yet folded into `digest`. Every reader goes
    /// through [`Self::pool`] or [`Self::folded`], so none is ever skipped.
    pending: Vec<f64>,
}

/// Local serializable mirror of `tdigests::Centroid`, which has no serde impl.
#[derive(Serialize, Deserialize)]
struct CentroidData {
    mean: f64,
    weight: f64,
}

impl LatencyDigest {
    /// Creates an empty digest.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `values` to the digest, sanitizing away NaN/infinite/negative
    /// entries first. Values are buffered and folded in batches of
    /// [`ADD_BATCH`]: a merge and compress per value dominated ingest.
    pub fn add(&mut self, values: &[f64]) {
        self.pending.extend(
            values
                .iter()
                .copied()
                .filter(|v| v.is_finite() && *v >= 0.0),
        );
        if self.pending.len() >= ADD_BATCH {
            self.digest = Self::pool(std::slice::from_ref(self));
            self.pending.clear();
        }
    }

    /// Pools the centroids and buffered values of `sketches` into one fresh,
    /// compressed digest (cheaper and more accurate than repeated pairwise
    /// merges). `None` if all inputs are empty.
    fn pool(sketches: &[LatencyDigest]) -> Option<TDigest> {
        let all_centroids: Vec<Centroid> = sketches
            .iter()
            .flat_map(|s| {
                let folded = s.digest.iter().flat_map(|d| d.centroids().iter().cloned());
                folded.chain(s.pending.iter().map(|v| Centroid::new(*v, 1.0)))
            })
            .collect();

        if all_centroids.is_empty() {
            return None;
        }

        let mut digest = TDigest::from_centroids(all_centroids);
        digest.compress(MAX_CENTROIDS);
        Some(digest)
    }

    /// The digest with any buffered values folded in. Borrows when nothing
    /// is buffered (every decoded digest), so reads stay copy-free.
    fn folded(&self) -> Option<Cow<'_, TDigest>> {
        if self.pending.is_empty() {
            self.digest.as_ref().map(Cow::Borrowed)
        } else {
            Self::pool(std::slice::from_ref(self)).map(Cow::Owned)
        }
    }

    /// Merges digests into one, including their buffered values. Empty if
    /// all inputs are.
    pub fn merge(sketches: &[LatencyDigest]) -> LatencyDigest {
        LatencyDigest {
            digest: Self::pool(sketches),
            pending: Vec::new(),
        }
    }

    /// Estimates the value at quantile `q` (0.0..=1.0). Returns `0.0` for an
    /// empty digest.
    pub fn quantile(&self, q: f64) -> f64 {
        self.folded()
            .map_or(0.0, |digest| digest.estimate_quantile(q))
    }

    /// Postcard-encodes the digest's centroids. Returns an empty `Vec` for an
    /// empty digest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data: Vec<CentroidData> = match self.folded() {
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

    /// Decodes a digest from [`Self::to_bytes`]. An empty payload decodes to an
    /// empty digest, never calling `TDigest::from_centroids` with zero
    /// centroids. Also filters out `weight <= 0.0`/NaN-`mean` centroids first:
    /// `from_centroids` drops those with the same predicate and then `assert!`s
    /// the remainder is non-empty, so a corrupt-but-structurally-valid blob
    /// (all-invalid centroids) would panic — filtering here degrades to empty.
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
            return Ok(Self::new());
        }

        Ok(Self {
            digest: Some(TDigest::from_centroids(centroids)),
            pending: Vec::new(),
        })
    }
}

/// Mergeable approximate distinct-count sketch over client IPs. HyperLogLog++
/// with a deterministic hasher (see [`HllHasherBuilder`]) so serialized
/// sketches are stable across restarts and mergeable across instances.
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

    /// Merges `other`'s multiset into `self` (an exact set union, not an
    /// estimate). Both share `HLL_PRECISION` on the happy path. Defense in
    /// depth: an incompatible-precision sketch (which [`Self::from_bytes`]
    /// already rejects) that reaches here anyway is logged and skipped rather
    /// than panicking.
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

    /// Decodes a sketch from [`Self::to_bytes`].
    ///
    /// `HyperLogLogPlus`'s derived `Deserialize` does not validate `precision`
    /// (only `new()` does), so a corrupt or stale-`HLL_PRECISION` blob could
    /// otherwise later panic or misbehave in `merge`/`add_ip`/`count`. Guard by
    /// probing a merge against a fresh known-good sketch: `merge` is the one op
    /// that validates precision, so a successful probe proves it safe to use.
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

/// Longest aggregation key retained, in bytes. Keys are attacker-controlled
/// (a path, `Referer`, or CF header) with no upstream length bound, so without
/// this a request could pin an arbitrarily large `String` in the map for a
/// window. 512 is well above any path/header worth distinguishing in a top-N.
pub const MAX_KEY_BYTES: usize = 512;

/// Multiple of `topn` at which [`TopN::add_bounded`] trims mid-window.
pub(crate) const SOFT_CAP_TRIGGER: usize = 8;

/// Multiple of `topn` that a mid-window trim keeps. See
/// [`TopN::add_bounded`] for why this is wider than `topn` itself.
const SOFT_CAP_KEEP: usize = 4;

/// Truncate `key` to at most [`MAX_KEY_BYTES`], on a UTF-8 char boundary
/// (slicing mid-codepoint panics, and these keys are arbitrary wire bytes).
/// Borrows unchanged in the common case.
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
    /// key -> (requests, bytes_out). foldhash, not SipHash: this map takes
    /// several lookups per event. The hasher is not serialized.
    pub counts: HashMap<String, (u64, u64), RandomState>,
    /// Aggregate (requests, bytes_out) for keys evicted by [`Self::cap`].
    pub other: (u64, u64),
}

impl TopN {
    /// Adds `reqs`/`bytes` to `key`'s running totals, truncating `key` to
    /// [`MAX_KEY_BYTES`] first (wire values have no upstream length bound).
    pub fn add(&mut self, key: &str, reqs: u64, bytes: u64) {
        let key = truncate_key(key);
        // Look up by the borrowed key first: on the common hit path (a key
        // already seen this window) this allocates nothing, where an
        // `entry(key.to_string())` would allocate an owned key on every call.
        if let Some(entry) = self.counts.get_mut(key) {
            entry.0 += reqs;
            entry.1 += bytes;
        } else {
            self.counts.insert(key.to_string(), (reqs, bytes));
        }
    }

    /// [`Self::add`], plus a soft cap that bounds the map *within* the window,
    /// not only at drain time — otherwise a flood of distinct attacker-chosen
    /// keys grows it unbounded for a whole minute. Keeps `counts.len()` under
    /// `topn ×`[`SOFT_CAP_TRIGGER`], trimming to `topn ×`[`SOFT_CAP_KEEP`] (not
    /// `topn`) so a mid-table key that leads by end-of-window can still get
    /// there. Below the trigger this is exactly [`Self::add`].
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
mod tests;
