use super::*;
use std::net::{IpAddr, Ipv4Addr};

/// Postcard-encodes `(mean, weight)` centroids and decodes them back
/// through [`LatencyDigest::from_bytes`], exercising the corrupt-blob guard.
fn decode_centroids(centroids: &[(f64, f64)]) -> LatencyDigest {
    let data: Vec<CentroidData> = centroids
        .iter()
        .map(|&(mean, weight)| CentroidData { mean, weight })
        .collect();
    LatencyDigest::from_bytes(&postcard::to_stdvec(&data).unwrap()).unwrap()
}

/// A sketch built one precision step above `HLL_PRECISION`.
fn other_precision_hll() -> HllType {
    HyperLogLogPlus::new(HLL_PRECISION + 1, HllHasherBuilder::default())
        .expect("valid precision within 4..=18")
}

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
    let restored = decode_centroids(&[(1.0, 0.0), (2.0, 0.0)]);
    assert!(restored.0.is_none());
    assert_eq!(restored.quantile(0.5), 0.0);
}

/// A NaN-mean centroid is also filtered out (mirrors tdigests' own
/// `!c.mean.is_nan()` predicate), independent of weight validity.
#[test]
fn latency_from_bytes_nan_mean_centroid_does_not_panic() {
    let restored = decode_centroids(&[(f64::NAN, 1.0)]);
    assert!(restored.0.is_none());
}

/// A mix of valid and invalid centroids keeps only the valid ones
/// instead of failing the whole decode.
#[test]
fn latency_from_bytes_filters_invalid_keeps_valid() {
    // (5.0, 0.0) invalid and dropped; (10.0, 1.0) valid and kept.
    let restored = decode_centroids(&[(5.0, 0.0), (10.0, 1.0)]);
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
    let bytes = postcard::to_stdvec(&other_precision_hll()).unwrap();

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

    let incompatible = Uniques(other_precision_hll());

    // Must not panic.
    a.merge_from(&incompatible);
    assert_eq!(a.count(), before, "incompatible merge should be a no-op");
}
