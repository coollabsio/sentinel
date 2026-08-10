#![forbid(unsafe_code)]

//! Tier compaction: rolls `1m` rows into `1h`, and `1h` into `1d`.
//! Sketch merging lives here to avoid a `store → traffic` dependency cycle;
//! `AnalyticsStore` owns the transaction and calls back through
//! [`AnalyticsStore::compact_window`]. Only closed buckets are processed, one
//! bucket per transaction, and each destination is recomputed from finer rows
//! plus its existing contents so late arrivals cannot clobber sketches.

use std::collections::HashMap;

use foldhash::fast::RandomState;
use store::traffic::{AnalyticsStore, BreakdownRow, PathRow, StatsRow, Tier, TierRows};

use crate::TrafficError;
use crate::sketches::{LatencyDigest, TopN, Uniques};

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Minimum top-N cap after compaction. It exceeds the ingestion default because
/// a coarse bucket unions many finer buckets.
const COMPACTION_TOPN: usize = 200;

/// Returns the compaction cap, widened by a larger configured top-N.
pub fn effective_topn(configured: usize) -> usize {
    configured.max(COMPACTION_TOPN)
}

/// Rolls every *closed* `1h`-aligned window of `1m` rows up into the `1h`
/// tier. The cap applied is [`effective_topn`] of `topn` (the configured
/// `TRAFFIC_TOPN`). Returns the number of coarser rows written.
pub fn compact_1m_to_1h(
    store: &AnalyticsStore,
    now: i64,
    topn: usize,
) -> Result<usize, TrafficError> {
    compact_tier(
        store,
        Tier::M1,
        Tier::H1,
        HOUR_MS,
        now,
        effective_topn(topn),
    )
}

/// Rolls every *closed* `1d`-aligned window of `1h` rows up into the `1d`
/// tier. See [`compact_1m_to_1h`].
pub fn compact_1h_to_1d(
    store: &AnalyticsStore,
    now: i64,
    topn: usize,
) -> Result<usize, TrafficError> {
    compact_tier(store, Tier::H1, Tier::D1, DAY_MS, now, effective_topn(topn))
}

/// Floors a millisecond timestamp to the start of its containing `width`-wide
/// bucket. `div_euclid`, not `/`: truncating division rounds negative
/// (pre-epoch) timestamps *towards* zero, i.e. into the following bucket.
fn floor_to(bucket: i64, width: i64) -> i64 {
    bucket.div_euclid(width) * width
}

/// Per-`(coarse bucket, app, host)` accumulator for the stats table.
#[derive(Default)]
struct StatsAcc {
    requests: i64,
    bytes_in: i64,
    bytes_out: i64,
    s2xx: i64,
    s3xx: i64,
    s4xx: i64,
    s5xx: i64,
    digests: Vec<LatencyDigest>,
    uniques: Option<Uniques>,
}

/// Per-`(coarse bucket, app, path)` accumulator for the paths table.
#[derive(Default)]
struct PathAcc {
    requests: i64,
    bytes_out: i64,
    digests: Vec<LatencyDigest>,
}

/// Rolls every closed `width`-wide bucket of `from_tier` up into `to_tier`,
/// one bucket per transaction. Returns the number of coarser rows written.
///
/// The upper bound is `floor_to(now, width)`, so the still-open bucket `now`
/// falls inside is never touched. `cap` is the *effective* top-N — the public
/// entry points reconcile it against [`COMPACTION_TOPN`]; this applies it as
/// given so tests can exercise eviction at small values.
fn compact_tier(
    store: &AnalyticsStore,
    from_tier: Tier,
    to_tier: Tier,
    width: i64,
    now: i64,
    cap: usize,
) -> Result<usize, TrafficError> {
    let cutoff = floor_to(now, width);

    // Floor and dedupe finer buckets to find closed coarse buckets with work.
    let mut coarse: Vec<i64> = store
        .distinct_buckets_before(from_tier, cutoff)?
        .into_iter()
        .map(|b| floor_to(b, width))
        .collect();
    coarse.dedup();

    let mut written = 0;
    for start in coarse {
        // `start` is aligned and below the cutoff, so this window is closed.
        let end = start.saturating_add(width);
        // Include a prior destination on re-compaction to preserve late data.
        written += store.compact_window(from_tier, to_tier, start, end, |src, dst| TierRows {
            stats: merge_stats(src.stats, dst.stats, start),
            paths: merge_paths(src.paths, dst.paths, start, cap),
            breakdown: merge_breakdown(src.breakdown, dst.breakdown, start, cap),
        })?;
    }

    Ok(written)
}

/// Merges stats by `(app, host)`, summing counters and merging sketches.
fn merge_stats(rows: Vec<StatsRow>, existing: Vec<StatsRow>, bucket: i64) -> Vec<StatsRow> {
    let mut groups: HashMap<(String, String), StatsAcc, RandomState> = HashMap::default();

    for row in rows.into_iter().chain(existing) {
        let acc = groups.entry((row.app, row.host)).or_default();
        acc.requests += row.requests;
        acc.bytes_in += row.bytes_in;
        acc.bytes_out += row.bytes_out;
        acc.s2xx += row.s2xx;
        acc.s3xx += row.s3xx;
        acc.s4xx += row.s4xx;
        acc.s5xx += row.s5xx;

        if let Some(digest) = decode_digest(&row.latency_tdigest) {
            acc.digests.push(digest);
        }
        if let Some(uniques) = decode_uniques(&row.uniques_hll) {
            match &mut acc.uniques {
                Some(existing) => existing.merge_from(&uniques),
                None => acc.uniques = Some(uniques),
            }
        }
    }

    groups
        .into_iter()
        .map(|((app, host), acc)| StatsRow {
            bucket,
            app,
            host,
            requests: acc.requests,
            bytes_in: acc.bytes_in,
            bytes_out: acc.bytes_out,
            s2xx: acc.s2xx,
            s3xx: acc.s3xx,
            s4xx: acc.s4xx,
            s5xx: acc.s5xx,
            latency_tdigest: LatencyDigest::merge(&acc.digests).to_bytes(),
            // NOT NULL: write an empty-but-valid sketch even if none decoded,
            // so the next tier up can still decode it.
            uniques_hll: acc.uniques.unwrap_or_default().to_bytes(),
        })
        .collect()
}

/// Merges paths by `(app, path)` and re-caps each app's set. Overflow rows are
/// merged directly into `TopN::other` so they cannot compete with real paths.
fn merge_paths(
    rows: Vec<PathRow>,
    existing: Vec<PathRow>,
    bucket: i64,
    topn: usize,
) -> Vec<PathRow> {
    let mut groups: HashMap<(String, String), PathAcc, RandomState> = HashMap::default();
    // Per-app top-N by request count, kept alongside `groups` because the
    // surviving rows still need their merged per-path digest, which `TopN`
    // does not carry.
    let mut tops: HashMap<String, TopN, RandomState> = HashMap::default();

    for row in rows.into_iter().chain(existing) {
        let top = tops.entry(row.app.clone()).or_default();
        let reqs = row.requests.max(0) as u64;
        let bytes = row.bytes_out.max(0) as u64;
        if row.path == OTHER {
            top.other.0 += reqs;
            top.other.1 += bytes;
            continue;
        }
        top.add(&row.path, reqs, bytes);

        let acc = groups.entry((row.app, row.path)).or_default();
        acc.requests += row.requests;
        acc.bytes_out += row.bytes_out;
        if let Some(digest) = decode_digest(&row.latency_tdigest) {
            acc.digests.push(digest);
        }
    }

    for top in tops.values_mut() {
        top.cap(topn);
    }

    let mut out = Vec::new();
    for ((app, path), acc) in groups {
        // Evicted by the cap: its counters already live in `top.other`.
        if !tops.get(&app).is_some_and(|t| t.counts.contains_key(&path)) {
            continue;
        }
        out.push(PathRow {
            bucket,
            app,
            path,
            requests: acc.requests,
            bytes_out: acc.bytes_out,
            latency_tdigest: LatencyDigest::merge(&acc.digests).to_bytes(),
        });
    }
    for (app, top) in tops {
        if top.other.0 > 0 {
            out.push(PathRow {
                bucket,
                app,
                path: OTHER.to_string(),
                requests: top.other.0 as i64,
                bytes_out: top.other.1 as i64,
                latency_tdigest: LatencyDigest::new().to_bytes(),
            });
        }
    }
    out
}

/// Merges breakdown rows by `(app, dimension)` and re-ranks each full group.
/// Existing `__other__` rows go directly to the overflow counter.
fn merge_breakdown(
    rows: Vec<BreakdownRow>,
    existing: Vec<BreakdownRow>,
    bucket: i64,
    topn: usize,
) -> Vec<BreakdownRow> {
    let mut groups: HashMap<(String, String), TopN, RandomState> = HashMap::default();

    for row in rows.into_iter().chain(existing) {
        let entry = groups.entry((row.app, row.dimension)).or_default();
        let reqs = row.requests.max(0) as u64;
        let bytes = row.bytes_out.max(0) as u64;
        if row.value == OTHER {
            entry.other.0 += reqs;
            entry.other.1 += bytes;
        } else {
            entry.add(&row.value, reqs, bytes);
        }
    }

    let mut out = Vec::new();
    for ((app, dimension), mut top) in groups {
        top.cap(topn);
        for (value, (reqs, bytes)) in top.counts {
            out.push(BreakdownRow {
                bucket,
                app: app.clone(),
                dimension: dimension.clone(),
                value,
                requests: reqs as i64,
                bytes_out: bytes as i64,
            });
        }
        if top.other.0 > 0 {
            out.push(BreakdownRow {
                bucket,
                app,
                dimension,
                value: OTHER.to_string(),
                requests: top.other.0 as i64,
                bytes_out: top.other.1 as i64,
            });
        }
    }
    out
}

/// Sentinel value for the aggregated tail of a capped top-N, matching
/// `aggregator::take_rollup`'s emitted row.
const OTHER: &str = "__other__";

/// Decodes a persisted latency digest, degrading to "no contribution" on a
/// corrupt BLOB. Failing the sweep would be worse than lossy: compaction
/// deletes what it consumes, so an undecodable row would block every later
/// sweep forever.
fn decode_digest(bytes: &[u8]) -> Option<LatencyDigest> {
    match LatencyDigest::from_bytes(bytes) {
        Ok(digest) => Some(digest),
        Err(err) => {
            tracing::warn!(error = %err, "compaction: skipping undecodable latency digest");
            None
        }
    }
}

/// Decodes a persisted HLL sketch, degrading to "no contribution" on a
/// corrupt BLOB. See [`decode_digest`].
fn decode_uniques(bytes: &[u8]) -> Option<Uniques> {
    match Uniques::from_bytes(bytes) {
        Ok(uniques) => Some(uniques),
        Err(err) => {
            tracing::warn!(error = %err, "compaction: skipping undecodable uniques sketch");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    const MIN: i64 = 60_000;
    const HOUR: i64 = 3_600_000;
    const DAY: i64 = 86_400_000;

    fn digest_bytes(values: &[f64]) -> Vec<u8> {
        let mut d = LatencyDigest::new();
        d.add(values);
        d.to_bytes()
    }

    fn uniques_bytes(ips: &[&str]) -> Vec<u8> {
        let mut u = Uniques::new();
        for ip in ips {
            u.add_ip(ip.parse::<IpAddr>().unwrap());
        }
        u.to_bytes()
    }

    fn stats_row(bucket: i64, app: &str, host: &str, requests: i64, latency: &[f64]) -> StatsRow {
        StatsRow {
            bucket,
            app: app.into(),
            host: host.into(),
            requests,
            bytes_in: 10,
            bytes_out: 20,
            s2xx: requests,
            s3xx: 0,
            s4xx: 0,
            s5xx: 0,
            latency_tdigest: digest_bytes(latency),
            uniques_hll: uniques_bytes(&[]),
        }
    }

    fn breakdown_row(bucket: i64, value: &str, requests: i64) -> BreakdownRow {
        BreakdownRow {
            bucket,
            app: "a".into(),
            dimension: "country".into(),
            value: value.into(),
            requests,
            bytes_out: requests * 10,
        }
    }

    fn path_row(
        bucket: i64,
        path: &str,
        requests: i64,
        bytes_out: i64,
        latency: &[f64],
    ) -> PathRow {
        PathRow {
            bucket,
            app: "a".into(),
            path: path.into(),
            requests,
            bytes_out,
            latency_tdigest: digest_bytes(latency),
        }
    }

    /// Two 1m buckets inside the same hour collapse into one 1h row whose
    /// counters are summed and whose latency digest genuinely spans both
    /// source buckets (p50 strictly inside the gap between their disjoint
    /// value ranges, not pinned to either one).
    #[test]
    fn compacts_two_minutes_into_one_hour_row() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;

        let mut a = stats_row(hour, "a", "h", 3, &[1.0, 2.0, 3.0]);
        a.uniques_hll = uniques_bytes(&["1.1.1.1", "1.1.1.2"]);
        let mut b = stats_row(hour + MIN, "a", "h", 3, &[8.0, 9.0, 10.0]);
        b.uniques_hll = uniques_bytes(&["1.1.1.2", "1.1.1.3"]);
        s.flush_window(&[a, b], &[], &[]).unwrap();

        let written = compact_1m_to_1h(&s, hour + HOUR, 50).unwrap();
        assert_eq!(written, 1, "one merged 1h stats row written");

        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bucket, hour, "bucket floored to the hour");
        assert_eq!(rows[0].requests, 6);
        assert_eq!(rows[0].bytes_in, 20);
        assert_eq!(rows[0].bytes_out, 40);
        assert_eq!(rows[0].s2xx, 6);

        let p50 = LatencyDigest::from_bytes(&rows[0].latency_tdigest)
            .unwrap()
            .quantile(0.5);
        assert!(
            p50 > 3.0 && p50 < 8.0,
            "merged p50 {p50} must span both source buckets: keeping only \
             bucket A would give ~3, only bucket B ~8"
        );

        let mut u = Uniques::from_bytes(&rows[0].uniques_hll).unwrap();
        assert_eq!(u.count(), 3, "HLL union of {{.1,.2}} and {{.2,.3}}");

        assert!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty(),
            "consumed 1m rows are deleted"
        );
    }

    /// Grouping is per `(coarse bucket, app, host)`: different hosts (and
    /// different apps) never get folded together.
    #[test]
    fn groups_stats_by_app_and_host() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[
                stats_row(hour, "a", "h1", 1, &[1.0]),
                stats_row(hour + MIN, "a", "h2", 2, &[1.0]),
                stats_row(hour + MIN, "b", "h1", 4, &[1.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(), 3);
        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|r| r.bucket == hour));
    }

    /// Paths merge on `(coarse bucket, app, path)`, summing counters and
    /// merging the per-path digest.
    #[test]
    fn compacts_paths_with_merged_digest() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[],
            &[
                path_row(hour, "/x", 2, 100, &[1.0, 2.0, 3.0]),
                path_row(hour + MIN, "/x", 3, 200, &[8.0, 9.0, 10.0]),
                path_row(hour + MIN, "/y", 1, 5, &[4.0]),
            ],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(), 2);
        let rows = s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        let x = rows.iter().find(|r| r.path == "/x").unwrap();
        assert_eq!(x.requests, 5);
        assert_eq!(x.bytes_out, 300);
        let p50 = LatencyDigest::from_bytes(&x.latency_tdigest)
            .unwrap()
            .quantile(0.5);
        assert!(p50 > 3.0 && p50 < 8.0, "merged per-path p50 {p50}");
        assert!(
            s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// `__other__` rows from the finer tier feed the rebuilt `TopN`'s
    /// dedicated `other` field, so two of them in the same coarse group sum
    /// into exactly one `__other__` row.
    #[test]
    fn other_rows_sum_into_a_single_other_row() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[],
            &[],
            &[
                breakdown_row(hour, "US", 5),
                breakdown_row(hour, "__other__", 2),
                breakdown_row(hour + MIN, "__other__", 3),
            ],
        )
        .unwrap();

        compact_1m_to_1h(&s, hour + HOUR, 50).unwrap();
        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(rows.len(), 2, "one US row + exactly one __other__ row");
        let other: Vec<_> = rows.iter().filter(|r| r.value == "__other__").collect();
        assert_eq!(other.len(), 1);
        assert_eq!(other[0].requests, 5, "2 + 3 summed");
        assert_eq!(other[0].bytes_out, 50);
        let us = rows.iter().find(|r| r.value == "US").unwrap();
        assert_eq!(us.requests, 5);
    }

    /// The load-bearing distinction: an incoming `__other__` row must NOT
    /// become a regular key in `counts` (i.e. `topn.add("__other__", ..)`
    /// must never be called). If it did, it would compete for a top-N slot
    /// and could evict a real value — here `__other__` (9) outranks `B` (8),
    /// so a buggy implementation drops `B` and emits two `__other__` rows
    /// that then collide (and sum) on the coarser tier's primary key.
    #[test]
    fn other_never_competes_for_a_topn_slot() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[],
            &[],
            &[
                breakdown_row(hour, "A", 10),
                breakdown_row(hour, "B", 8),
                breakdown_row(hour, "__other__", 9),
            ],
        )
        .unwrap();

        let written = compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR, 2).unwrap();
        assert_eq!(written, 3);

        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(rows.len(), 3, "A + B kept, one __other__ row");
        assert_eq!(rows.iter().find(|r| r.value == "A").unwrap().requests, 10);
        assert_eq!(
            rows.iter().find(|r| r.value == "B").unwrap().requests,
            8,
            "__other__ must not evict a real value from the top-N"
        );
        assert_eq!(
            rows.iter()
                .find(|r| r.value == "__other__")
                .unwrap()
                .requests,
            9,
            "carried through untouched, not merged with an evicted value"
        );
    }

    /// Real values evicted by the cap fold into `other`, on top of whatever
    /// `__other__` already carried in.
    #[test]
    fn capped_values_fold_into_the_existing_other_bucket() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[],
            &[],
            &[
                breakdown_row(hour, "A", 10),
                breakdown_row(hour, "B", 4),
                breakdown_row(hour, "C", 3),
                breakdown_row(hour, "__other__", 2),
            ],
        )
        .unwrap();

        compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR, 1).unwrap();
        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().find(|r| r.value == "A").unwrap().requests, 10);
        assert_eq!(
            rows.iter()
                .find(|r| r.value == "__other__")
                .unwrap()
                .requests,
            9,
            "B(4) + C(3) evicted, plus the incoming __other__(2)"
        );
    }

    /// 1h -> 1d floors to the UTC day boundary.
    #[test]
    fn compacts_hours_into_days() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let day = 100 * DAY;
        s.write_rows(
            Tier::H1,
            &[
                stats_row(day + HOUR, "a", "h", 2, &[1.0]),
                stats_row(day + 5 * HOUR, "a", "h", 3, &[2.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1h_to_1d(&s, day + DAY, 50).unwrap(), 1);
        let rows = s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bucket, day);
        assert_eq!(rows[0].requests, 5);
        assert!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// Rows at or after `now` are outside the compacted window: a flush that
    /// lands mid-compaction must be neither rolled up nor deleted.
    #[test]
    fn leaves_rows_at_or_after_now_untouched() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        let now = hour + HOUR;
        s.flush_window(
            &[
                stats_row(hour, "a", "h", 1, &[1.0]),
                stats_row(now, "a", "h", 7, &[1.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, now, 50).unwrap(), 1);
        let leftover = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(leftover.len(), 1);
        assert_eq!(leftover[0].bucket, now);
        assert_eq!(leftover[0].requests, 7);

        let coarse = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(coarse.len(), 1);
        assert_eq!(coarse[0].requests, 1);
    }

    #[test]
    fn empty_finer_tier_is_a_noop() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        assert_eq!(compact_1m_to_1h(&s, 100 * HOUR, 50).unwrap(), 0);
        assert_eq!(compact_1h_to_1d(&s, 100 * DAY, 50).unwrap(), 0);
        assert!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// A corrupt sketch BLOB must not abort (and thereby permanently wedge)
    /// compaction: the row's counters still roll up, only its sketch
    /// contribution is dropped.
    #[test]
    fn corrupt_sketch_blob_degrades_instead_of_failing() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        let mut bad = stats_row(hour, "a", "h", 4, &[1.0]);
        bad.latency_tdigest = vec![0xff, 0xff, 0xff];
        bad.uniques_hll = vec![0xff, 0xff, 0xff];
        s.flush_window(&[bad, stats_row(hour + MIN, "a", "h", 1, &[5.0])], &[], &[])
            .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(), 1);
        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows[0].requests, 5, "counters still roll up");
        let p50 = LatencyDigest::from_bytes(&rows[0].latency_tdigest)
            .unwrap()
            .quantile(0.5);
        assert!(
            (p50 - 5.0).abs() < 1e-9,
            "only the readable digest survives"
        );
        // The written HLL must still be decodable by the next compaction pass.
        assert!(Uniques::from_bytes(&rows[0].uniques_hll).is_ok());
    }

    /// A caller on a non-aligned cadence (hourly, firing at `H+3min`) must not
    /// compact the hour it is standing in (rule 1). With the floored bound,
    /// sweep one compacts nothing and sweep two takes the whole closed hour.
    #[test]
    fn non_aligned_cadence_never_compacts_a_half_open_hour() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;

        // Minutes 0..2 of hour H, all with fast latencies.
        s.flush_window(
            &[
                stats_row(hour, "a", "h", 1, &[1.0]),
                stats_row(hour + MIN, "a", "h", 1, &[1.0]),
                stats_row(hour + 2 * MIN, "a", "h", 1, &[1.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        // Sweep at H+3min: hour H is still open.
        assert_eq!(
            compact_1m_to_1h(&s, hour + 3 * MIN, 50).unwrap(),
            0,
            "the hour `now` falls inside must not be compacted yet"
        );
        assert_eq!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .len(),
            3,
            "and its 1m rows must be left in place, not consumed"
        );
        assert!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );

        // The rest of hour H arrives, with markedly slower latencies.
        s.flush_window(
            &[
                stats_row(hour + 4 * MIN, "a", "h", 1, &[100.0]),
                stats_row(hour + 30 * MIN, "a", "h", 1, &[100.0]),
                stats_row(hour + 58 * MIN, "a", "h", 1, &[100.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        // Sweep at H+1h+1min: hour H is closed now.
        assert_eq!(compact_1m_to_1h(&s, hour + HOUR + MIN, 50).unwrap(), 1);

        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bucket, hour);
        assert_eq!(rows[0].requests, 6, "all six minutes, counted once each");

        let digest = LatencyDigest::from_bytes(&rows[0].latency_tdigest).unwrap();
        assert!(
            (digest.quantile(0.0) - 1.0).abs() < 1e-6,
            "the first three minutes' latency data must survive: a digest \
             built from only the last three would start at 100, got {}",
            digest.quantile(0.0)
        );
        assert!(
            (digest.quantile(1.0) - 100.0).abs() < 1e-6,
            "and so must the last three's"
        );
        assert!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    /// Each closed coarse bucket is its own window: a backlog spanning
    /// several hours produces one row per hour, and no hour's data leaks
    /// into another's.
    #[test]
    fn a_multi_hour_backlog_compacts_one_hour_at_a_time() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[
                stats_row(hour + MIN, "a", "h", 1, &[1.0]),
                stats_row(hour + HOUR + MIN, "a", "h", 2, &[1.0]),
                // Hour H+2 is empty — it must simply not appear.
                stats_row(hour + 3 * HOUR + MIN, "a", "h", 4, &[1.0]),
            ],
            &[],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + 4 * HOUR, 50).unwrap(), 3);
        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(
            rows.iter()
                .map(|r| (r.bucket, r.requests))
                .collect::<Vec<_>>(),
            vec![(hour, 1), (hour + HOUR, 2), (hour + 3 * HOUR, 4),],
            "one row per non-empty hour, counters not pooled across hours"
        );
    }

    /// The write and the delete are one transaction, so a second sweep over
    /// already-compacted data finds nothing left to consume and changes
    /// nothing. (If they were separate calls, a crash between them would
    /// leave the finer rows behind for this second sweep to add a second
    /// time — the doubling this asserts against.)
    #[test]
    fn a_second_sweep_over_compacted_data_is_a_noop() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[stats_row(hour, "a", "h", 3, &[1.0])],
            &[path_row(hour, "/x", 3, 30, &[1.0])],
            &[breakdown_row(hour, "US", 3)],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(), 3);
        assert_eq!(
            compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(),
            0,
            "nothing left in the 1m tier to re-compact"
        );

        let stats = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].requests, 3, "not doubled by the second sweep");
        let paths = s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(paths[0].requests, 3);
        let bd = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(bd[0].requests, 3);
    }

    /// Paths are re-capped per `(coarse bucket, app)`, with the overflow
    /// folded into an `__other__` row carrying an empty digest — the same
    /// shape `aggregator::take_rollup` emits. Without this, an hour would
    /// hold the union of its 60 minutes' path sets, and a day the union of
    /// its 24 hours', growing without bound in the 395-day `1d` tier.
    #[test]
    fn paths_are_recapped_with_an_other_row() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        // Descending requests, so the cap keeps /p0 and /p1.
        let rows: Vec<PathRow> = (0..5)
            .map(|i| path_row(hour + i * MIN, &format!("/p{i}"), 100 - i, 10, &[1.0]))
            .collect();
        s.flush_window(&[], &rows, &[]).unwrap();

        compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR, 2).unwrap();

        let got = s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(got.len(), 3, "2 kept paths + 1 __other__ row");
        let kept: Vec<&str> = {
            let mut v: Vec<&str> = got
                .iter()
                .filter(|r| r.path != "__other__")
                .map(|r| r.path.as_str())
                .collect();
            v.sort_unstable();
            v
        };
        assert_eq!(kept, vec!["/p0", "/p1"], "the two busiest paths survive");

        let other = got.iter().find(|r| r.path == "__other__").unwrap();
        assert_eq!(
            other.requests,
            98 + 97 + 96,
            "/p2 + /p3 + /p4 folded into __other__"
        );
        assert_eq!(other.bytes_out, 30);
        assert!(
            LatencyDigest::from_bytes(&other.latency_tdigest).is_ok(),
            "the __other__ digest must be an empty-but-decodable sketch, not \
             a NULL or a corrupt blob"
        );
    }

    /// An incoming `__other__` path row is the finer tier's own overflow: it
    /// must go straight to the top-N's `other` bucket, never compete for a
    /// slot (where it could evict a real path) and never be emitted twice.
    #[test]
    fn incoming_other_path_rows_do_not_compete_for_a_slot() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        let mk = |path: &str, requests: i64| path_row(hour, path, requests, requests, &[1.0]);
        s.flush_window(&[], &[mk("/a", 10), mk("/b", 8), mk("__other__", 9)], &[])
            .unwrap();

        compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR, 2).unwrap();

        let got = s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(got.len(), 3, "/a + /b kept, exactly one __other__ row");
        assert_eq!(
            got.iter().find(|r| r.path == "/b").unwrap().requests,
            8,
            "__other__(9) must not evict the real path /b(8)"
        );
        assert_eq!(
            got.iter().find(|r| r.path == "__other__").unwrap().requests,
            9,
            "carried through untouched"
        );
    }

    /// Builds `n` distinct breakdown values in one 1m bucket.
    fn many_values(hour: i64, n: usize) -> Vec<BreakdownRow> {
        (0..n)
            .map(|i| breakdown_row(hour, &format!("v{i:04}"), (n - i) as i64))
            .collect()
    }

    /// A configured `TRAFFIC_TOPN` *above* the 200 floor must be honored, not
    /// silently truncated back to 200.
    #[test]
    fn a_configured_topn_above_the_floor_is_respected() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(&[], &[], &many_values(hour, 250)).unwrap();

        compact_1m_to_1h(&s, hour + HOUR, 300).unwrap();

        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(
            rows.len(),
            250,
            "a cap of 300 keeps all 250 values; truncating to COMPACTION_TOPN \
             would leave 200 + an __other__ row"
        );
        assert!(rows.iter().all(|r| r.value != "__other__"));
    }

    /// ...and a configured value *below* the floor is widened to it, so
    /// compaction is never the narrower funnel.
    #[test]
    fn a_configured_topn_below_the_floor_is_widened_to_it() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(&[], &[], &many_values(hour, 250)).unwrap();

        compact_1m_to_1h(&s, hour + HOUR, 50).unwrap();

        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(
            rows.len(),
            201,
            "capped at the COMPACTION_TOPN floor of 200, plus one __other__"
        );
        assert_eq!(rows.iter().filter(|r| r.value == "__other__").count(), 1);
    }

    /// The late-arrival regression (rule 3), and why [`compact_window`] reads
    /// its destination tier. Hour `H` is compacted at `H+1h`; then a late `1m`
    /// row for `H` lands and the next sweep re-compacts it. That second pass
    /// must merge into the existing coarse digest/HLL, not replace them with
    /// the straggler's — the old upsert summed counters but replaced the sketch
    /// columns, silently discarding 59 minutes of distribution.
    ///
    /// [`AnalyticsStore::compact_window`]: store::traffic::AnalyticsStore::compact_window
    #[test]
    fn a_late_finer_row_merges_into_the_existing_coarse_row() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;

        // Hour H as it is first seen: three minutes, all fast, three visitors.
        let mut early: Vec<StatsRow> = (0..3)
            .map(|i| stats_row(hour + i * MIN, "a", "h", 1, &[1.0]))
            .collect();
        early[0].uniques_hll = uniques_bytes(&["1.1.1.1"]);
        early[1].uniques_hll = uniques_bytes(&["1.1.1.2"]);
        early[2].uniques_hll = uniques_bytes(&["1.1.1.3"]);
        s.flush_window(
            &early,
            &[path_row(hour, "/x", 3, 30, &[1.0, 1.0, 1.0])],
            &[breakdown_row(hour, "US", 3)],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR, 50).unwrap(), 3);

        // ...and now H's last minute finally flushes, slow and from a fourth
        // visitor, into an hour that has already been rolled up.
        let mut late = stats_row(hour + 59 * MIN, "a", "h", 1, &[100.0]);
        late.uniques_hll = uniques_bytes(&["1.1.1.4"]);
        s.flush_window(
            &[late],
            &[path_row(hour + 59 * MIN, "/x", 1, 10, &[100.0])],
            &[breakdown_row(hour + 59 * MIN, "US", 1)],
        )
        .unwrap();

        // Second sweep: same coarse bucket, second visit.
        assert_eq!(compact_1m_to_1h(&s, hour + HOUR + 5 * MIN, 50).unwrap(), 3);

        let rows = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(rows.len(), 1, "still one row for hour H, not two");
        assert_eq!(rows[0].bucket, hour);
        assert_eq!(
            rows[0].requests, 4,
            "the three early minutes plus the late one, each counted once"
        );
        assert_eq!(rows[0].bytes_in, 40, "and no counter double-added");

        let digest = LatencyDigest::from_bytes(&rows[0].latency_tdigest).unwrap();
        assert!(
            (digest.quantile(0.0) - 1.0).abs() < 1e-6,
            "the already-compacted minutes' latency must survive the second \
             pass: a digest rebuilt from the late row alone starts at 100, \
             got {}",
            digest.quantile(0.0)
        );
        assert!(
            (digest.quantile(1.0) - 100.0).abs() < 1e-6,
            "and the late row's must be in there too, got {}",
            digest.quantile(1.0)
        );

        let mut uniques = Uniques::from_bytes(&rows[0].uniques_hll).unwrap();
        assert_eq!(
            uniques.count(),
            4,
            "the union of the three original visitors and the late one; \
             replacing the HLL with the late row's would report 1"
        );

        let paths = s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].requests, 4);
        assert_eq!(paths[0].bytes_out, 40);
        let path_digest = LatencyDigest::from_bytes(&paths[0].latency_tdigest).unwrap();
        assert!(
            (path_digest.quantile(0.0) - 1.0).abs() < 1e-6,
            "per-path digests are replaced on conflict too, got {}",
            path_digest.quantile(0.0)
        );
        assert!((path_digest.quantile(1.0) - 100.0).abs() < 1e-6);

        // Breakdown rows carry no sketch, so they were never corrupted — but
        // they must not double-count now that the coarse window is rewritten
        // wholesale rather than upserted into.
        let bd = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        assert_eq!(bd.len(), 1);
        assert_eq!(bd[0].requests, 4);
        assert_eq!(bd[0].bytes_out, 40);

        assert!(
            s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
                .unwrap()
                .is_empty(),
            "the late row is consumed like any other"
        );
    }

    /// Re-compacting a coarse bucket re-ranks its whole top-N rather than
    /// bolting the late value onto an already-capped set: with a cap of 2, a
    /// late value that outranks everything must push the previous runner-up
    /// into `__other__`, not become a third row.
    #[test]
    fn a_late_row_re_caps_the_coarse_bucket_instead_of_widening_it() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(
            &[],
            &[],
            &[
                breakdown_row(hour, "A", 10),
                breakdown_row(hour, "B", 8),
                breakdown_row(hour, "C", 3),
            ],
        )
        .unwrap();
        compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR, 2).unwrap();

        s.flush_window(&[], &[], &[breakdown_row(hour + 59 * MIN, "D", 100)])
            .unwrap();
        compact_tier(&s, Tier::M1, Tier::H1, HOUR, hour + HOUR + MIN, 2).unwrap();

        let rows = s
            .breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap();
        let mut got: Vec<(&str, i64)> = rows
            .iter()
            .map(|r| (r.value.as_str(), r.requests))
            .collect();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![("A", 10), ("D", 100), ("__other__", 11)],
            "D(100) and A(10) are the top 2; B(8) is demoted onto the \
             existing __other__(3)"
        );
    }

    /// A coarse bucket whose finer tier is empty is not touched at all — the
    /// merge never runs, so a bucket cannot be perturbed (its digests
    /// re-merged, its top-N re-capped) by a sweep that has nothing to add.
    #[test]
    fn a_sweep_with_nothing_to_add_leaves_the_coarse_row_byte_identical() {
        let s = AnalyticsStore::open_in_memory().unwrap();
        let hour = 100 * HOUR;
        s.flush_window(&[stats_row(hour, "a", "h", 3, &[1.0, 2.0, 3.0])], &[], &[])
            .unwrap();
        compact_1m_to_1h(&s, hour + HOUR, 50).unwrap();
        let before = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + 5 * HOUR, 50).unwrap(), 0);
        assert_eq!(
            s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap(),
            before
        );
    }

    #[test]
    fn floors_are_utc_and_handle_pre_epoch_timestamps() {
        assert_eq!(floor_to(100 * HOUR + 59 * MIN, HOUR), 100 * HOUR);
        assert_eq!(floor_to(100 * DAY + 23 * HOUR, DAY), 100 * DAY);
        // Truncating division would round a negative timestamp *up*, putting
        // it in the wrong (later) bucket.
        assert_eq!(floor_to(-MIN, HOUR), -HOUR);
        assert_eq!(floor_to(-HOUR, DAY), -DAY);
    }
}
