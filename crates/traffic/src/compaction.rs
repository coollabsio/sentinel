#![forbid(unsafe_code)]

//! Tier compaction: rolls `1m` rows up into `1h`, and `1h` into `1d`.
//!
//! Lives in this crate rather than on `AnalyticsStore` because merging the
//! persisted sketch BLOBs needs [`crate::sketches`] — and `traffic` already
//! depends on `store`, so the reverse edge would be a dependency cycle. The
//! store side contributes only raw primitives (`*_rows_between`,
//! `write_rows`, `delete_*_before`).
//!
//! Each call is a full sweep of whatever finer-tier rows exist strictly
//! before `now`: read, group by the coarser bucket, merge, write the coarser
//! rows, delete the consumed finer ones. There is no watermark — the delete
//! *is* the watermark — so a caller can invoke these on any cadence.

use std::collections::HashMap;

use foldhash::fast::RandomState;
use store::traffic::{AnalyticsStore, BreakdownRow, PathRow, StatsRow, Tier};

use crate::TrafficError;
use crate::sketches::{LatencyDigest, TopN, Uniques};

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// Top-N cap re-applied to every `(bucket, app, dimension)` breakdown group
/// after a compaction merge. (Paths are not re-capped: they arrive already
/// capped per finer bucket, and their rows carry a per-path digest that has
/// nowhere to fold into an `__other__` row.)
///
/// Deliberately larger than the ingestion-side cap (`TRAFFIC_TOPN`, default
/// 50, and 200 at the high end of what's configured in practice): compaction
/// must never be the narrower funnel, or a value that survived in every
/// contributing finer bucket could still be discarded on the way up. A
/// coarse bucket unions up to 60 finer buckets, so its key set is legitimately
/// wider than any single one of them.
const COMPACTION_TOPN: usize = 200;

/// Rolls every `1m` row older than `now` up into the `1h` tier. Returns the
/// number of coarser rows written (stats + paths + breakdown).
pub fn compact_1m_to_1h(store: &AnalyticsStore, now: i64) -> Result<usize, TrafficError> {
    compact_tier(store, Tier::M1, Tier::H1, floor_hour, now, COMPACTION_TOPN)
}

/// Rolls every `1h` row older than `now` up into the `1d` tier. Returns the
/// number of coarser rows written (stats + paths + breakdown).
pub fn compact_1h_to_1d(store: &AnalyticsStore, now: i64) -> Result<usize, TrafficError> {
    compact_tier(store, Tier::H1, Tier::D1, floor_day, now, COMPACTION_TOPN)
}

/// Floors a millisecond timestamp to its containing UTC hour.
///
/// `div_euclid`, not `/`: truncating division rounds negative (pre-epoch)
/// timestamps *towards* zero, i.e. into the following bucket.
fn floor_hour(bucket: i64) -> i64 {
    bucket.div_euclid(HOUR_MS) * HOUR_MS
}

/// Floors a millisecond timestamp to its containing UTC day.
fn floor_day(bucket: i64) -> i64 {
    bucket.div_euclid(DAY_MS) * DAY_MS
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

/// Reads every `from_tier` row strictly older than `now`, merges it into
/// `to_tier` buckets (via `floor`), writes the result, and deletes the
/// consumed rows. Returns the number of coarser rows written.
///
/// `now` is the single upper bound used for both the read and the delete, so
/// a flush that commits while compaction is running is neither compacted nor
/// dropped — it is simply left for the next sweep.
fn compact_tier(
    store: &AnalyticsStore,
    from_tier: Tier,
    to_tier: Tier,
    floor: fn(i64) -> i64,
    now: i64,
    topn: usize,
) -> Result<usize, TrafficError> {
    let src_stats = store.stats_rows_between(from_tier, i64::MIN, now)?;
    let src_paths = store.paths_rows_between(from_tier, i64::MIN, now)?;
    let src_breakdown = store.breakdown_rows_between(from_tier, i64::MIN, now)?;

    if src_stats.is_empty() && src_paths.is_empty() && src_breakdown.is_empty() {
        return Ok(0);
    }

    let stats = merge_stats(src_stats, floor);
    let paths = merge_paths(src_paths, floor);
    let breakdown = merge_breakdown(src_breakdown, floor, topn);

    store.write_rows(to_tier, &stats, &paths, &breakdown)?;

    store.delete_stats_before(from_tier, now)?;
    store.delete_paths_before(from_tier, now)?;
    store.delete_breakdown_before(from_tier, now)?;

    Ok(stats.len() + paths.len() + breakdown.len())
}

/// Groups by `(floor(bucket), app, host)`: counters sum, latency digests are
/// pooled into a single [`LatencyDigest::merge`], and the HLLs are unioned.
fn merge_stats(rows: Vec<StatsRow>, floor: fn(i64) -> i64) -> Vec<StatsRow> {
    let mut groups: HashMap<(i64, String, String), StatsAcc, RandomState> = HashMap::default();

    for row in rows {
        let acc = groups
            .entry((floor(row.bucket), row.app, row.host))
            .or_default();
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
        .map(|((bucket, app, host), acc)| StatsRow {
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
            // Both columns are NOT NULL: a group whose every sketch failed to
            // decode still writes an empty-but-valid sketch, so the next tier
            // up can decode it.
            uniques_hll: acc.uniques.unwrap_or_default().to_bytes(),
        })
        .collect()
}

/// Groups by `(floor(bucket), app, path)`.
fn merge_paths(rows: Vec<PathRow>, floor: fn(i64) -> i64) -> Vec<PathRow> {
    let mut groups: HashMap<(i64, String, String), PathAcc, RandomState> = HashMap::default();

    for row in rows {
        let acc = groups
            .entry((floor(row.bucket), row.app, row.path))
            .or_default();
        acc.requests += row.requests;
        acc.bytes_out += row.bytes_out;
        if let Some(digest) = decode_digest(&row.latency_tdigest) {
            acc.digests.push(digest);
        }
    }

    groups
        .into_iter()
        .map(|((bucket, app, path), acc)| PathRow {
            bucket,
            app,
            path,
            requests: acc.requests,
            bytes_out: acc.bytes_out,
            latency_tdigest: LatencyDigest::merge(&acc.digests).to_bytes(),
        })
        .collect()
}

/// Groups by `(floor(bucket), app, dimension)` — deliberately *not* by
/// `value`: each group rebuilds a full-resolution [`TopN`] from its rows and
/// is re-capped once, so a value just outside the cut in every contributing
/// finer bucket can still be reunited above it here.
///
/// An incoming `value == "__other__"` row is the previous tier's overflow
/// bucket, so it is added to [`TopN::other`] directly. Routing it through
/// [`TopN::add`] would instead create a literal `"__other__"` key in
/// `counts`, where it would compete for a top-N slot against real values
/// (possibly evicting one) and could then be emitted twice — once from
/// `counts` and once from `other` — colliding on the coarser table's primary
/// key.
fn merge_breakdown(
    rows: Vec<BreakdownRow>,
    floor: fn(i64) -> i64,
    topn: usize,
) -> Vec<BreakdownRow> {
    let mut groups: HashMap<(i64, String, String), TopN, RandomState> = HashMap::default();

    for row in rows {
        let entry = groups
            .entry((floor(row.bucket), row.app, row.dimension))
            .or_default();
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
    for ((bucket, app, dimension), mut top) in groups {
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
/// corrupt BLOB. Failing the whole sweep instead would be worse than lossy:
/// compaction deletes what it consumes, so an undecodable row would block
/// every later sweep forever.
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

        let written = compact_1m_to_1h(&s, hour + HOUR).unwrap();
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

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR).unwrap(), 3);
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
                PathRow {
                    bucket: hour,
                    app: "a".into(),
                    path: "/x".into(),
                    requests: 2,
                    bytes_out: 100,
                    latency_tdigest: digest_bytes(&[1.0, 2.0, 3.0]),
                },
                PathRow {
                    bucket: hour + MIN,
                    app: "a".into(),
                    path: "/x".into(),
                    requests: 3,
                    bytes_out: 200,
                    latency_tdigest: digest_bytes(&[8.0, 9.0, 10.0]),
                },
                PathRow {
                    bucket: hour + MIN,
                    app: "a".into(),
                    path: "/y".into(),
                    requests: 1,
                    bytes_out: 5,
                    latency_tdigest: digest_bytes(&[4.0]),
                },
            ],
            &[],
        )
        .unwrap();

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR).unwrap(), 2);
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

        compact_1m_to_1h(&s, hour + HOUR).unwrap();
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

        let written = compact_tier(&s, Tier::M1, Tier::H1, floor_hour, hour + HOUR, 2).unwrap();
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

        compact_tier(&s, Tier::M1, Tier::H1, floor_hour, hour + HOUR, 1).unwrap();
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

        assert_eq!(compact_1h_to_1d(&s, day + DAY).unwrap(), 1);
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

        assert_eq!(compact_1m_to_1h(&s, now).unwrap(), 1);
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
        assert_eq!(compact_1m_to_1h(&s, 100 * HOUR).unwrap(), 0);
        assert_eq!(compact_1h_to_1d(&s, 100 * DAY).unwrap(), 0);
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

        assert_eq!(compact_1m_to_1h(&s, hour + HOUR).unwrap(), 1);
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

    #[test]
    fn floors_are_utc_and_handle_pre_epoch_timestamps() {
        assert_eq!(floor_hour(100 * HOUR + 59 * MIN), 100 * HOUR);
        assert_eq!(floor_day(100 * DAY + 23 * HOUR), 100 * DAY);
        // Truncating division would round a negative timestamp *up*, putting
        // it in the wrong (later) bucket.
        assert_eq!(floor_hour(-MIN), -HOUR);
        assert_eq!(floor_day(-HOUR), -DAY);
    }
}
