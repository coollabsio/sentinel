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
mod tests;
