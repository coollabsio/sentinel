use super::*;

fn stats_row(
    bucket: i64,
    app: &str,
    host: &str,
    requests: i64,
    tdigest: Vec<u8>,
    hll: Vec<u8>,
) -> StatsRow {
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
        latency_tdigest: tdigest,
        uniques_hll: hll,
    }
}

/// Design spec §9: `wal_autocheckpoint=0` ([`AnalyticsStore::checkpoint`]'s
/// timed `wal_checkpoint(TRUNCATE)` owns checkpointing instead) and
/// `auto_vacuum=INCREMENTAL` (reported back as `2`) must both actually
/// take effect on the writer connection, not just be sent and ignored.
#[test]
fn writer_pragmas_take_effect() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let (autocheckpoint, auto_vacuum) = s
        .with_conn(|conn| {
            let autocheckpoint: i64 =
                conn.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))?;
            let auto_vacuum: i64 = conn.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
            Ok((autocheckpoint, auto_vacuum))
        })
        .unwrap();
    assert_eq!(
        autocheckpoint, 0,
        "automatic checkpointing must be disabled; a later task's timed \
         wal_checkpoint(TRUNCATE) owns it instead"
    );
    assert_eq!(
        auto_vacuum, 2,
        "auto_vacuum must be INCREMENTAL (SQLite reports this mode as 2)"
    );
    // busy_timeout has no readback pragma in rusqlite; init_conn sets it
    // via `conn.busy_timeout(Duration::from_secs(5))`, mirroring the
    // reader connection's setting above.
}

/// With `wal_autocheckpoint` disabled, writes accumulate in the `-wal` file
/// and nothing reclaims it on the write path — [`AnalyticsStore::checkpoint`]
/// is the only thing that does. After a batch of flushes the WAL is non-empty;
/// a checkpoint truncates it back to zero. This is the regression guard for the
/// unbounded-WAL-growth bug: without the timed checkpoint the file only ever
/// grows.
#[test]
fn checkpoint_truncates_the_wal() {
    let dir = std::env::temp_dir().join(format!("sentinel-traffic-wal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("analytics.sqlite");
    let wal = dir.join("analytics.sqlite-wal");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal);

    {
        let s = AnalyticsStore::open(&path).unwrap();
        // Enough separate commits that the WAL definitely holds pages.
        for b in 0..50i64 {
            let stats = vec![stats_row(b * 60_000, "a", "h", 1, vec![1, 2], vec![3, 4])];
            s.flush_window(&stats, &[], &[]).unwrap();
        }
        let grew = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert!(
            grew > 0,
            "writes with auto-checkpoint off must leave a non-empty WAL"
        );

        // No reader is active here, so TRUNCATE runs to completion.
        s.checkpoint().unwrap();
        let after = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
        assert_eq!(
            after, 0,
            "wal_checkpoint(TRUNCATE) must truncate the -wal file back to zero"
        );
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(dir.join("analytics.sqlite-shm"));
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn flush_and_read_back() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let stats = vec![stats_row(60_000, "a", "h", 5, vec![1, 2], vec![3, 4])];
    s.flush_window(&stats, &[], &[]).unwrap();
    let got = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].requests, 5);
    assert_eq!(got[0].latency_tdigest, vec![1, 2]);
}

/// Two flushes of the same (bucket, app, host): `ON CONFLICT` must sum
/// the count/byte columns but replace (not merge) the sketch blobs with
/// whatever the latest flush handed over.
#[test]
fn upsert_accumulates_on_conflict() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let first = stats_row(60_000, "a", "h", 5, vec![1, 2], vec![9, 9]);
    s.flush_window(&[first], &[], &[]).unwrap();

    let second = stats_row(60_000, "a", "h", 3, vec![7, 8], vec![10, 10]);
    s.flush_window(&[second], &[], &[]).unwrap();

    let got = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
    assert_eq!(
        got.len(),
        1,
        "same (bucket, app, host) must upsert in place, not duplicate"
    );
    assert_eq!(got[0].requests, 8);
    assert_eq!(got[0].bytes_in, 20);
    assert_eq!(got[0].bytes_out, 40);
    assert_eq!(got[0].s2xx, 8);
    assert_eq!(
        got[0].latency_tdigest,
        vec![7, 8],
        "sketch blobs replace, they don't concatenate/merge byte-wise"
    );
    assert_eq!(got[0].uniques_hll, vec![10, 10]);
}

#[test]
fn apps_lists_distinct() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let rows = vec![
        stats_row(60_000, "a", "h1", 1, vec![], vec![]),
        stats_row(60_000, "a", "h2", 1, vec![], vec![]),
        stats_row(60_000, "b", "h1", 1, vec![], vec![]),
        stats_row(120_000, "a", "h1", 1, vec![], vec![]),
    ];
    s.flush_window(&rows, &[], &[]).unwrap();
    let apps = s.apps().unwrap();
    assert_eq!(apps, vec!["a".to_string(), "b".to_string()]);
}

/// An app whose `1m` rows compaction has already consumed and deleted must
/// still be listed — its history lives in the coarser tiers and is fully
/// queryable, so omitting it from `apps()` would make it unreachable
/// through the UI while every other endpoint still answered for it.
///
/// The coarse rows are written directly rather than via `flush_window`
/// (which only ever writes `1m`), reproducing exactly the state
/// compaction leaves behind: coarse rows present, finer rows gone.
#[test]
fn apps_lists_apps_whose_data_only_survives_in_the_coarse_tiers() {
    let s = AnalyticsStore::open_in_memory().unwrap();

    // Recently active: still un-compacted, so present in `1m`.
    s.flush_window(
        &[stats_row(60_000, "recent", "h1", 1, vec![], vec![])],
        &[],
        &[],
    )
    .unwrap();
    // Idle for hours: compacted up to `1h`, its `1m` rows deleted.
    s.write_rows(
        Tier::H1,
        &[stats_row(3_600_000, "hourly-only", "h1", 1, vec![], vec![])],
        &[],
        &[],
    )
    .unwrap();
    // Idle for days: compacted all the way to `1d`.
    s.write_rows(
        Tier::D1,
        &[stats_row(86_400_000, "daily-only", "h1", 1, vec![], vec![])],
        &[],
        &[],
    )
    .unwrap();

    assert_eq!(
        s.apps().unwrap(),
        vec![
            "daily-only".to_string(),
            "hourly-only".to_string(),
            "recent".to_string()
        ],
        "every tier contributes; a 1m-only query would have returned just `recent`"
    );
}

fn path_row(bucket: i64, app: &str, path: &str, requests: i64) -> PathRow {
    PathRow {
        bucket,
        app: app.into(),
        path: path.into(),
        requests,
        bytes_out: 20,
        latency_tdigest: vec![1],
    }
}

fn breakdown_row(bucket: i64, app: &str, dim: &str, value: &str, requests: i64) -> BreakdownRow {
    BreakdownRow {
        bucket,
        app: app.into(),
        dimension: dim.into(),
        value: value.into(),
        requests,
        bytes_out: 20,
    }
}

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;

/// The `flush_window` -> `write_rows(Tier::M1, ..)` refactor must not
/// change `_1m` behavior: both entry points write the same rows to the
/// same tier, and both still upsert-accumulate on conflict.
#[test]
fn write_rows_m1_matches_flush_window() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[stats_row(60_000, "a", "h", 5, vec![1, 2], vec![3, 4])],
        &[path_row(60_000, "a", "/x", 5)],
        &[breakdown_row(60_000, "a", "country", "US", 5)],
    )
    .unwrap();
    s.write_rows(
        Tier::M1,
        &[stats_row(60_000, "a", "h", 3, vec![7, 8], vec![9, 9])],
        &[path_row(60_000, "a", "/x", 3)],
        &[breakdown_row(60_000, "a", "country", "US", 3)],
    )
    .unwrap();

    let stats = s.stats_range(Tier::M1, "a", 0, 120_000).unwrap();
    assert_eq!(stats.len(), 1, "write_rows must target the same _1m table");
    assert_eq!(stats[0].requests, 8, "counts accumulate identically");
    assert_eq!(stats[0].latency_tdigest, vec![7, 8], "sketch blobs replace");

    let paths = s.paths_range(Tier::M1, "a", 0, 120_000, 10).unwrap();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].requests, 8);

    let bd = s
        .breakdown_range(Tier::M1, "a", "country", 0, 120_000, 10)
        .unwrap();
    assert_eq!(bd.len(), 1);
    assert_eq!(bd[0].requests, 8);
}

/// `write_rows` addresses whichever tier it is handed; a `1h` write must
/// not leak into `1m` (or vice versa).
#[test]
fn write_rows_targets_the_requested_tier() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.write_rows(
        Tier::H1,
        &[stats_row(HOUR_MS, "a", "h", 7, vec![], vec![])],
        &[path_row(HOUR_MS, "a", "/x", 7)],
        &[breakdown_row(HOUR_MS, "a", "country", "US", 7)],
    )
    .unwrap();

    assert_eq!(s.stats_range(Tier::H1, "a", 0, i64::MAX).unwrap().len(), 1);
    assert!(
        s.stats_range(Tier::M1, "a", 0, i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.paths_range(Tier::H1, "a", 0, i64::MAX, 10).unwrap().len(),
        1
    );
    assert!(
        s.paths_range(Tier::M1, "a", 0, i64::MAX, 10)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.breakdown_range(Tier::H1, "a", "country", 0, i64::MAX, 10)
            .unwrap()
            .len(),
        1
    );
    assert!(
        s.breakdown_range(Tier::M1, "a", "country", 0, i64::MAX, 10)
            .unwrap()
            .is_empty()
    );
}

/// The `*_rows_between` bulk reads are unfiltered by app — compaction
/// needs every app's rows in the window, not one app's.
#[test]
fn rows_between_spans_all_apps_and_honors_bounds() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[
            stats_row(100, "a", "h", 1, vec![], vec![]),
            stats_row(200, "b", "h", 1, vec![], vec![]),
            stats_row(300, "c", "h", 1, vec![], vec![]),
        ],
        &[
            path_row(100, "a", "/x", 1),
            path_row(200, "b", "/y", 1),
            path_row(300, "c", "/z", 1),
        ],
        &[
            breakdown_row(100, "a", "country", "US", 1),
            breakdown_row(200, "b", "country", "DE", 1),
            breakdown_row(300, "c", "country", "FR", 1),
        ],
    )
    .unwrap();

    let stats = s.stats_rows_between(Tier::M1, i64::MIN, 300).unwrap();
    let apps: Vec<&str> = stats.iter().map(|r| r.app.as_str()).collect();
    assert_eq!(
        apps,
        vec!["a", "b"],
        "half-open [from, to): bucket 300 is excluded, all apps included"
    );

    let paths = s.paths_rows_between(Tier::M1, i64::MIN, 300).unwrap();
    assert_eq!(paths.len(), 2);
    let bd = s.breakdown_rows_between(Tier::M1, i64::MIN, 300).unwrap();
    assert_eq!(bd.len(), 2);

    assert_eq!(
        s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        3
    );
}

/// `delete_before` is strictly-older-than: the row exactly at the cutoff
/// survives, as do newer rows.
#[test]
fn delete_before_removes_only_strictly_older_rows() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[
            stats_row(100, "a", "h", 1, vec![], vec![]),
            stats_row(200, "a", "h", 1, vec![], vec![]),
            stats_row(300, "a", "h", 1, vec![], vec![]),
        ],
        &[
            path_row(100, "a", "/x", 1),
            path_row(200, "a", "/x", 1),
            path_row(300, "a", "/x", 1),
        ],
        &[
            breakdown_row(100, "a", "country", "US", 1),
            breakdown_row(200, "a", "country", "US", 1),
            breakdown_row(300, "a", "country", "US", 1),
        ],
    )
    .unwrap();

    let deleted = s.delete_before(Tier::M1, 200).unwrap();
    assert_eq!(deleted, 3, "one row per table, only the bucket-100 rows");

    let stats = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(
        stats.iter().map(|r| r.bucket).collect::<Vec<_>>(),
        vec![200, 300],
        "the row exactly at the cutoff must survive"
    );
    assert_eq!(
        s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        s.breakdown_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        2
    );
}

/// Per-table deletes are tier-scoped: deleting from `1m` leaves `1h`
/// and `1d` untouched.
#[test]
fn delete_before_is_tier_scoped() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    for tier in [Tier::M1, Tier::H1, Tier::D1] {
        s.write_rows(
            tier,
            &[stats_row(100, "a", "h", 1, vec![], vec![])],
            &[path_row(100, "a", "/x", 1)],
            &[breakdown_row(100, "a", "country", "US", 1)],
        )
        .unwrap();
    }

    assert_eq!(
        s.delete_before(Tier::M1, 200).unwrap(),
        3,
        "one row per table (stats + paths + breakdown), all in the 1m tier"
    );

    assert!(
        s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        1
    );
}

/// Retention applies a per-tier cutoff (`now - window`) across all three
/// tiers in one call, keeping rows at or newer than each cutoff.
#[test]
fn retention_applies_per_tier_cutoffs() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let now = 1_000 * DAY_MS;

    // 1m tier: 48h window -> 47h old survives, 49h old goes.
    s.write_rows(
        Tier::M1,
        &[
            stats_row(now - 47 * HOUR_MS, "a", "h", 1, vec![], vec![]),
            stats_row(now - 49 * HOUR_MS, "a", "h", 1, vec![], vec![]),
        ],
        &[
            path_row(now - 47 * HOUR_MS, "a", "/x", 1),
            path_row(now - 49 * HOUR_MS, "a", "/x", 1),
        ],
        &[],
    )
    .unwrap();
    // 1h tier: 30d window -> 29d survives, 31d goes.
    s.write_rows(
        Tier::H1,
        &[
            stats_row(now - 29 * DAY_MS, "a", "h", 1, vec![], vec![]),
            stats_row(now - 31 * DAY_MS, "a", "h", 1, vec![], vec![]),
        ],
        &[],
        &[],
    )
    .unwrap();
    // 1d tier: 395d window -> 394d survives, 396d goes.
    s.write_rows(
        Tier::D1,
        &[
            stats_row(now - 394 * DAY_MS, "a", "h", 1, vec![], vec![]),
            stats_row(now - 396 * DAY_MS, "a", "h", 1, vec![], vec![]),
        ],
        &[],
        &[breakdown_row(now - 396 * DAY_MS, "a", "country", "US", 1)],
    )
    .unwrap();

    let deleted = s.retention(now, 48, 30, 395).unwrap();
    assert_eq!(
        deleted, 5,
        "1m: 1 stats + 1 paths, 1h: 1 stats, 1d: 1 stats + 1 breakdown"
    );

    let m1 = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(m1.len(), 1);
    assert_eq!(m1[0].bucket, now - 47 * HOUR_MS);
    assert_eq!(
        s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        1
    );

    let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].bucket, now - 29 * DAY_MS);

    let d1 = s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(d1.len(), 1);
    assert_eq!(d1[0].bucket, now - 394 * DAY_MS);
    assert!(
        s.breakdown_rows_between(Tier::D1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
}

/// A retention window wide enough to predate the epoch must not overflow
/// into a positive cutoff (which would delete everything).
#[test]
fn retention_saturates_instead_of_overflowing() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.write_rows(
        Tier::D1,
        &[stats_row(0, "a", "h", 1, vec![], vec![])],
        &[],
        &[],
    )
    .unwrap();
    // u32::MAX days is ~1.1e7 years of milliseconds: the subtraction must
    // saturate at i64::MIN, not wrap.
    let deleted = s
        .retention(i64::MIN + 1, u32::MAX, u32::MAX, u32::MAX)
        .unwrap();
    assert_eq!(deleted, 0);
    assert_eq!(
        s.stats_rows_between(Tier::D1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        1
    );
}

/// `compact_window` is read + merge + write + delete in one transaction:
/// the callback sees the finer rows, and on return the coarse rows exist
/// and the finer ones in that window are gone.
#[test]
fn compact_window_reads_merges_writes_and_deletes() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[
            stats_row(HOUR_MS, "a", "h", 2, vec![1], vec![2]),
            stats_row(HOUR_MS + 60_000, "a", "h", 3, vec![3], vec![4]),
        ],
        &[path_row(HOUR_MS, "a", "/x", 4)],
        &[breakdown_row(HOUR_MS, "a", "country", "US", 6)],
    )
    .unwrap();

    let written = s
        .compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, dst| {
            assert_eq!(src.stats.len(), 2, "callback sees the finer rows");
            assert_eq!(src.paths.len(), 1);
            assert_eq!(src.breakdown.len(), 1);
            assert_eq!(src.len(), 4);
            assert!(dst.is_empty(), "nothing in the coarse bucket yet");
            // Trivial "merge": one summed stats row for the window.
            TierRows {
                stats: vec![stats_row(HOUR_MS, "a", "h", 5, vec![9], vec![9])],
                paths: src.paths,
                breakdown: src.breakdown,
            }
        })
        .unwrap();
    assert_eq!(written, 3, "1 stats + 1 paths + 1 breakdown");

    let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].requests, 5);
    assert!(
        s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty(),
        "consumed finer rows are deleted in the same transaction"
    );
    assert!(
        s.paths_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert!(
        s.breakdown_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
}

/// The delete is window-scoped, not `< to_bucket`: rows *older* than the
/// window belong to a coarse bucket that has not been compacted yet, and
/// dropping them here would lose them entirely.
#[test]
fn compact_window_deletes_only_its_own_window() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[
            stats_row(0, "a", "h", 1, vec![], vec![]),
            stats_row(HOUR_MS, "a", "h", 2, vec![], vec![]),
            stats_row(2 * HOUR_MS, "a", "h", 4, vec![], vec![]),
        ],
        &[],
        &[],
    )
    .unwrap();

    s.compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
        TierRows {
            stats: src.stats,
            ..Default::default()
        }
    })
    .unwrap();

    let left = s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(
        left.iter().map(|r| r.bucket).collect::<Vec<_>>(),
        vec![0, 2 * HOUR_MS],
        "the earlier and later buckets both survive for their own passes"
    );
}

/// An empty window writes nothing and reports zero.
#[test]
fn compact_window_on_an_empty_window_is_a_noop() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let written = s
        .compact_window(Tier::M1, Tier::H1, 0, HOUR_MS, |_, _| {
            panic!("merge must not run for an empty window")
        })
        .unwrap();
    assert_eq!(written, 0);
    assert!(
        s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
}

/// Atomicity, tested for real: a `BEFORE DELETE` trigger that raises
/// makes the delete half of `compact_window` fail *after* the coarse
/// rows have been inserted. The whole transaction must roll back — no
/// coarse rows, finer rows intact — so that the retry recomputes the
/// same roll-up instead of adding a second copy of it.
#[test]
fn compact_window_rolls_back_the_write_when_the_delete_fails() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[stats_row(HOUR_MS, "a", "h", 5, vec![1], vec![2])],
        &[path_row(HOUR_MS, "a", "/x", 5)],
        &[breakdown_row(HOUR_MS, "a", "country", "US", 5)],
    )
    .unwrap();

    s.execute_batch_for_test(
        "CREATE TRIGGER boom BEFORE DELETE ON traffic_stats_1m
         BEGIN SELECT RAISE(ABORT, 'simulated crash'); END;",
    )
    .unwrap();

    let err = s
        .compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
            TierRows {
                stats: src.stats,
                paths: src.paths,
                breakdown: src.breakdown,
            }
        })
        .unwrap_err();
    assert!(
        format!("{err}").contains("simulated crash"),
        "expected the injected failure, got {err}"
    );

    assert!(
        s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty(),
        "the coarse write must roll back with the failed delete, or the \
         retry would double-count this bucket"
    );
    assert!(
        s.paths_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert!(
        s.breakdown_rows_between(Tier::H1, i64::MIN, i64::MAX)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        s.stats_rows_between(Tier::M1, i64::MIN, i64::MAX)
            .unwrap()
            .len(),
        1,
        "the finer rows survive for the retry"
    );

    // With the fault removed, the retry produces exactly one coarse row.
    s.execute_batch_for_test("DROP TRIGGER boom").unwrap();
    s.compact_window(Tier::M1, Tier::H1, HOUR_MS, 2 * HOUR_MS, |src, _| {
        TierRows {
            stats: src.stats,
            paths: src.paths,
            breakdown: src.breakdown,
        }
    })
    .unwrap();
    let h1 = s.stats_rows_between(Tier::H1, i64::MIN, i64::MAX).unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].requests, 5, "retry recomputes, it does not add");
}

/// `distinct_buckets_before` unions all three tables, dedupes, sorts, and
/// honors the strict `< cutoff` bound.
#[test]
fn distinct_buckets_before_unions_all_three_tables() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    s.flush_window(
        &[
            stats_row(100, "a", "h", 1, vec![], vec![]),
            stats_row(100, "b", "h", 1, vec![], vec![]),
            stats_row(300, "a", "h", 1, vec![], vec![]),
        ],
        &[path_row(200, "a", "/x", 1)],
        &[breakdown_row(400, "a", "country", "US", 1)],
    )
    .unwrap();

    assert_eq!(
        s.distinct_buckets_before(Tier::M1, 400).unwrap(),
        vec![100, 200, 300],
        "deduped across apps, unioned across tables, cutoff exclusive"
    );
    assert_eq!(
        s.distinct_buckets_before(Tier::M1, i64::MAX).unwrap(),
        vec![100, 200, 300, 400]
    );
    assert!(
        s.distinct_buckets_before(Tier::H1, i64::MAX)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn paths_and_breakdown_flush_and_range() {
    let s = AnalyticsStore::open_in_memory().unwrap();
    let paths = vec![path_row(60_000, "a", "/x", 2)];
    let breakdown = vec![breakdown_row(60_000, "a", "country", "US", 2)];
    s.flush_window(&[], &paths, &breakdown).unwrap();

    let got_paths = s.paths_range(Tier::M1, "a", 0, 120_000, 10).unwrap();
    assert_eq!(got_paths.len(), 1);
    assert_eq!(got_paths[0].path, "/x");

    let got_breakdown = s
        .breakdown_range(Tier::M1, "a", "country", 0, 120_000, 10)
        .unwrap();
    assert_eq!(got_breakdown.len(), 1);
    assert_eq!(got_breakdown[0].value, "US");
}
