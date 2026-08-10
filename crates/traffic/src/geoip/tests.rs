use super::*;

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

fn default_settings() -> config::TrafficSettings {
    config::Config::load_for_test().traffic
}

fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// Builds a `.tar.gz` from `(path, contents)` members, in order.
fn targz(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for (name, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The MaxMind URL carries the operator's credential in a query
/// parameter, and that URL is logged on every load/refresh and embedded in
/// every `TrafficError::Download`. Nothing but the redacted form may reach
/// a log line.
#[test]
fn redact_url_masks_a_maxmind_license_key() {
    let url = maxmind_url("SUPERSECRET", "GeoLite2-Country");
    let redacted = redact_url(&url);

    assert!(
        !redacted.contains("SUPERSECRET"),
        "the credential leaked: {redacted}"
    );
    assert_eq!(
        redacted,
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=REDACTED&suffix=tar.gz",
        "every other parameter must survive so the log stays diagnostic"
    );

    // A key in trailing position (no following `&`) is masked too.
    assert_eq!(
        redact_url("https://example.com/db?license_key=SUPERSECRET"),
        "https://example.com/db?license_key=REDACTED"
    );

    // …and `Source` exposes only that form.
    let source = Source {
        url,
        archive: Archive::TarGz,
    };
    assert!(!source.redacted_url().contains("SUPERSECRET"));
}

/// Key-less URLs — the mirror, DB-IP, a custom `GEOIP_DB_URL` — must be
/// untouched, and borrowed rather than needlessly re-allocated.
#[test]
fn redact_url_leaves_keyless_urls_alone() {
    for url in [MIRROR_URL, &dbip_url(2026, 8), "https://example.com/x.mmdb"] {
        let redacted = redact_url(url);
        assert_eq!(redacted, url);
        assert!(
            matches!(redacted, Cow::Borrowed(_)),
            "a URL with no credential should not allocate: {url}"
        );
    }
}

#[test]
fn maxmind_url_format() {
    assert_eq!(
        maxmind_url("KEY", "GeoLite2-Country"),
        "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=KEY&suffix=tar.gz"
    );
}

#[test]
fn dbip_url_format() {
    assert_eq!(
        dbip_url(2026, 8),
        "https://download.db-ip.com/free/dbip-country-lite-2026-08.mmdb.gz"
    );
}

#[test]
fn resolve_default_is_mirror_then_dbip() {
    let cfg = default_settings(); // no key, no db_url
    let s = resolve_sources(&cfg);
    assert_eq!(s[0].url, MIRROR_URL);
    assert!(
        s[1].url
            .starts_with("https://download.db-ip.com/free/dbip-country-lite-")
    );
    assert!(matches!(s[0].archive, Archive::Gz));
    // Third candidate is the previous month's DB-IP file: the current
    // month's build may not be published yet at the start of a month.
    assert_eq!(s.len(), 3);
    assert!(
        s[2].url
            .starts_with("https://download.db-ip.com/free/dbip-country-lite-")
    );
    assert_ne!(s[1].url, s[2].url);
}

#[test]
fn resolve_key_is_maxmind_only_no_fallback() {
    let mut cfg = default_settings();
    cfg.geoip_maxmind_key = Some("K".into());
    let s = resolve_sources(&cfg);
    assert_eq!(s.len(), 1);
    assert!(matches!(s[0].archive, Archive::TarGz));
}

#[test]
fn resolve_explicit_url_no_fallback() {
    let mut cfg = default_settings();
    cfg.geoip_db_url = Some("https://x/y.mmdb".into());
    let s = resolve_sources(&cfg);
    assert_eq!(s.len(), 1);
    assert!(matches!(s[0].archive, Archive::Raw)); // .mmdb => raw
}

#[test]
fn archive_detection() {
    assert!(matches!(archive_from_url("a.tar.gz"), Archive::TarGz));
    assert!(matches!(archive_from_url("a.mmdb.gz"), Archive::Gz));
    assert!(matches!(archive_from_url("a.mmdb"), Archive::Raw));
}

#[test]
fn extract_gz_roundtrip() {
    let original = b"a fake mmdb payload".repeat(64);
    let compressed = gz(&original);
    let out = extract_mmdb(&compressed, &Archive::Gz).unwrap();
    assert_eq!(out, original);
}

#[test]
fn extract_targz_finds_mmdb_member() {
    let payload = b"nested mmdb bytes".repeat(32);
    // A README member that must be skipped, then the real .mmdb, nested a
    // directory deep exactly like MaxMind's tarball layout.
    let archive = targz(&[
        ("GeoLite2-Country_20260801/README", b"hello"),
        ("GeoLite2-Country_20260801/GeoLite2-Country.mmdb", &payload),
    ]);

    let out = extract_mmdb(&archive, &Archive::TarGz).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn extract_raw_is_passthrough() {
    assert_eq!(extract_mmdb(b"abc", &Archive::Raw).unwrap(), b"abc");
}

/// `MAX_DOWNLOAD_BYTES` bounds the *compressed* body only. A gzip bomb —
/// a tiny body that expands to far more than the agent has memory for —
/// slips straight past it, so the decompressed side needs its own bound.
/// Zeroes compress to roughly nothing, which is the whole point.
#[test]
fn extract_gz_refuses_a_decompression_bomb() {
    let bomb = gz(&vec![0u8; (MAX_DECOMPRESSED_BYTES + 4096) as usize]);
    assert!(
        (bomb.len() as u64) < MAX_DOWNLOAD_BYTES,
        "the fixture must pass the compressed-size check to test the decompressed one"
    );

    let err = extract_mmdb(&bomb, &Archive::Gz).expect_err("a gzip bomb must be refused");

    assert!(
        matches!(err, TrafficError::Decompress(_)),
        "must fail as a decompression error, not truncate silently: {err}"
    );
    assert!(err.to_string().contains("exceeds"), "{err}");
}

/// A payload right at the limit is legitimate and must still be accepted —
/// the guard rejects, it does not merely truncate at the boundary.
#[test]
fn extract_gz_accepts_a_payload_exactly_at_the_limit() {
    let original = vec![7u8; MAX_DECOMPRESSED_BYTES as usize];
    let out = extract_mmdb(&gz(&original), &Archive::Gz).unwrap();
    assert_eq!(out.len(), original.len());
}

/// The tar branch reads its member separately, so it needs the same guard:
/// a tar header can claim any size at all.
#[test]
fn extract_targz_refuses_an_oversized_member() {
    let payload = vec![0u8; (MAX_DECOMPRESSED_BYTES + 4096) as usize];
    let archive = targz(&[("x/GeoLite2-Country.mmdb", &payload)]);

    let err =
        extract_mmdb(&archive, &Archive::TarGz).expect_err("an oversized member must be refused");
    assert!(matches!(err, TrafficError::Decompress(_)), "{err}");
}

#[test]
fn magic_reconciles_mismatched_suffix() {
    // A server that hands back a bare .mmdb from a .gz URL still works.
    assert_eq!(
        extract_mmdb(b"raw bytes", &Archive::Gz).unwrap(),
        b"raw bytes"
    );
    // ...and vice versa.
    let compressed = gz(b"payload");
    assert_eq!(
        extract_mmdb(&compressed, &Archive::Raw).unwrap(),
        b"payload"
    );
}

#[test]
fn write_fresh_never_reuses_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let a = write_fresh(dir.path(), b"first").unwrap();
    let b = write_fresh(dir.path(), b"second").unwrap();
    assert_ne!(a, b);
    assert_eq!(std::fs::read(&a).unwrap(), b"first");
    assert_eq!(std::fs::read(&b).unwrap(), b"second");
}

#[test]
fn prune_old_keeps_the_live_file_only() {
    let dir = tempfile::tempdir().unwrap();
    let old = write_fresh(dir.path(), b"old").unwrap();
    let live = write_fresh(dir.path(), b"live").unwrap();
    std::fs::write(dir.path().join("unrelated.sqlite"), b"x").unwrap();

    prune_old(dir.path(), &live);

    assert!(!old.exists(), "previous database should be removed");
    assert!(live.exists(), "live database must survive pruning");
    assert!(dir.path().join("unrelated.sqlite").exists());
}

#[test]
fn attribution_recognizes_the_mirror_as_maxmind() {
    assert_eq!(
        classify_attribution(MIRROR_URL),
        Some(MAXMIND_ATTRIBUTION.to_string())
    );
    // Any jsDelivr-hosted path, not just the exact constant, since the
    // mirror's package could gain a versioned path over time.
    assert_eq!(
        classify_attribution(
            "https://cdn.jsdelivr.net/npm/geolite2-country@1/GeoLite2-Country.mmdb.gz"
        ),
        Some(MAXMIND_ATTRIBUTION.to_string())
    );
}

#[test]
fn attribution_recognizes_licensed_maxmind_direct() {
    assert_eq!(
        classify_attribution(&maxmind_url("KEY", "GeoLite2-Country")),
        Some(MAXMIND_ATTRIBUTION.to_string())
    );
}

#[test]
fn attribution_recognizes_dbip() {
    assert_eq!(
        classify_attribution(&dbip_url(2026, 8)),
        Some(DBIP_ATTRIBUTION.to_string())
    );
}

#[test]
fn attribution_is_none_for_an_unrecognized_override() {
    assert_eq!(
        classify_attribution("https://internal.example.com/custom.mmdb"),
        None
    );
}

/// `GeoIp::attribution` is a thin wrapper over `classify_attribution`
/// applied to `meta.source_url` (see the tests above for the
/// classification cases); building a full `GeoIp` needs a real mmap'd
/// `.mmdb`, which the network-gated test below covers end to end.
///
/// Network-gated: actually downloads from the default source chain.
/// Run manually with `cargo test -p traffic geoip -- --ignored`.
#[tokio::test]
#[ignore = "hits the network"]
async fn bootstrap_downloads_and_looks_up() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = default_settings();

    let geo = GeoIp::bootstrap(&cfg, dir.path()).await.unwrap();
    let country = geo.country("89.160.20.128".parse().unwrap());
    assert!(
        country.is_some(),
        "expected a country for a known public IP"
    );
    assert!(
        geo.attribution().is_some(),
        "the default source chain always resolves to an attributable source"
    );

    // A second pass either 304s (Ok(false)) or re-downloads (Ok(true));
    // either way the database stays usable and only one file remains.
    let swapped = geo.refresh(&cfg, dir.path()).await.unwrap();
    assert!(geo.country("89.160.20.128".parse().unwrap()).is_some());
    let dbs = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("geoip-"))
        .count();
    assert_eq!(dbs, 1, "swapped={swapped}");
}
