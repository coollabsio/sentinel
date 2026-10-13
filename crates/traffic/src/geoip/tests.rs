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
        "https://download.db-ip.com/free/dbip-city-lite-2026-08.mmdb.gz"
    );
}

#[test]
fn resolve_default_is_mirror_then_dbip() {
    let cfg = default_settings(); // no key, no db_url
    let s = resolve_sources(&cfg);
    assert_eq!(s[0].url, MIRROR_URL);
    assert!(
        s[1].url
            .starts_with("https://download.db-ip.com/free/dbip-city-lite-")
    );
    assert!(matches!(s[0].archive, Archive::Gz));
    // Third candidate is the previous month's DB-IP file: the current
    // month's build may not be published yet at the start of a month.
    assert_eq!(s.len(), 3);
    assert!(
        s[2].url
            .starts_with("https://download.db-ip.com/free/dbip-city-lite-")
    );
    assert_ne!(s[1].url, s[2].url);
}

#[test]
fn default_sources_are_city_databases() {
    let sources = resolve_sources(&default_settings());
    assert_eq!(
        sources[0].url,
        "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz"
    );
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

fn extract(bytes: &[u8], archive: &Archive) -> Result<Vec<u8>, TrafficError> {
    let mut out = Vec::new();
    extract_mmdb(bytes, archive, &mut out)?;
    Ok(out)
}

fn write_bytes(db_dir: &Path, bytes: &[u8]) -> Result<PathBuf, TrafficError> {
    write_fresh(db_dir, |file| Ok(file.write_all(bytes)?))
}

#[test]
fn extract_gz_roundtrip() {
    let original = b"a fake mmdb payload".repeat(64);
    let compressed = gz(&original);
    let out = extract(&compressed, &Archive::Gz).unwrap();
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

    let out = extract(&archive, &Archive::TarGz).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn extract_raw_is_passthrough() {
    assert_eq!(extract(b"abc", &Archive::Raw).unwrap(), b"abc");
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

    let err = extract(&bomb, &Archive::Gz).expect_err("a gzip bomb must be refused");

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
    let out = extract(&gz(&original), &Archive::Gz).unwrap();
    assert_eq!(out.len(), original.len());
}

/// The tar branch reads its member separately, so it needs the same guard:
/// a tar header can claim any size at all.
#[test]
fn extract_targz_refuses_an_oversized_member() {
    let payload = vec![0u8; (MAX_DECOMPRESSED_BYTES + 4096) as usize];
    let archive = targz(&[("x/GeoLite2-Country.mmdb", &payload)]);

    let err = extract(&archive, &Archive::TarGz).expect_err("an oversized member must be refused");
    assert!(matches!(err, TrafficError::Decompress(_)), "{err}");
}

#[test]
fn magic_reconciles_mismatched_suffix() {
    // A server that hands back a bare .mmdb from a .gz URL still works.
    assert_eq!(extract(b"raw bytes", &Archive::Gz).unwrap(), b"raw bytes");
    // ...and vice versa.
    let compressed = gz(b"payload");
    assert_eq!(extract(&compressed, &Archive::Raw).unwrap(), b"payload");
}

#[test]
fn write_fresh_never_reuses_a_path() {
    let dir = tempfile::tempdir().unwrap();
    let a = write_bytes(dir.path(), b"first").unwrap();
    let b = write_bytes(dir.path(), b"second").unwrap();
    assert_ne!(a, b);
    assert_eq!(std::fs::read(&a).unwrap(), b"first");
    assert_eq!(std::fs::read(&b).unwrap(), b"second");
}

/// A failed extraction must not leave a partial file for a later map.
#[test]
fn write_fresh_removes_the_file_when_the_fill_fails() {
    let dir = tempfile::tempdir().unwrap();

    let result = write_fresh(dir.path(), |file| {
        file.write_all(b"partial")?;
        Err(TrafficError::Decompress("truncated".to_string()))
    });

    assert!(result.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn prune_old_keeps_the_live_file_only() {
    let dir = tempfile::tempdir().unwrap();
    let old = write_bytes(dir.path(), b"old").unwrap();
    let live = write_bytes(dir.path(), b"live").unwrap();
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

fn place<'a>(iso_code: Option<&'a str>, name: Option<&'a str>) -> Place<'a> {
    Place {
        iso_code,
        names: Names { en: name },
    }
}

fn city_record<'a>() -> Record<'a> {
    Record {
        country: place(Some("DE"), None),
        subdivisions: Vec::new(),
        city: place(None, Some("Berlin")),
        location: Location {
            latitude: Some(52.52),
            longitude: Some(13.405),
        },
    }
}

#[test]
fn location_from_maps_a_city_record() {
    let mut record = city_record();
    record
        .subdivisions
        .push(place(Some("BE"), Some("Land Berlin")));

    assert_eq!(
        location_from(&record),
        GeoLocation {
            country: Some("DE".to_string()),
            subdivision: Some("BE".to_string()),
            city: Some("Berlin".to_string()),
            lat: Some(52.52),
            lon: Some(13.405),
        }
    );
}

/// DB-IP has no ISO subdivision code, only a name.
#[test]
fn location_from_uses_the_subdivision_name_when_there_is_no_code() {
    let mut record = city_record();
    record.subdivisions.push(place(None, Some("Land Berlin")));

    assert_eq!(
        location_from(&record).subdivision,
        Some("Land Berlin".to_string())
    );
}

/// A country-only database decodes to a record with only the country set.
#[test]
fn location_from_a_country_only_record_has_no_city() {
    let record = Record {
        country: place(Some("DE"), None),
        ..Record::default()
    };

    assert_eq!(
        location_from(&record),
        GeoLocation {
            country: Some("DE".to_string()),
            ..GeoLocation::default()
        }
    );
}

fn meta(dir: &Path, file: &str, source_url: &str) -> Meta {
    Meta {
        etag: Some("\"v1\"".to_string()),
        last_modified: None,
        path: dir.join(file),
        source_url: source_url.to_string(),
    }
}

/// The sidecar must never hold the MaxMind license key.
#[test]
fn save_meta_redacts_the_license_key() {
    let dir = tempfile::tempdir().unwrap();
    let url = maxmind_url("SECRETKEY", "GeoLite2-City");

    save_meta(dir.path(), &meta(dir.path(), "geoip-1.mmdb", &url));

    let saved = std::fs::read_to_string(dir.path().join(META_FILE)).unwrap();
    assert!(!saved.contains("SECRETKEY"), "{saved}");
    assert!(saved.contains("geoip-1.mmdb"), "{saved}");
}

#[test]
fn open_cached_is_none_with_no_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    write_bytes(dir.path(), b"not reused").unwrap();

    assert!(GeoIp::open_cached(&default_settings(), dir.path()).is_none());
}

/// A database from a source the configuration no longer uses (for example
/// the country edition from before an upgrade) must be downloaded again.
#[test]
fn open_cached_is_none_when_the_source_changed() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_bytes(dir.path(), b"old").unwrap();
    let file = path.file_name().unwrap().to_str().unwrap();
    save_meta(
        dir.path(),
        &meta(
            dir.path(),
            file,
            "https://example.com/GeoLite2-Country.mmdb",
        ),
    );

    assert!(GeoIp::open_cached(&default_settings(), dir.path()).is_none());
}

/// A sidecar must not point the mapping at a file outside the directory.
#[test]
fn open_cached_refuses_a_file_name_that_is_not_a_database() {
    let dir = tempfile::tempdir().unwrap();
    for file in ["../geoip-1.mmdb", "analytics.sqlite"] {
        save_meta(dir.path(), &meta(dir.path(), file, MIRROR_URL));
        assert!(GeoIp::open_cached(&default_settings(), dir.path()).is_none());
    }
}

/// A file that is not a database fails to map; the caller then downloads.
#[test]
fn open_cached_is_none_when_the_file_is_not_a_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_bytes(dir.path(), b"garbage").unwrap();
    let file = path.file_name().unwrap().to_str().unwrap();
    save_meta(dir.path(), &meta(dir.path(), file, MIRROR_URL));

    assert!(GeoIp::open_cached(&default_settings(), dir.path()).is_none());
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
    let location = geo.locate("89.160.20.128".parse().unwrap()).unwrap();
    assert!(
        location.country.is_some(),
        "expected a country for a known public IP"
    );
    assert!(location.city.is_some(), "expected a city: {location:?}");
    assert!(location.lat.is_some() && location.lon.is_some());
    assert!(
        geo.attribution().is_some(),
        "the default source chain always resolves to an attributable source"
    );

    // A second pass either 304s (Ok(false)) or re-downloads (Ok(true));
    // either way the database stays usable and only one file remains.
    let swapped = geo.refresh(&cfg, dir.path()).await.unwrap();
    assert!(geo.locate("89.160.20.128".parse().unwrap()).is_some());
    let dbs = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("geoip-"))
        .count();
    assert_eq!(dbs, 1, "swapped={swapped}");
    assert!(!dir.path().join(DOWNLOAD_FILE).exists());

    // A new start reuses the file with no download, and its first refresh
    // is a conditional request.
    let cached = GeoIp::open_cached(&cfg, dir.path()).expect("database on disk is reused");
    assert!(cached.locate("89.160.20.128".parse().unwrap()).is_some());
    assert_eq!(cached.attribution(), geo.attribution());
    assert!(!cached.refresh(&cfg, dir.path()).await.unwrap());
}

/// Network-gated: the DB-IP city database decodes with the same record type.
/// Run manually with `cargo test -p traffic geoip -- --ignored`.
#[tokio::test]
#[ignore = "hits the network"]
async fn dbip_city_database_resolves_a_city() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = default_settings();
    let now = time::OffsetDateTime::now_utc();
    cfg.geoip_db_url = Some(dbip_url(now.year(), now.month() as u32));

    let geo = GeoIp::bootstrap(&cfg, dir.path()).await.unwrap();
    let location = geo.locate("89.160.20.128".parse().unwrap()).unwrap();

    assert!(location.country.is_some(), "{location:?}");
    assert!(location.city.is_some(), "{location:?}");
    assert!(
        location.lat.is_some() && location.lon.is_some(),
        "{location:?}"
    );
}
