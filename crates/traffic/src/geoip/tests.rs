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
            subdivision: Some("Land Berlin".to_string()),
            city: Some("Berlin".to_string()),
            lat: Some(52.52),
            lon: Some(13.405),
        }
    );
}

/// GeoLite has a code and a name, DB-IP only the name. Preferring the name
/// keeps one region under one key when the active source changes.
#[test]
fn location_from_gives_one_subdivision_for_geolite_and_dbip() {
    let mut geolite = city_record();
    geolite
        .subdivisions
        .push(place(Some("BE"), Some("Land Berlin")));
    let mut dbip = city_record();
    dbip.subdivisions.push(place(None, Some("Land Berlin")));

    assert_eq!(
        location_from(&geolite).subdivision,
        location_from(&dbip).subdivision
    );
}

/// The code is the fallback when a record has no English name.
#[test]
fn location_from_uses_the_subdivision_code_when_there_is_no_name() {
    let mut record = city_record();
    record.subdivisions.push(place(Some("BE"), None));

    assert_eq!(location_from(&record).subdivision, Some("BE".to_string()));
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

/// Before the first database is loaded, lookups resolve nothing.
#[test]
fn an_empty_geoip_resolves_nothing() {
    let geo = GeoIp::empty();

    assert!(!geo.is_loaded());
    assert!(geo.locate("89.160.20.128".parse().unwrap()).is_none());
    assert!(geo.attribution().is_none());
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

#[tokio::test]
async fn fetch_errors_do_not_expose_the_license_key() {
    // Keep the port open without answering: the request times out.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let source = Source {
        url: format!(
            "http://{}/db?license_key=SECRETKEY",
            listener.local_addr().unwrap()
        ),
        archive: Archive::Raw,
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let error = GeoIp::fetch(&client, &source, dir.path(), None, None)
        .await
        .err()
        .expect("request must fail");
    let message = error.to_string();
    assert!(!message.contains("SECRETKEY"), "{message}");
    assert!(message.contains("REDACTED"), "{message}");
}

#[test]
fn extract_raw_refuses_an_oversized_database() {
    let body = std::io::repeat(0).take(MAX_DECOMPRESSED_BYTES + 1);
    let error = extract_mmdb(body, &Archive::Raw, &mut std::io::sink())
        .expect_err("raw databases must obey the same limit as gzip databases");
    assert!(matches!(error, TrafficError::Decompress(_)), "{error}");
}

/// A minimal valid `.mmdb`: one search-tree node whose records both mean
/// "not found", plus the metadata `Reader` requires. Built here so the tests
/// need no binary fixture. `kind` (under 29 bytes) is the `database_type`.
fn tiny_mmdb_of(kind: &str) -> Vec<u8> {
    fn key(db: &mut Vec<u8>, key: &str, value: &[u8]) {
        db.push(0x40 | key.len() as u8); // utf8 string
        db.extend_from_slice(key.as_bytes());
        db.extend_from_slice(value);
    }
    // Node 0: both 24-bit records equal node_count, i.e. no data.
    let mut db = vec![0, 0, 1, 0, 0, 1];
    db.extend_from_slice(&[0; 16]); // data section separator
    db.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    db.push(0xE9); // map, 9 entries
    key(&mut db, "binary_format_major_version", &[0xA1, 2]); // uint16
    key(&mut db, "binary_format_minor_version", &[0xA0]);
    key(&mut db, "build_epoch", &[0x00, 0x02]); // uint64 0
    let mut kind_value = vec![0x40 | kind.len() as u8];
    kind_value.extend_from_slice(kind.as_bytes());
    key(&mut db, "database_type", &kind_value);
    key(&mut db, "description", &[0xE0]); // empty map
    key(&mut db, "ip_version", &[0xA1, 4]);
    key(&mut db, "languages", &[0x00, 0x04]); // empty array
    key(&mut db, "node_count", &[0xC1, 1]); // uint32
    key(&mut db, "record_size", &[0xA1, 24]);
    db
}

fn tiny_mmdb() -> Vec<u8> {
    tiny_mmdb_of("Test")
}

/// Serves `body` as a `200` to every connection, `chunk` bytes at a time
/// with `pause` after each write. Returns the base URL.
fn serve_slowly(body: Vec<u8>, chunk: usize, pause: Duration) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let body = body.clone();
            std::thread::spawn(move || {
                // Read the request head; its contents do not matter.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                for part in body.chunks(chunk) {
                    if stream
                        .write_all(part)
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        return;
                    }
                    std::thread::sleep(pause);
                }
            });
        }
    });
    url
}

fn test_client(read_timeout: Duration) -> reqwest::Client {
    client_builder(read_timeout).no_proxy().build().unwrap()
}

/// The timeout bounds each read, not the whole download: a city database
/// takes minutes on a slow link, and that must still finish.
#[tokio::test]
async fn fetch_finishes_a_slow_but_steady_download() {
    let body = b"0123456789".repeat(20);
    // ~1 s in total, far longer than the timeout, but never silent for long.
    let url = serve_slowly(body.clone(), 10, Duration::from_millis(50));
    let source = Source {
        url: format!("{url}/db.mmdb"),
        archive: Archive::Raw,
    };
    let dir = tempfile::tempdir().unwrap();

    let client = test_client(Duration::from_millis(400));
    let fetched = GeoIp::fetch(&client, &source, dir.path(), None, None)
        .await
        .expect("a steady download must not time out");

    let Fetched::Body { body: path, .. } = fetched else {
        panic!("expected a body");
    };
    assert_eq!(std::fs::read(path).unwrap(), body);
}

/// A download that goes silent fails, says so, and keeps the key out.
#[tokio::test]
async fn fetch_reports_a_stalled_download_as_timed_out() {
    let url = serve_slowly(vec![0; 64], 8, Duration::from_secs(30));
    let source = Source {
        url: format!("{url}/db?license_key=SECRETKEY"),
        archive: Archive::Raw,
    };
    let dir = tempfile::tempdir().unwrap();

    let client = test_client(Duration::from_millis(200));
    let fetch = GeoIp::fetch(&client, &source, dir.path(), None, None);
    let error = tokio::time::timeout(Duration::from_secs(5), fetch)
        .await
        .expect("the read timeout must end a stalled body")
        .err()
        .expect("a stalled download must fail");

    let message = error.to_string();
    assert!(message.contains("timed out"), "{message}");
    assert!(!message.contains("SECRETKEY"), "{message}");
    assert!(!dir.path().join(DOWNLOAD_FILE).exists());
}

/// The read timeout also covers waiting for the response head.
#[tokio::test]
async fn fetch_reports_a_server_that_never_answers_as_timed_out() {
    // Keep the port open without answering.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let source = Source {
        url: format!("http://{}/db.mmdb", listener.local_addr().unwrap()),
        archive: Archive::Raw,
    };
    let dir = tempfile::tempdir().unwrap();

    let client = test_client(Duration::from_millis(200));
    let fetch = GeoIp::fetch(&client, &source, dir.path(), None, None);
    let error = tokio::time::timeout(Duration::from_secs(5), fetch)
        .await
        .expect("the read timeout must end a silent server")
        .err()
        .expect("a silent server must fail");

    let message = error.to_string();
    assert!(message.contains("timed out"), "{message}");
}

#[test]
fn retry_delay_doubles_up_to_the_cap() {
    let minutes = |m: u64| Duration::from_secs(m * 60);
    let day = minutes(24 * 60);
    let period = 30 * day;

    assert_eq!(retry_delay(1, period), minutes(15));
    assert_eq!(retry_delay(2, period), minutes(30));
    assert_eq!(retry_delay(3, period), minutes(60));
    assert_eq!(retry_delay(7, period), minutes(960));
    // Never more than a day apart...
    assert_eq!(retry_delay(8, period), day);
    assert_eq!(retry_delay(u32::MAX, period), day);
    // ...and never longer than the refresh period itself.
    assert_eq!(retry_delay(5, minutes(120)), minutes(120));
}

struct FullDisk;

impl Write for FullDisk {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::StorageFull.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A failed write is a local problem, not a bad download.
#[test]
fn extract_reports_a_failed_write_as_an_io_error() {
    let error =
        extract_mmdb(&b"abc"[..], &Archive::Raw, &mut FullDisk).expect_err("the write must fail");
    assert!(matches!(error, TrafficError::Io(_)), "{error}");
}

/// A full disk is not the source's fault: the next source would fail the
/// same way, after another long download.
#[tokio::test]
async fn refresh_stops_the_source_chain_on_a_local_error() {
    let dir = tempfile::tempdir().unwrap();
    // The spool file cannot be created: a directory holds its name.
    std::fs::create_dir(dir.path().join(DOWNLOAD_FILE)).unwrap();
    let first = serve_slowly(tiny_mmdb(), 4096, Duration::ZERO);
    let next = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    next.set_nonblocking(true).unwrap();
    let sources = vec![
        Source {
            url: format!("{first}/a.mmdb"),
            archive: Archive::Raw,
        },
        Source {
            url: format!("http://{}/b.mmdb", next.local_addr().unwrap()),
            archive: Archive::Raw,
        },
    ];

    let geo = GeoIp::empty();
    let client = test_client(Duration::from_secs(1));
    let error = geo
        .refresh_from(sources, dir.path(), &client)
        .await
        .expect_err("the spool file cannot be written");

    assert!(matches!(error, TrafficError::Io(_)), "{error}");
    assert!(
        next.accept()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock),
        "the next source must not be contacted"
    );
}

fn leave_partial_files(dir: &Path) {
    std::fs::write(dir.join(DOWNLOAD_FILE), b"partial").unwrap();
    std::fs::write(dir.join(format!("{META_FILE}.tmp")), b"{").unwrap();
}

fn assert_no_partial_files(dir: &Path) {
    assert!(!dir.join(DOWNLOAD_FILE).exists());
    assert!(!dir.join(format!("{META_FILE}.tmp")).exists());
}

/// A download cut short by shutdown leaves its spool file behind.
#[test]
fn open_cached_removes_partial_files() {
    let dir = tempfile::tempdir().unwrap();
    leave_partial_files(dir.path());

    assert!(GeoIp::open_cached(&default_settings(), dir.path()).is_none());
    assert_no_partial_files(dir.path());
}

#[tokio::test]
async fn refresh_removes_partial_files_before_it_starts() {
    let dir = tempfile::tempdir().unwrap();
    leave_partial_files(dir.path());
    // A closed port: the source fails at once.
    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let sources = vec![Source {
        url: format!("http://{addr}/db.mmdb"),
        archive: Archive::Raw,
    }];

    let client = test_client(Duration::from_secs(1));
    let result = GeoIp::empty()
        .refresh_from(sources, dir.path(), &client)
        .await;

    assert!(result.is_err());
    assert_no_partial_files(dir.path());
}

/// Refreshes share one spool file, so they must not overlap.
#[tokio::test]
async fn concurrent_refreshes_do_not_share_the_spool_file() {
    // Different sizes, so interleaved writes to one file would show.
    let short = serve_slowly(tiny_mmdb_of("A"), 16, Duration::from_millis(20));
    let long = serve_slowly(tiny_mmdb_of(&"B".repeat(28)), 16, Duration::from_millis(20));
    let source = |url: &str| {
        vec![Source {
            url: format!("{url}/db.mmdb"),
            archive: Archive::Raw,
        }]
    };
    let dir = tempfile::tempdir().unwrap();
    let geo = GeoIp::empty();
    let client = test_client(Duration::from_secs(5));

    let (a, b) = tokio::join!(
        geo.refresh_from(source(&short), dir.path(), &client),
        geo.refresh_from(source(&long), dir.path(), &client),
    );

    assert!(a.is_ok(), "{a:?}");
    assert!(b.is_ok(), "{b:?}");
    assert!(geo.is_loaded());
}

fn cache(dir: &Path, source_url: &str) {
    let path = write_bytes(dir, &tiny_mmdb()).unwrap();
    let file = path.file_name().unwrap().to_str().unwrap();
    save_meta(dir, &meta(dir, file, source_url));
}

#[test]
fn open_cached_reuses_a_database_from_the_same_source() {
    let dir = tempfile::tempdir().unwrap();
    cache(dir.path(), MIRROR_URL);

    let geo = GeoIp::open_cached(&default_settings(), dir.path()).expect("database is reused");
    assert!(geo.is_loaded());
}

/// The DB-IP URL names a month, so last month's file is no longer among the
/// sources; it is still a DB-IP database and still worth serving.
#[test]
fn open_cached_reuses_a_dbip_database_from_an_earlier_month() {
    let dir = tempfile::tempdir().unwrap();
    let year = time::OffsetDateTime::now_utc().year() - 1;
    let saved = dbip_url(year, 6);
    cache(dir.path(), &saved);

    let geo = GeoIp::open_cached(&default_settings(), dir.path())
        .expect("an earlier DB-IP month is reused");
    assert_eq!(geo.attribution(), Some(DBIP_ATTRIBUTION.to_string()));
    let source_url = geo
        .meta
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .source_url
        .clone();
    assert_eq!(source_url, saved);
}

/// ...but not once the configuration no longer uses DB-IP at all.
#[test]
fn open_cached_drops_a_dbip_database_when_dbip_is_not_configured() {
    let dir = tempfile::tempdir().unwrap();
    cache(dir.path(), &dbip_url(2020, 6));
    let mut cfg = default_settings();
    cfg.geoip_db_url = Some("https://example.com/custom.mmdb".into());

    assert!(GeoIp::open_cached(&cfg, dir.path()).is_none());
}

/// Shutdown drops a refresh mid-download; the partial body goes with it.
#[tokio::test]
async fn a_dropped_fetch_removes_its_partial_body() {
    let url = serve_slowly(vec![0; 64], 8, Duration::from_secs(30));
    let source = Source {
        url: format!("{url}/db.mmdb"),
        archive: Archive::Raw,
    };
    let dir = tempfile::tempdir().unwrap();

    let client = test_client(Duration::from_secs(10));
    let fetch = GeoIp::fetch(&client, &source, dir.path(), None, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), fetch)
            .await
            .is_err(),
        "the fetch is still downloading"
    );

    assert!(!dir.path().join(DOWNLOAD_FILE).exists());
}

/// Enrichers cache lookups per generation: nothing loaded is `0`, and each
/// database stored moves it on.
#[tokio::test]
async fn generation_moves_on_with_each_database_stored() {
    let url = serve_slowly(tiny_mmdb(), 1024, Duration::ZERO);
    let sources = || {
        vec![Source {
            url: format!("{url}/db.mmdb"),
            archive: Archive::Raw,
        }]
    };
    let dir = tempfile::tempdir().unwrap();
    let geo = GeoIp::empty();
    let client = test_client(Duration::from_secs(5));
    assert_eq!(geo.generation(), 0);

    geo.refresh_from(sources(), dir.path(), &client)
        .await
        .unwrap();
    assert_eq!(geo.generation(), 1);
    geo.refresh_from(sources(), dir.path(), &client)
        .await
        .unwrap();
    assert_eq!(geo.generation(), 2);

    let cached = GeoIp::open_cached(&default_settings(), dir.path());
    assert!(
        cached.is_none(),
        "the test server is not a configured source"
    );
    cache(dir.path(), MIRROR_URL);
    let cached = GeoIp::open_cached(&default_settings(), dir.path()).unwrap();
    assert_eq!(cached.generation(), 1);
}
