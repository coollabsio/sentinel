// `deny`, not `forbid`: this module contains the crate's only `unsafe` block
// (`Reader::open_mmap`), which needs a scoped `#[allow(unsafe_code)]`. `forbid`
// cannot be lifted by an inner `allow`, so it would make that impossible.
#![deny(unsafe_code)]

//! GeoIP database management and lookup.
//!
//! Resolves an ordered list of candidate database sources (spec §6), downloads
//! the first one that works, decompresses it, memory-maps it, and publishes it
//! through an [`ArcSwap`] so lookups stay lock-free across hot reloads.
//!
//! Source resolution, in priority order:
//! 1. `geoip_maxmind_key` set — the licensed MaxMind tarball, no fallback (an
//!    explicit credential means the operator wants *that* database).
//! 2. `geoip_db_url` set — that URL only, no fallback (explicit override).
//! 3. Otherwise — the jsDelivr mirror, then DB-IP Lite for the current month,
//!    then DB-IP Lite for the previous month. DB-IP's URLs are date-derived and
//!    the current month's build is not published until some point into the
//!    month, so the previous month is carried as a third candidate rather than
//!    special-cased inside the DB-IP attempt.
//!
//! Every refresh writes a *new* dated file and only removes the previous one
//! after the new mapping is live; see the `SAFETY` note on [`GeoIp::install`].

use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use config::TrafficSettings;
use flate2::read::GzDecoder;
use maxminddb::{Mmap, Reader, geoip2};
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};

use crate::TrafficError;
use crate::enrich::CountryLookup;

/// Default database source: a GeoLite2-Country mirror published on npm and
/// served by the jsDelivr CDN. Requires no MaxMind account.
pub const MIRROR_URL: &str =
    "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz";

/// Gzip magic number; used to sanity-check URL-derived archive detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Refuse bodies larger than this. The largest legitimate candidate (a
/// GeoLite2-City tarball) is well under 100 MiB.
const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Refuse *decompressed* payloads larger than this.
///
/// [`MAX_DOWNLOAD_BYTES`] bounds only the compressed body, which says nothing
/// about what it expands to — a hostile or compromised `GEOIP_DB_URL` can
/// serve a few kilobytes that inflate to gigabytes and OOM the agent or fill
/// its disk. Real GeoLite2/DB-IP *country* databases are a few MiB, so 64 MiB
/// is a wide safety margin rather than an operational limit.
const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// How the bytes at a source URL are packaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Archive {
    /// A gzip-compressed tar containing an `.mmdb` member (MaxMind's layout).
    TarGz,
    /// A gzip-compressed `.mmdb` file.
    Gz,
    /// A bare, uncompressed `.mmdb` file.
    Raw,
}

/// One candidate database source.
#[derive(Debug, Clone)]
pub struct Source {
    /// URL to fetch.
    pub url: String,
    /// How to unpack the response body.
    pub archive: Archive,
}

impl Source {
    /// This source's URL with any credential masked — the *only* form that
    /// may reach a log line or an error message. See [`redact_url`].
    pub fn redacted_url(&self) -> Cow<'_, str> {
        redact_url(&self.url)
    }
}

/// Mask the value of a `license_key` query parameter.
///
/// [`maxmind_url`] embeds the operator's MaxMind credential directly in the
/// download URL. That URL is logged on every successful load and refresh and
/// is interpolated into every [`TrafficError::Download`] message, so without
/// this the key ends up in `docker logs`, in whatever aggregator scrapes
/// them, and in any support-bundle paste. URLs with no key (the jsDelivr
/// mirror, DB-IP, a custom `GEOIP_DB_URL`) pass through untouched and
/// unallocated.
pub fn redact_url(url: &str) -> Cow<'_, str> {
    const KEY: &str = "license_key=";

    let Some(at) = url.find(KEY) else {
        return Cow::Borrowed(url);
    };
    let value_start = at + KEY.len();
    // The credential runs to the next parameter separator, or to the end.
    let value_end = url[value_start..]
        .find('&')
        .map_or(url.len(), |i| value_start + i);

    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..value_start]);
    out.push_str("REDACTED");
    out.push_str(&url[value_end..]);
    Cow::Owned(out)
}

/// Build the ordered list of candidate sources for `cfg`. Callers try them in
/// order and keep the first that succeeds.
pub fn resolve_sources(cfg: &TrafficSettings) -> Vec<Source> {
    if let Some(key) = cfg.geoip_maxmind_key.as_deref() {
        return vec![Source {
            url: maxmind_url(key, &cfg.geoip_maxmind_edition),
            archive: Archive::TarGz,
        }];
    }

    if let Some(url) = cfg.geoip_db_url.as_deref() {
        return vec![Source {
            archive: archive_from_url(url),
            url: url.to_string(),
        }];
    }

    let now = time::OffsetDateTime::now_utc();
    let (year, month) = (now.year(), now.month() as u32);
    let (prev_year, prev_month) = if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    };

    vec![
        Source {
            url: MIRROR_URL.to_string(),
            archive: Archive::Gz,
        },
        Source {
            url: dbip_url(year, month),
            archive: Archive::Gz,
        },
        Source {
            url: dbip_url(prev_year, prev_month),
            archive: Archive::Gz,
        },
    ]
}

/// MaxMind's licensed download URL for `edition`, authenticated with `key`.
pub fn maxmind_url(key: &str, edition: &str) -> String {
    format!(
        "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={key}&suffix=tar.gz"
    )
}

/// DB-IP's free country-lite download URL for a given year and month.
pub fn dbip_url(year: i32, month: u32) -> String {
    format!("https://download.db-ip.com/free/dbip-country-lite-{year:04}-{month:02}.mmdb.gz")
}

/// Guess the packaging of `url` from its path suffix (query/fragment ignored).
pub fn archive_from_url(url: &str) -> Archive {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Archive::TarGz
    } else if lower.ends_with(".gz") {
        Archive::Gz
    } else {
        Archive::Raw
    }
}

/// Reconcile URL-derived packaging against the body's gzip magic number, so a
/// server that serves a bare `.mmdb` from a `.gz` URL (or vice versa) still
/// works. Cannot distinguish `TarGz` from `Gz`; that stays URL-driven.
fn reconcile_archive(archive: &Archive, bytes: &[u8]) -> Archive {
    let looks_gzipped = bytes.len() >= 2 && bytes[..2] == GZIP_MAGIC;
    match (archive, looks_gzipped) {
        (Archive::TarGz | Archive::Gz, false) => Archive::Raw,
        (Archive::Raw, true) => Archive::Gz,
        _ => *archive,
    }
}

/// Read `reader` to EOF, refusing anything past [`MAX_DECOMPRESSED_BYTES`].
///
/// Reads one byte past the limit precisely so hitting it can be distinguished
/// from legitimately ending there: an over-long payload is a
/// [`TrafficError::Decompress`], never a silent truncation that would hand a
/// half-written `.mmdb` to the parser.
fn read_bounded<R: Read>(reader: R, what: &str) -> Result<Vec<u8>, TrafficError> {
    let mut out = Vec::new();
    let read = reader
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| TrafficError::Decompress(format!("{what}: {e}")))? as u64;
    if read > MAX_DECOMPRESSED_BYTES {
        return Err(TrafficError::Decompress(format!(
            "{what}: decompressed size exceeds {MAX_DECOMPRESSED_BYTES} bytes"
        )));
    }
    Ok(out)
}

/// Unpack a downloaded body into raw `.mmdb` bytes.
fn extract_mmdb(bytes: &[u8], archive: &Archive) -> Result<Vec<u8>, TrafficError> {
    match reconcile_archive(archive, bytes) {
        Archive::Raw => Ok(bytes.to_vec()),
        Archive::Gz => read_bounded(GzDecoder::new(bytes), "gunzip"),
        Archive::TarGz => {
            let mut tar = tar::Archive::new(GzDecoder::new(bytes));
            let entries = tar
                .entries()
                .map_err(|e| TrafficError::Decompress(format!("tar entries: {e}")))?;
            for entry in entries {
                let entry =
                    entry.map_err(|e| TrafficError::Decompress(format!("tar entry: {e}")))?;
                let is_mmdb = entry
                    .path()
                    .map(|p| {
                        p.extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("mmdb"))
                    })
                    .unwrap_or(false);
                if !is_mmdb {
                    continue;
                }
                return read_bounded(entry, "tar member");
            }
            Err(TrafficError::Decompress(
                "no .mmdb member in tar.gz".to_string(),
            ))
        }
    }
}

/// Bookkeeping for the currently-loaded database.
struct Meta {
    /// `ETag` of the response the current database came from, if the server
    /// sent one.
    etag: Option<String>,
    /// `Last-Modified` of that response, used only when there is no `ETag`.
    last_modified: Option<String>,
    /// On-disk path of the file currently mapped by `db`.
    path: PathBuf,
    /// URL the current database was fetched from. Conditional-request headers
    /// are only replayed against this exact URL.
    source_url: String,
}

/// Outcome of a conditional GET.
enum Fetched {
    /// Server answered `304 Not Modified`.
    NotModified,
    /// Server answered with a body.
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// A memory-mapped GeoIP country database with lock-free reads and atomic
/// hot-reload.
pub struct GeoIp {
    db: ArcSwap<Reader<Mmap>>,
    meta: Mutex<Meta>,
}

impl GeoIp {
    /// Download and map a database, trying each candidate from
    /// [`resolve_sources`] in order.
    ///
    /// Returns `Err` only when *every* candidate fails; the caller is expected
    /// to fall back to [`crate::enrich::NoGeo`] rather than treat that as
    /// fatal. On success the returned `GeoIp` always has a live mapping.
    pub async fn bootstrap(
        cfg: &TrafficSettings,
        db_dir: &Path,
    ) -> Result<Arc<GeoIp>, TrafficError> {
        std::fs::create_dir_all(db_dir)?;
        let client = http_client()?;

        let mut last_err: Option<TrafficError> = None;
        for source in resolve_sources(cfg) {
            let (bytes, etag, last_modified) = match Self::fetch(&client, &source, None, None).await
            {
                Ok(Fetched::Body {
                    bytes,
                    etag,
                    last_modified,
                }) => (bytes, etag, last_modified),
                // No conditional headers were sent, so 304 is a protocol
                // violation; treat it as a failed candidate.
                Ok(Fetched::NotModified) => {
                    last_err = Some(TrafficError::Download(format!(
                        "{}: unexpected 304 without conditional request",
                        source.redacted_url()
                    )));
                    continue;
                }
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip source failed");
                    last_err = Some(e);
                    continue;
                }
            };

            match Self::install(&bytes, &source, db_dir) {
                Ok((reader, path)) => {
                    tracing::info!(url = %source.redacted_url(), path = %path.display(), "geoip database loaded");
                    let geo = Arc::new(GeoIp {
                        db: ArcSwap::new(Arc::new(reader)),
                        meta: Mutex::new(Meta {
                            etag,
                            last_modified,
                            path: path.clone(),
                            source_url: source.url.clone(),
                        }),
                    });
                    // Only now that the new file is mapped and published is it
                    // safe to remove anything else left in the directory.
                    prune_old(db_dir, &path);
                    return Ok(geo);
                }
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip source unusable");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            TrafficError::GeoIp("no geoip sources resolved from configuration".to_string())
        }))
    }

    /// Re-check the configured sources and hot-swap in a newer database.
    ///
    /// Returns `Ok(true)` if a new database was mapped and swapped in,
    /// `Ok(false)` if the active source answered `304 Not Modified` (nothing to
    /// do), and `Err` if every candidate failed. The currently-mapped database
    /// is never disturbed on `Ok(false)` or `Err`.
    pub async fn refresh(
        self: &Arc<Self>,
        cfg: &TrafficSettings,
        db_dir: &Path,
    ) -> Result<bool, TrafficError> {
        std::fs::create_dir_all(db_dir)?;
        let client = http_client()?;

        let (active_url, etag, last_modified) = {
            let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
            (
                meta.source_url.clone(),
                meta.etag.clone(),
                meta.last_modified.clone(),
            )
        };

        let mut last_err: Option<TrafficError> = None;
        for source in resolve_sources(cfg) {
            // Validators are only meaningful for the URL they came from.
            let (cond_etag, cond_lm) = if source.url == active_url {
                (etag.as_deref(), last_modified.as_deref())
            } else {
                (None, None)
            };

            let (bytes, new_etag, new_lm) = match Self::fetch(&client, &source, cond_etag, cond_lm)
                .await
            {
                Ok(Fetched::Body {
                    bytes,
                    etag,
                    last_modified,
                }) => (bytes, etag, last_modified),
                Ok(Fetched::NotModified) => {
                    tracing::debug!(url = %source.redacted_url(), "geoip database unchanged");
                    return Ok(false);
                }
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip refresh source failed");
                    last_err = Some(e);
                    continue;
                }
            };

            let (reader, path) = match Self::install(&bytes, &source, db_dir) {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip refresh source unusable");
                    last_err = Some(e);
                    continue;
                }
            };

            // The new file is written and mapped; publish it before touching
            // the old one.
            self.db.store(Arc::new(reader));
            {
                let mut meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
                meta.path = path.clone();
                meta.etag = new_etag;
                meta.last_modified = new_lm;
                meta.source_url = source.url.clone();
            }
            tracing::info!(url = %source.redacted_url(), path = %path.display(), "geoip database refreshed");
            // Only now: the superseded file is unlinked strictly after the new
            // one is mapped and published. Readers still holding the old
            // mapping are unaffected — unlinking a mapped file does not
            // invalidate existing mappings on Linux.
            prune_old(db_dir, &path);
            return Ok(true);
        }

        Err(last_err.unwrap_or_else(|| {
            TrafficError::GeoIp("no geoip sources resolved from configuration".to_string())
        }))
    }

    /// Conditional GET of `source`. `etag`/`last_modified` are the validators
    /// for the *currently loaded* copy of this exact URL, if any.
    async fn fetch(
        client: &reqwest::Client,
        source: &Source,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<Fetched, TrafficError> {
        let mut req = client.get(&source.url);
        // Prefer ETag: servers that receive both validators ignore the date.
        if let Some(etag) = etag {
            req = req.header(IF_NONE_MATCH, etag);
        } else if let Some(lm) = last_modified {
            req = req.header(IF_MODIFIED_SINCE, lm);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| TrafficError::Download(format!("{}: {e}", source.redacted_url())))?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !resp.status().is_success() {
            return Err(TrafficError::Download(format!(
                "{}: http {}",
                source.redacted_url(),
                resp.status()
            )));
        }
        if let Some(len) = resp.content_length()
            && len > MAX_DOWNLOAD_BYTES
        {
            return Err(TrafficError::Download(format!(
                "{}: content-length {len} exceeds {MAX_DOWNLOAD_BYTES}",
                source.redacted_url()
            )));
        }

        let header = |name: reqwest::header::HeaderName| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let etag = header(ETAG);
        let last_modified = header(LAST_MODIFIED);

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| TrafficError::Download(format!("{}: body: {e}", source.redacted_url())))?;
        if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err(TrafficError::Download(format!(
                "{}: body of {} bytes exceeds {MAX_DOWNLOAD_BYTES}",
                source.redacted_url(),
                bytes.len()
            )));
        }

        Ok(Fetched::Body {
            bytes: bytes.to_vec(),
            etag,
            last_modified,
        })
    }

    /// Unpack `bytes`, write them to a brand-new file under `db_dir`, and map
    /// it. Never touches an existing file.
    fn install(
        bytes: &[u8],
        source: &Source,
        db_dir: &Path,
    ) -> Result<(Reader<Mmap>, PathBuf), TrafficError> {
        let mmdb = extract_mmdb(bytes, &source.archive)?;
        let path = write_fresh(db_dir, &mmdb)?;

        // SAFETY: `Reader::open_mmap` requires that the mapped file is never
        // modified or truncated for as long as the returned `Reader` lives.
        // `write_fresh` above created `path` with `create_new(true)`, so it is
        // a filename no other file has ever occupied, and it was fully written
        // and closed before this call. Nothing in this crate ever reopens a
        // `geoip-*.mmdb` file for writing: every download lands on a new
        // timestamped path, and the only other operation performed on these
        // files is `prune_old`'s unlink of paths *other* than the live one.
        // Unlinking is not modification or truncation, and on Linux an
        // existing mapping survives its file being unlinked, so even a reader
        // still in flight during a swap stays sound.
        #[allow(unsafe_code)]
        let reader = unsafe { Reader::open_mmap(&path) }.map_err(|e| {
            // The file is unusable; drop it rather than leave it for prune.
            let _ = std::fs::remove_file(&path);
            TrafficError::GeoIp(format!("open {}: {e}", path.display()))
        })?;

        Ok((reader, path))
    }
}

/// MaxMind's required GeoLite2 attribution string (MaxMind's EULA — see
/// spec §6). Applies whether the data came via the licensed-direct path or
/// the jsDelivr mirror, since the mirror redistributes the same data.
const MAXMIND_ATTRIBUTION: &str = "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com";

/// DB-IP's required attribution string for its CC-BY 4.0 licensed Lite data.
const DBIP_ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com)";

/// Classifies a resolved source URL into the attribution string its license
/// requires, or `None` if the URL isn't one of the two recognized,
/// license-obligated sources (e.g. an operator-supplied `GEOIP_DB_URL`
/// pointing somewhere else entirely — the operator is responsible for
/// whatever they pointed at).
fn classify_attribution(source_url: &str) -> Option<String> {
    if source_url == MIRROR_URL || source_url.starts_with("https://cdn.jsdelivr.net/") {
        // The mirror redistributes MaxMind GeoLite2-Country data.
        Some(MAXMIND_ATTRIBUTION.to_string())
    } else if source_url.starts_with("https://download.maxmind.com/") {
        Some(MAXMIND_ATTRIBUTION.to_string())
    } else if source_url.starts_with("https://download.db-ip.com/") {
        Some(DBIP_ATTRIBUTION.to_string())
    } else {
        None
    }
}

impl GeoIp {
    /// The attribution string required by the license of whichever source is
    /// *actually active* right now (spec §6). Since the winning source is
    /// resolved at runtime — it can be the jsDelivr mirror, the licensed
    /// MaxMind path, or the DB-IP fallback, depending on configuration and
    /// source availability — this reads the URL recorded in `meta` rather
    /// than assuming a fixed source. Total and panic-free: a poisoned mutex
    /// still yields its last-written value, and an unrecognized URL yields
    /// `None` rather than a guess.
    pub fn attribution(&self) -> Option<String> {
        let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        classify_attribution(&meta.source_url)
    }
}

impl CountryLookup for GeoIp {
    fn country(&self, ip: IpAddr) -> Option<String> {
        let guard = self.db.load();
        let result = guard.lookup(ip).ok()?;
        let record = result.decode::<geoip2::Country>().ok()??;
        record.country.iso_code.map(str::to_string)
    }
}

/// HTTP client for database downloads. Timeouts are generous: the MaxMind
/// tarball is tens of megabytes and this runs on a background schedule.
fn http_client() -> Result<reqwest::Client, TrafficError> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|e| TrafficError::Download(format!("client: {e}")))
}

/// Write `mmdb` to a path under `db_dir` that did not previously exist.
fn write_fresh(db_dir: &Path, mmdb: &[u8]) -> Result<PathBuf, TrafficError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // `create_new` makes the "never write over a mapped file" invariant an
    // enforced property rather than a convention; the counter only exists so a
    // freak nanosecond collision degrades to a retry instead of an error.
    for attempt in 0..16u32 {
        let path = if attempt == 0 {
            db_dir.join(format!("geoip-{stamp}.mmdb"))
        } else {
            db_dir.join(format!("geoip-{stamp}-{attempt}.mmdb"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(mmdb)?;
                file.sync_all()?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(TrafficError::GeoIp(format!(
        "could not allocate a fresh database filename in {}",
        db_dir.display()
    )))
}

/// Best-effort removal of every `geoip-*.mmdb` in `db_dir` except `keep`.
/// Called only after `keep` is mapped and published.
fn prune_old(db_dir: &Path, keep: &Path) {
    let entries = match std::fs::read_dir(db_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(dir = %db_dir.display(), error = %e, "geoip prune skipped");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == keep {
            continue;
        }
        let is_db = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("geoip-") && n.ends_with(".mmdb"));
        if !is_db {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::debug!(path = %path.display(), error = %e, "geoip prune failed");
        }
    }
}

#[cfg(test)]
mod tests {
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

        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        // A README member that must be skipped, then the real .mmdb, nested a
        // directory deep exactly like MaxMind's tarball layout.
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "GeoLite2-Country_20260801/README",
                &b"hello"[..],
            )
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "GeoLite2-Country_20260801/GeoLite2-Country.mmdb",
                &payload[..],
            )
            .unwrap();

        let archive = builder.into_inner().unwrap().finish().unwrap();

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
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "x/GeoLite2-Country.mmdb", &payload[..])
            .unwrap();
        let archive = builder.into_inner().unwrap().finish().unwrap();

        let err = extract_mmdb(&archive, &Archive::TarGz)
            .expect_err("an oversized member must be refused");
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
}
