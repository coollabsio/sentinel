// `deny`, not `forbid`: this module has the crate's only `unsafe` block
// (`Reader::open_mmap`), which needs a scoped `#[allow(unsafe_code)]` that
// `forbid` could not lift.
#![deny(unsafe_code)]

//! GeoIP database management and lookup. Sources are tried in configured
//! priority order, then decompressed, memory-mapped, and published through
//! [`ArcSwapOption`] for lock-free lookups during refresh. The old file is removed
//! only after the new mapping is live.

use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use config::TrafficSettings;
use flate2::read::GzDecoder;
use maxminddb::{Mmap, Reader};
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use serde::{Deserialize, Serialize};

use crate::TrafficError;
use crate::enrich::{GeoLocation, GeoLookup};

/// Default database source: a GeoLite2-City mirror published on npm and
/// served by the jsDelivr CDN. Requires no MaxMind account.
pub const MIRROR_URL: &str = "https://cdn.jsdelivr.net/npm/geolite2-city/GeoLite2-City.mmdb.gz";

/// Sidecar next to the database: which file is live, where it came from, and
/// its HTTP validators. Lets the next start reuse the file with no download.
const META_FILE: &str = "geoip.meta.json";

/// [`META_FILE`] is written here first, then renamed over it.
const META_TMP_FILE: &str = "geoip.meta.json.tmp";

/// Where a download body is spooled before it is unpacked.
const DOWNLOAD_FILE: &str = "geoip-download.tmp";

/// Gzip magic number; used to sanity-check URL-derived archive detection.
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Refuse bodies larger than this. The largest legitimate candidate (a
/// GeoLite2-City tarball) is well under 100 MiB.
const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Refuse *decompressed* payloads larger than this. [`MAX_DOWNLOAD_BYTES`]
/// bounds only the compressed body — a hostile `GEOIP_DB_URL` can serve a few
/// KiB that inflate to gigabytes and OOM the agent. GeoLite2-City is ~50 MiB
/// and DB-IP city lite ~125 MiB.
const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

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

/// Mask the value of a `license_key` query parameter. [`maxmind_url`] embeds
/// the operator's MaxMind credential in the download URL, which is logged on
/// every load/refresh and interpolated into every [`TrafficError::Download`],
/// so it must never reach a log line unmasked. Key-less URLs (mirror, DB-IP,
/// custom `GEOIP_DB_URL`) pass through untouched and unallocated.
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

/// Prefix shared by every DB-IP download URL.
const DBIP_PREFIX: &str = "https://download.db-ip.com/";

/// DB-IP's free city-lite download URL for a given year and month.
pub fn dbip_url(year: i32, month: u32) -> String {
    format!("https://download.db-ip.com/free/dbip-city-lite-{year:04}-{month:02}.mmdb.gz")
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

/// Copy `reader` to EOF into `out`, refusing anything past
/// [`MAX_DECOMPRESSED_BYTES`]. Reads one byte past the limit so hitting it is
/// distinguishable from legitimately ending there: an over-long payload is a
/// [`TrafficError::Decompress`], never a silent truncation handing a
/// half-written `.mmdb` to the parser. A failed write (a full disk) is a
/// [`TrafficError::Io`], so [`GeoIp::refresh`] can tell it from a bad body.
fn copy_bounded<R: Read>(reader: R, out: &mut impl Write, what: &str) -> Result<(), TrafficError> {
    let mut reader = reader.take(MAX_DECOMPRESSED_BYTES + 1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(TrafficError::Decompress(format!("{what}: {e}"))),
        };
        out.write_all(&buf[..n])?;
        copied += n as u64;
    }
    if copied > MAX_DECOMPRESSED_BYTES {
        return Err(TrafficError::Decompress(format!(
            "{what}: decompressed size exceeds {MAX_DECOMPRESSED_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Unpack a downloaded body into `out` as raw `.mmdb` bytes. Streams, so
/// neither the body nor the decompressed database is held in memory.
fn extract_mmdb(
    body: impl Read,
    archive: &Archive,
    out: &mut impl Write,
) -> Result<(), TrafficError> {
    let mut body = BufReader::new(body);
    let head = body
        .fill_buf()
        .map_err(|e| TrafficError::Decompress(format!("read body: {e}")))?;
    match reconcile_archive(archive, head) {
        Archive::Raw => copy_bounded(body, out, "raw database"),
        Archive::Gz => copy_bounded(GzDecoder::new(body), out, "gunzip"),
        Archive::TarGz => {
            let mut tar = tar::Archive::new(GzDecoder::new(body));
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
                return copy_bounded(entry, out, "tar member");
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

/// A file removed on drop unless kept: a failed download, or one shutdown
/// drops mid-body, leaves no partial file behind.
struct PartialFile(PathBuf);

impl PartialFile {
    /// The path, no longer removed on drop.
    fn keep(mut self) -> PathBuf {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// Outcome of a conditional GET.
enum Fetched {
    /// Server answered `304 Not Modified`.
    NotModified,
    /// Server answered with a body, spooled to the file at `body`.
    Body {
        body: PathBuf,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// On-disk form of [`Meta`], stored in [`META_FILE`]. `source` is the
/// redacted URL, so a MaxMind license key is never written to disk.
#[derive(Serialize, Deserialize)]
struct SavedMeta {
    file: String,
    source: String,
    etag: Option<String>,
    last_modified: Option<String>,
}

/// A memory-mapped GeoIP database with lock-free reads and atomic
/// hot-reload.
pub struct GeoIp {
    /// `None` until the first database is loaded.
    db: ArcSwapOption<Reader<Mmap>>,
    /// Bumped after each database `db` stores; `0` while there is none. See
    /// [`GeoLookup::generation`].
    generation: AtomicU64,
    meta: Mutex<Option<Meta>>,
    /// Held for a whole [`Self::refresh`]: every refresh spools to the same
    /// [`DOWNLOAD_FILE`] and deletes a leftover one first.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl GeoIp {
    /// Map the database a previous run left in `db_dir`, with no network
    /// access. `None` when there is none, or when it came from a source the
    /// current configuration no longer uses. The caller refreshes afterwards;
    /// the saved validators make that a `304` when nothing changed.
    pub fn open_cached(cfg: &TrafficSettings, db_dir: &Path) -> Option<Arc<GeoIp>> {
        remove_partial_files(db_dir);
        let saved = match std::fs::read(db_dir.join(META_FILE)) {
            Ok(saved) => saved,
            Err(e) => {
                tracing::debug!(dir = %db_dir.display(), error = %e, "geoip cache not used: no meta");
                return None;
            }
        };
        let saved: SavedMeta = match serde_json::from_slice(&saved) {
            Ok(saved) => saved,
            Err(e) => {
                tracing::debug!(error = %e, "geoip cache not used: bad meta");
                return None;
            }
        };
        if !is_db_name(&saved.file) {
            tracing::debug!(file = %saved.file, "geoip cache not used: bad file name");
            return None;
        }
        let sources = resolve_sources(cfg);
        let source_url =
            if let Some(source) = sources.iter().find(|s| s.redacted_url() == saved.source) {
                source.url.clone()
            } else if saved.source.starts_with(DBIP_PREFIX)
                && sources.iter().any(|s| s.url.starts_with(DBIP_PREFIX))
            {
                // DB-IP names a month in its URL, so an earlier month is no
                // longer a candidate but is still the configured provider. The
                // URL holds no secret; the next refresh walks the chain as usual.
                saved.source
            } else {
                tracing::debug!(source = %saved.source, "geoip cache not used: source changed");
                return None;
            };
        let path = db_dir.join(&saved.file);
        let reader = match map_database(&path) {
            Ok(reader) => reader,
            Err(e) => {
                tracing::debug!(error = %e, "geoip cache not used: map failed");
                return None;
            }
        };
        tracing::info!(path = %path.display(), "geoip database loaded from disk");
        prune_old(db_dir, &path);
        Some(Arc::new(GeoIp {
            db: ArcSwapOption::from_pointee(reader),
            generation: AtomicU64::new(1),
            meta: Mutex::new(Some(Meta {
                etag: saved.etag,
                last_modified: saved.last_modified,
                path,
                source_url,
            })),
            refresh_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// A `GeoIp` with no database: lookups resolve nothing until a
    /// [`Self::refresh`] succeeds.
    pub fn empty() -> Arc<GeoIp> {
        Arc::new(GeoIp {
            db: ArcSwapOption::empty(),
            generation: AtomicU64::new(0),
            meta: Mutex::new(None),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// True when a database is loaded.
    pub fn is_loaded(&self) -> bool {
        self.db.load().is_some()
    }

    /// Download and map a database, trying each [`resolve_sources`] candidate
    /// in order. Returns `Err` only when *every* candidate fails; on success
    /// the `GeoIp` always has a live mapping.
    pub async fn bootstrap(
        cfg: &TrafficSettings,
        db_dir: &Path,
    ) -> Result<Arc<GeoIp>, TrafficError> {
        let geo = Self::empty();
        geo.refresh(cfg, db_dir).await?;
        Ok(geo)
    }

    /// Re-check the sources and hot-swap in a newer database; on an empty
    /// `GeoIp` this is the first load. `Ok(true)` if a new database was
    /// swapped in, `Ok(false)` if the active source answered
    /// `304 Not Modified`, `Err` if every candidate failed or a local error
    /// (disk I/O) stopped the chain. The live database is never disturbed on
    /// `Ok(false)` or `Err`. Concurrent calls run one after another.
    pub async fn refresh(
        self: &Arc<Self>,
        cfg: &TrafficSettings,
        db_dir: &Path,
    ) -> Result<bool, TrafficError> {
        let client = client_builder(READ_TIMEOUT)
            .build()
            .map_err(|e| TrafficError::Download(format!("client: {e}")))?;
        self.refresh_from(resolve_sources(cfg), db_dir, &client)
            .await
    }

    /// [`Self::refresh`] over an explicit source list and client.
    async fn refresh_from(
        self: &Arc<Self>,
        sources: Vec<Source>,
        db_dir: &Path,
        client: &reqwest::Client,
    ) -> Result<bool, TrafficError> {
        let _refreshing = self.refresh_lock.lock().await;
        std::fs::create_dir_all(db_dir)?;
        // A refresh cut short (shutdown drops it mid-download) leaves these.
        remove_partial_files(db_dir);

        let (active_url, etag, last_modified) = {
            let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
            match meta.as_ref() {
                Some(meta) => (
                    Some(meta.source_url.clone()),
                    meta.etag.clone(),
                    meta.last_modified.clone(),
                ),
                None => (None, None, None),
            }
        };

        let mut last_err: Option<TrafficError> = None;
        for source in sources {
            // Validators are only meaningful for the URL they came from.
            let (cond_etag, cond_lm) = if active_url.as_deref() == Some(source.url.as_str()) {
                (etag.as_deref(), last_modified.as_deref())
            } else {
                (None, None)
            };

            let (body, new_etag, new_lm) = match Self::fetch(
                client, &source, db_dir, cond_etag, cond_lm,
            )
            .await
            {
                Ok(Fetched::Body {
                    body,
                    etag,
                    last_modified,
                }) => (body, etag, last_modified),
                Ok(Fetched::NotModified) => {
                    tracing::debug!(url = %source.redacted_url(), "geoip database unchanged");
                    return Ok(false);
                }
                // A full disk fails every source the same way.
                Err(e @ TrafficError::Io(_)) => return Err(e),
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip refresh source failed");
                    last_err = Some(e);
                    continue;
                }
            };

            let (reader, path) = match Self::install(body, &source, db_dir).await {
                Ok(v) => v,
                Err(e @ TrafficError::Io(_)) => return Err(e),
                Err(e) => {
                    tracing::debug!(url = %source.redacted_url(), error = %e, "geoip refresh source unusable");
                    last_err = Some(e);
                    continue;
                }
            };

            // The new file is written and mapped; publish it before touching
            // the old one.
            self.db.store(Some(Arc::new(reader)));
            // After the store: a reader that sees the new generation also
            // sees the new database.
            self.generation.fetch_add(1, Ordering::Release);
            let meta = Meta {
                etag: new_etag,
                last_modified: new_lm,
                path: path.clone(),
                source_url: source.url.clone(),
            };
            save_meta(db_dir, &meta);
            *self.meta.lock().unwrap_or_else(|e| e.into_inner()) = Some(meta);
            tracing::info!(url = %source.redacted_url(), path = %path.display(), "geoip database loaded");
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

    /// Conditional GET of `source`, with the body spooled to a file in
    /// `db_dir`. `etag`/`last_modified` are the validators for the *currently
    /// loaded* copy of this exact URL, if any.
    async fn fetch(
        client: &reqwest::Client,
        source: &Source,
        db_dir: &Path,
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

        let mut resp = req.send().await.map_err(|e| {
            TrafficError::Download(format!("{}: {}", source.redacted_url(), describe(e)))
        })?;

        if resp.status() == StatusCode::NOT_MODIFIED {
            // With no conditional headers sent, 304 is a protocol violation;
            // treat it as a failed candidate.
            if etag.is_none() && last_modified.is_none() {
                return Err(TrafficError::Download(format!(
                    "{}: unexpected 304 without conditional request",
                    source.redacted_url()
                )));
            }
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

        let body = PartialFile(db_dir.join(DOWNLOAD_FILE));
        Self::spool(&mut resp, source, &body.0).await?;

        Ok(Fetched::Body {
            body: body.keep(),
            etag,
            last_modified,
        })
    }

    /// Write the response body to `path` chunk by chunk, so a city database
    /// is never held in memory.
    async fn spool(
        resp: &mut reqwest::Response,
        source: &Source,
        path: &Path,
    ) -> Result<(), TrafficError> {
        let mut file = std::fs::File::create(path)?;
        let mut total = 0u64;
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            TrafficError::Download(format!("{}: body: {}", source.redacted_url(), describe(e)))
        })? {
            total += chunk.len() as u64;
            if total > MAX_DOWNLOAD_BYTES {
                return Err(TrafficError::Download(format!(
                    "{}: body exceeds {MAX_DOWNLOAD_BYTES} bytes",
                    source.redacted_url()
                )));
            }
            file.write_all(&chunk)?;
        }
        Ok(())
    }

    /// [`Self::install_blocking`] on a blocking thread: the gunzip, write and
    /// fsync of a city database take seconds.
    async fn install(
        body: PathBuf,
        source: &Source,
        db_dir: &Path,
    ) -> Result<(Reader<Mmap>, PathBuf), TrafficError> {
        let archive = source.archive;
        let db_dir = db_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let installed = Self::install_blocking(&body, &archive, &db_dir);
            let _ = std::fs::remove_file(&body);
            installed
        })
        .await
        .map_err(|e| TrafficError::GeoIp(format!("install task: {e}")))?
    }

    /// Unpack the spooled `body`, write it to a brand-new file under `db_dir`,
    /// and map it. Never touches an existing database file.
    fn install_blocking(
        body: &Path,
        archive: &Archive,
        db_dir: &Path,
    ) -> Result<(Reader<Mmap>, PathBuf), TrafficError> {
        let body = std::fs::File::open(body)?;
        let path = write_fresh(db_dir, |file| extract_mmdb(body, archive, file))?;
        let reader = map_database(&path).inspect_err(|_| {
            // The file is unusable; drop it rather than leave it for prune.
            let _ = std::fs::remove_file(&path);
        })?;
        Ok((reader, path))
    }
}

/// Memory-map the database file at `path`.
fn map_database(path: &Path) -> Result<Reader<Mmap>, TrafficError> {
    // SAFETY: `Reader::open_mmap` requires that the mapped file is never
    // modified or truncated for as long as the returned `Reader` lives.
    // `write_fresh` created `path` with `create_new(true)`, so it is a
    // filename no other file has ever occupied, and it was fully written,
    // synced and closed before this call (in this run, or in the earlier run
    // that `open_cached` reuses). Nothing in this crate ever reopens a
    // `geoip-*.mmdb` file for writing: every download lands on a new
    // timestamped path, and the only other operation performed on these
    // files is `prune_old`'s unlink of paths *other* than the live one.
    // Unlinking is not modification or truncation, and on Linux an
    // existing mapping survives its file being unlinked, so even a reader
    // still in flight during a swap stays sound.
    #[allow(unsafe_code)]
    unsafe { Reader::open_mmap(path) }
        .map_err(|e| TrafficError::GeoIp(format!("open {}: {e}", path.display())))
}

/// Best-effort write of the [`META_FILE`] sidecar for the live database. A
/// failure only costs the next start a download.
fn save_meta(db_dir: &Path, meta: &Meta) {
    let Some(file) = meta.path.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    let saved = SavedMeta {
        file: file.to_string(),
        source: redact_url(&meta.source_url).into_owned(),
        etag: meta.etag.clone(),
        last_modified: meta.last_modified.clone(),
    };
    // Rename, so a crash never leaves a half-written sidecar.
    let tmp = db_dir.join(META_TMP_FILE);
    let written = serde_json::to_vec(&saved)
        .map_err(std::io::Error::other)
        .and_then(|json| std::fs::write(&tmp, json))
        .and_then(|()| std::fs::rename(&tmp, db_dir.join(META_FILE)));
    if let Err(e) = written {
        tracing::debug!(dir = %db_dir.display(), error = %e, "geoip meta not saved");
    }
}

/// Best-effort removal of the temporary files an interrupted refresh leaves:
/// the spooled body and a half-written sidecar. Callers must hold no refresh
/// in progress in `db_dir` (see [`GeoIp::refresh`]'s lock).
fn remove_partial_files(db_dir: &Path) {
    for name in [DOWNLOAD_FILE, META_TMP_FILE] {
        let path = db_dir.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::debug!(path = %path.display(), "geoip partial file removed"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "geoip partial file not removed")
            }
        }
    }
}

/// True for the file names [`write_fresh`] makes.
fn is_db_name(name: &str) -> bool {
    name.starts_with("geoip-") && name.ends_with(".mmdb") && !name.contains(['/', '\\'])
}

/// MaxMind's required GeoLite2 attribution string (MaxMind's EULA — see
/// spec §6). Applies whether the data came via the licensed-direct path or
/// the jsDelivr mirror, since the mirror redistributes the same data.
const MAXMIND_ATTRIBUTION: &str = "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com";

/// DB-IP's required attribution string for its CC-BY 4.0 licensed Lite data.
const DBIP_ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com)";

/// Classifies a resolved source URL into the attribution string its license
/// requires, or `None` for an unrecognized source (e.g. an operator-supplied
/// `GEOIP_DB_URL` — their responsibility, not ours).
fn classify_attribution(source_url: &str) -> Option<String> {
    if source_url == MIRROR_URL || source_url.starts_with("https://cdn.jsdelivr.net/") {
        // The mirror redistributes MaxMind GeoLite2 data.
        Some(MAXMIND_ATTRIBUTION.to_string())
    } else if source_url.starts_with("https://download.maxmind.com/") {
        Some(MAXMIND_ATTRIBUTION.to_string())
    } else if source_url.starts_with(DBIP_PREFIX) {
        Some(DBIP_ATTRIBUTION.to_string())
    } else {
        None
    }
}

impl GeoIp {
    /// The attribution string required by the license of whichever source is
    /// *actually active* now (spec §6). Reads the runtime-resolved URL from
    /// `meta` rather than assuming a fixed source. Panic-free: a poisoned mutex
    /// still yields its last value, an unrecognized URL yields `None`.
    pub fn attribution(&self) -> Option<String> {
        let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        classify_attribution(&meta.as_ref()?.source_url)
    }
}

/// The fields of a GeoLite2 / DB-IP record that Sentinel keeps. Much smaller
/// than `geoip2::City`, so the per-request decode skips everything else.
#[derive(Debug, Default, Deserialize)]
struct Record<'a> {
    #[serde(borrow, default)]
    country: Place<'a>,
    #[serde(borrow, default)]
    subdivisions: Vec<Place<'a>>,
    #[serde(borrow, default)]
    city: Place<'a>,
    #[serde(default)]
    location: Location,
}

/// A country, subdivision or city entry.
#[derive(Debug, Default, Deserialize)]
struct Place<'a> {
    #[serde(borrow, default)]
    iso_code: Option<&'a str>,
    #[serde(borrow, default)]
    names: Names<'a>,
}

#[derive(Debug, Default, Deserialize)]
struct Names<'a> {
    #[serde(borrow, default)]
    en: Option<&'a str>,
}

#[derive(Debug, Default, Deserialize)]
struct Location {
    #[serde(default)]
    latitude: Option<f64>,
    #[serde(default)]
    longitude: Option<f64>,
}

/// Maps a decoded record onto the fields Sentinel keeps. A country-only
/// database decodes to a record with only the country set.
fn location_from(record: &Record<'_>) -> GeoLocation {
    let subdivision = record
        .subdivisions
        .first()
        .and_then(|s| s.names.en.or(s.iso_code));
    GeoLocation {
        country: record.country.iso_code.map(str::to_string),
        subdivision: subdivision.map(str::to_string),
        city: record.city.names.en.map(str::to_string),
        lat: record.location.latitude,
        lon: record.location.longitude,
    }
}

impl GeoLookup for GeoIp {
    fn locate(&self, ip: IpAddr) -> Option<GeoLocation> {
        let guard = self.db.load();
        let result = guard.as_ref()?.lookup(ip).ok()?;
        let record = result.decode::<Record>().ok()??;
        Some(location_from(&record))
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// Longest silence tolerated from a download server. Bounds each read, not
/// the whole download: a city database is 26-60 MB, which takes minutes on a
/// slow link.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Delay before the first retry after a failed download.
pub const RETRY_BASE: Duration = Duration::from_secs(15 * 60);

/// Retries are never further apart than this.
const RETRY_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Delay before the next download attempt after `failures` failures in a
/// row: [`RETRY_BASE`], doubled per further failure, capped at
/// `min(cap, 24 h)`.
pub fn retry_delay(failures: u32, cap: Duration) -> Duration {
    let doublings = failures.saturating_sub(1).min(31);
    RETRY_BASE
        .saturating_mul(1 << doublings)
        .min(cap)
        .min(RETRY_MAX)
}

/// Safety net for a server that trickles bytes just inside [`READ_TIMEOUT`].
/// 60 MB in an hour needs only about 140 kbit/s.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// HTTP client for database downloads (see [`READ_TIMEOUT`]).
fn client_builder(read_timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(read_timeout)
        .timeout(TOTAL_TIMEOUT)
}

/// `e` without its URL, which may hold the license key, saying so plainly
/// when it was a timeout.
fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        format!("timed out: {}", e.without_url())
    } else {
        e.without_url().to_string()
    }
}

/// Create a path under `db_dir` that did not previously exist and let `fill`
/// write the database into it. A failed `fill` removes the partial file.
fn write_fresh(
    db_dir: &Path,
    fill: impl FnOnce(&mut std::fs::File) -> Result<(), TrafficError>,
) -> Result<PathBuf, TrafficError> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    // `create_new` enforces the "never write over a mapped file" invariant;
    // the counter only lets a freak nanosecond collision retry instead of erroring.
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
                let written = fill(&mut file).and_then(|()| Ok(file.sync_all()?));
                if let Err(e) = written {
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
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
            .is_some_and(is_db_name);
        if !is_db {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::debug!(path = %path.display(), error = %e, "geoip prune failed");
        }
    }
}

#[cfg(test)]
mod tests;
