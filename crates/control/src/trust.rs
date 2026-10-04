//! The Flux CA trust bundle that Sentinel uses to verify Flux.
//!
//! The bundle lives at `FLUX_CA_PATH`; its version lives next to it in a
//! `.version` file, the same pair that the SSH install and repair scripts
//! write. Coolify can replace the pair over the authenticated Flux channel
//! (`trust.bundle.update.v1`) to stage a CA rotation. The TLS client reads the
//! bundle from disk on every connection, so an update applies to the next
//! connection without a restart.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use config::ControlTlsConfig;

/// Upper bound on the encoded bundle. A CA certificate is about 1 KiB.
pub(crate) const MAX_BUNDLE_BYTES: usize = 64 * 1024;
/// A rotation needs two CAs; leave room without accepting arbitrary lists.
pub(crate) const MAX_BUNDLE_CERTIFICATES: usize = 8;
const VERSION_FILE_BYTES: u64 = 32;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TrustBundleUpdate {
    pub(crate) installed_version: u64,
    pub(crate) changed: bool,
}

pub(crate) fn version_path(ca_path: &Path) -> PathBuf {
    ca_path.with_extension("version")
}

/// The version of the installed bundle: the version file written next to the
/// bundle when it is present and valid, otherwise the configured version.
pub(crate) fn installed_version(control_tls: &ControlTlsConfig) -> u64 {
    read_version(&version_path(&control_tls.ca_path)).unwrap_or(control_tls.trust_bundle_version)
}

fn read_version(path: &Path) -> Option<u64> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > VERSION_FILE_BYTES {
        return None;
    }
    fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|version| *version > 0)
}

/// Checks that `bundle` contains only PEM CA certificates that are not expired.
pub(crate) fn validate_bundle(bundle: &str) -> Result<usize, String> {
    if bundle.trim().is_empty() {
        return Err("The trust bundle is empty.".into());
    }
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err("The trust bundle exceeds the size limit.".into());
    }
    // Only certificate blocks and blank lines are allowed, so a private key or
    // stray text never reaches the trust store.
    let mut inside = false;
    for line in bundle.lines().map(str::trim) {
        match (inside, line) {
            (false, "") => {}
            (false, "-----BEGIN CERTIFICATE-----") => inside = true,
            (true, "-----END CERTIFICATE-----") => inside = false,
            (true, line) if !line.starts_with("-----") => {}
            _ => return Err("The trust bundle may contain only PEM certificates.".into()),
        }
    }
    if inside {
        return Err("The trust bundle has an unterminated certificate.".into());
    }
    let certificates = rustls_pemfile::certs(&mut bundle.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "The trust bundle is not valid PEM.".to_string())?;
    if certificates.is_empty() {
        return Err("The trust bundle has no certificates.".into());
    }
    if certificates.len() > MAX_BUNDLE_CERTIFICATES {
        return Err("The trust bundle has too many certificates.".into());
    }
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    for certificate in &certificates {
        let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
            .map_err(|_| "The trust bundle has an invalid certificate.".to_string())?;
        if !remaining.is_empty() {
            return Err("The trust bundle has an invalid certificate.".into());
        }
        let is_ca = parsed
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca);
        if !is_ca {
            return Err("Every trust bundle certificate must be a CA certificate.".into());
        }
        if parsed.validity().not_after.timestamp() <= now {
            return Err("The trust bundle has an expired CA certificate.".into());
        }
    }
    Ok(certificates.len())
}

/// Installs `bundle` as trust bundle `version`.
///
/// The bundle is written before the version file, so a crash in between
/// leaves a newer bundle under the older version: Sentinel keeps reporting the
/// older version and Coolify delivers the bundle again. The replaced bundle and
/// version stay as `.previous` files, and a failed version write restores the
/// previous bundle.
pub(crate) fn install(
    control_tls: &ControlTlsConfig,
    version: u64,
    bundle: &str,
) -> Result<TrustBundleUpdate, String> {
    let ca_path = &control_tls.ca_path;
    let installed = installed_version(control_tls);
    if version == 0 {
        return Err("The trust bundle version is invalid.".into());
    }
    if version < installed {
        return Err(format!(
            "Trust bundle version {version} is older than installed version {installed}."
        ));
    }
    if version == installed {
        return match fs::read(ca_path) {
            Ok(current) if current == bundle.as_bytes() => Ok(TrustBundleUpdate {
                installed_version: installed,
                changed: false,
            }),
            _ => Err(format!(
                "Trust bundle version {version} is already installed with different contents."
            )),
        };
    }
    validate_bundle(bundle)?;

    let version_path = version_path(ca_path);
    let previous_bundle = sibling(ca_path, "previous");
    let staged_bundle = sibling(ca_path, "update");
    let staged_version = sibling(&version_path, "update");
    let had_bundle = ca_path.is_file();
    let result: Result<(), String> = (|| {
        write_synced(&staged_bundle, bundle.as_bytes())?;
        write_synced(&staged_version, format!("{version}\n").as_bytes())?;
        if had_bundle {
            fs::copy(ca_path, &previous_bundle)
                .map_err(|_| "Cannot keep the previous trust bundle.".to_string())?;
            if version_path.is_file() {
                let _ = fs::copy(&version_path, sibling(&version_path, "previous"));
            }
        }
        fs::rename(&staged_bundle, ca_path)
            .map_err(|_| "Cannot replace the trust bundle.".to_string())?;
        if fs::rename(&staged_version, &version_path).is_err() {
            let restored = if had_bundle {
                fs::copy(&previous_bundle, &staged_bundle).is_ok()
                    && fs::rename(&staged_bundle, ca_path).is_ok()
            } else {
                fs::remove_file(ca_path).is_ok()
            };
            return Err(if restored {
                "Cannot record the trust bundle version. The previous bundle was restored.".into()
            } else {
                "Cannot record the trust bundle version or restore the previous bundle.".into()
            });
        }
        sync_directory(ca_path);
        Ok(())
    })();
    let _ = fs::remove_file(&staged_bundle);
    let _ = fs::remove_file(&staged_version);
    result?;
    tracing::info!(version, "Sentinel installed a new Flux trust bundle");

    Ok(TrustBundleUpdate {
        installed_version: version,
        changed: true,
    })
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

fn write_synced(path: &Path, contents: &[u8]) -> Result<(), String> {
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|_| "Cannot stage the trust bundle.".to_string())?;
    file.write_all(contents)
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o644)))
        .and_then(|()| file.sync_all())
        .map_err(|_| "Cannot write the trust bundle.".to_string())
}

fn sync_directory(path: &Path) {
    if let Some(directory) = path.parent()
        && let Ok(directory) = File::open(directory)
    {
        let _ = directory.sync_all();
    }
}
