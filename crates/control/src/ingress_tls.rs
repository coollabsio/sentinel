//! HTTPS for the ingress. Certificates live in Corrosion: `tls_certificates`
//! holds each host's PEM chain and its private key, sealed with the cluster TLS
//! key; `acme_challenges` holds the HTTP-01 answers that every ingress Node
//! serves, so the CA can validate through any of them.
//!
//! Coolify sends the cluster TLS key only to ingress Nodes. The renderer writes
//! the usable certificates of routed hosts to files that only the Caddy user
//! reads and loads them with `load_files`, so private keys never enter the
//! Caddy JSON, which is world-readable.

use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sentinel_protocol::control::v1::{IngressCertificateStatus, IngressReconcileRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_parser::extensions::GeneralName;

use crate::ingress::{INGRESS_USER, valid_ingress_host};
use crate::network::{hash, write_if_changed};

pub(crate) const KEY_LENGTH: usize = 32;
const KEY_FILE: &str = "etc/coolify/network/ingress-tls.key";
const KEY_DIR: &str = "etc/coolify/network";
const ISSUER_FILE: &str = "etc/coolify/network/ingress-acme.json";
const ACME_CA_FILE: &str = "etc/coolify/network/ingress-acme-ca.pem";
const MAX_ACME_CA_LENGTH: usize = 65_536;
const MAX_INGRESS_ADDRESSES: usize = 64;
/// Inside the Caddy service's `StateDirectory`.
pub(crate) const CERTIFICATES_DIR: &str = "var/lib/coolify-ingress/certs";

pub(crate) fn validate_request(request: &IngressReconcileRequest) -> Result<(), String> {
    if request.tls_enabled && !request.enabled {
        return Err("HTTPS needs the ingress to be enabled.".into());
    }
    let key_valid = if request.tls_enabled {
        request.tls_key.len() == KEY_LENGTH
    } else {
        request.tls_key.is_empty()
    };
    if !key_valid {
        return Err("The ingress TLS key is invalid.".into());
    }
    if request.tls_issuer && !request.tls_enabled {
        return Err("The certificate issuer needs HTTPS to be enabled.".into());
    }
    if !request.tls_issuer {
        if !request.acme_directory_url.is_empty()
            || !request.ingress_public_ips.is_empty()
            || !request.acme_ca_pem.is_empty()
        {
            return Err("Only the certificate issuer gets ACME settings.".into());
        }
        return Ok(());
    }
    let directory = url::Url::parse(&request.acme_directory_url)
        .map_err(|_| "The ACME directory URL is invalid.".to_string())?;
    if directory.scheme() != "https" || request.acme_directory_url.len() > 2048 {
        return Err("The ACME directory URL must use HTTPS.".into());
    }
    if !request.acme_ca_pem.is_empty()
        && (request.acme_ca_pem.len() > MAX_ACME_CA_LENGTH
            || !rustls_pemfile::certs(&mut request.acme_ca_pem.as_bytes())
                .all(|certificate| certificate.is_ok())
            || rustls_pemfile::certs(&mut request.acme_ca_pem.as_bytes())
                .next()
                .is_none())
    {
        return Err("The ACME CA certificate is invalid.".into());
    }
    if request.ingress_public_ips.is_empty()
        || request.ingress_public_ips.len() > MAX_INGRESS_ADDRESSES
    {
        return Err(format!(
            "The certificate issuer needs 1 to {MAX_INGRESS_ADDRESSES} ingress addresses."
        ));
    }
    if request
        .ingress_public_ips
        .iter()
        .any(|address| address.parse::<IpAddr>().is_err())
    {
        return Err("An ingress address is invalid.".into());
    }
    Ok(())
}

/// What the certificate issuer needs to run without Coolify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IssuerSettings {
    pub(crate) directory_url: String,
    /// The public addresses of the ingress Nodes.
    pub(crate) public_ips: Vec<IpAddr>,
    /// Whether the issuer trusts only [`acme_ca_file`] for the directory.
    #[serde(default)]
    pub(crate) custom_ca: bool,
}

/// The test CA that the issuer trusts instead of the system roots.
pub(crate) fn acme_ca_file(root: &Path) -> PathBuf {
    root.join(ACME_CA_FILE)
}

/// The issuer settings, when this Node is the certificate issuer.
pub(crate) fn read_issuer(root: &Path) -> Option<IssuerSettings> {
    serde_json::from_slice(&fs::read(root.join(ISSUER_FILE)).ok()?).ok()
}

/// Stores or removes the cluster TLS key, which is the HTTPS switch of this
/// Node. The renderer removes certificate files after Caddy dropped them.
pub(crate) fn apply(root: &Path, request: &IngressReconcileRequest) -> Result<(), String> {
    if !request.tls_issuer {
        remove_file(&root.join(ISSUER_FILE))?;
    }
    if request.acme_ca_pem.is_empty() {
        remove_file(&root.join(ACME_CA_FILE))?;
    }
    if !request.tls_enabled {
        return remove_file(&root.join(KEY_FILE));
    }
    let directory = root.join(KEY_DIR);
    fs::create_dir_all(&directory)
        .and_then(|()| fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)))
        .map_err(|_| "The ingress TLS key directory could not be created.".to_string())?;
    write_if_changed(&root.join(KEY_FILE), &request.tls_key, 0o600)?;
    if request.tls_issuer {
        let settings = IssuerSettings {
            directory_url: request.acme_directory_url.clone(),
            public_ips: request
                .ingress_public_ips
                .iter()
                .filter_map(|address| address.parse().ok())
                .collect(),
            custom_ca: !request.acme_ca_pem.is_empty(),
        };
        if settings.custom_ca {
            write_if_changed(
                &root.join(ACME_CA_FILE),
                request.acme_ca_pem.as_bytes(),
                0o600,
            )?;
        }
        let encoded = serde_json::to_vec(&settings)
            .map_err(|_| "The issuer settings could not be encoded.".to_string())?;
        write_if_changed(&root.join(ISSUER_FILE), &encoded, 0o600)?;
    }
    Ok(())
}

/// Removes the TLS key and every certificate file. The caller holds
/// `ingress_lock` and has removed the Caddy configuration.
pub(crate) fn remove(root: &Path) -> Result<(), String> {
    remove_file(&root.join(ISSUER_FILE))?;
    remove_file(&root.join(ACME_CA_FILE))?;
    remove_file(&root.join(KEY_FILE))?;
    match fs::remove_dir_all(root.join(CERTIFICATES_DIR)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("The ingress certificates could not be removed.".into()),
    }
}

fn remove_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("A managed ingress TLS file could not be removed.".into()),
    }
}

/// The cluster TLS key, when HTTPS is enabled on this Node.
pub(crate) fn read_key(root: &Path) -> Option<[u8; KEY_LENGTH]> {
    fs::read(root.join(KEY_FILE)).ok()?.try_into().ok()
}

fn cipher(key: &[u8; KEY_LENGTH]) -> Result<LessSafeKey, String> {
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .map(LessSafeKey::new)
        .map_err(|_| "The ingress TLS key is invalid.".to_string())
}

/// Seals a secret for `context` (a certificate's host, or an ACME account's
/// directory): base64 of a random nonce followed by the ChaCha20-Poly1305
/// ciphertext, with the context as associated data, so a row copied to another
/// host does not open.
pub(crate) fn seal(key: &[u8; KEY_LENGTH], context: &str, secret: &[u8]) -> Result<String, String> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "No random nonce is available.".to_string())?;
    let mut buffer = secret.to_vec();
    cipher(key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(context.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| "A secret could not be sealed.".to_string())?;
    Ok(STANDARD.encode([nonce.as_slice(), buffer.as_slice()].concat()))
}

/// Opens a secret from [`seal`] for the same `context`.
pub(crate) fn open(key: &[u8; KEY_LENGTH], context: &str, sealed: &str) -> Result<Vec<u8>, String> {
    let invalid = || "A sealed certificate key is invalid.".to_string();
    let mut nonce = STANDARD.decode(sealed).map_err(|_| invalid())?;
    if nonce.len() <= NONCE_LEN {
        return Err(invalid());
    }
    let mut ciphertext = nonce.split_off(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| invalid())?;
    let plaintext = cipher(key)?
        .open_in_place(nonce, Aad::from(context.as_bytes()), &mut ciphertext)
        .map_err(|_| invalid())?;
    Ok(plaintext.to_vec())
}

/// One live HTTP-01 answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Challenge {
    pub(crate) host: String,
    pub(crate) token: String,
    pub(crate) key_authorization: String,
}

pub(crate) fn challenges_query_sql() -> &'static str {
    "SELECT host, token, key_authorization FROM acme_challenges WHERE expires_at > unixepoch() ORDER BY host, token"
}

fn base64url(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Keeps only well-formed answers: RFC 8555 tokens and key authorizations are
/// `token.thumbprint` in base64url.
pub(crate) fn parse_challenges(rows: &[Vec<Value>]) -> Vec<Challenge> {
    rows.iter()
        .filter_map(|row| {
            let text = |index: usize| row.get(index).and_then(Value::as_str);
            let host = text(0).filter(|host| valid_ingress_host(host))?;
            let token = text(1).filter(|token| base64url(token))?;
            let key_authorization = text(2)?;
            let (answered, thumbprint) = key_authorization.split_once('.')?;
            (answered == token && base64url(thumbprint)).then(|| Challenge {
                host: host.into(),
                token: token.into(),
                key_authorization: key_authorization.into(),
            })
        })
        .collect()
}

/// One `tls_certificates` row that carries a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredCertificate {
    pub(crate) host: String,
    pub(crate) certificate_pem: String,
    pub(crate) key_sealed: String,
}

pub(crate) fn certificates_query_sql() -> &'static str {
    "SELECT host, certificate_pem, key_sealed FROM tls_certificates WHERE certificate_pem != '' AND key_sealed != '' ORDER BY host"
}

pub(crate) fn parse_certificates(rows: &[Vec<Value>]) -> Vec<StoredCertificate> {
    rows.iter()
        .filter_map(|row| {
            let text = |index: usize| row.get(index).and_then(Value::as_str).map(str::to_string);
            Some(StoredCertificate {
                host: text(0)?,
                certificate_pem: text(1)?,
                key_sealed: text(2)?,
            })
        })
        .collect()
}

/// A certificate on disk that Caddy loads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LoadedCertificate {
    pub(crate) host: String,
    pub(crate) certificate_file: String,
    pub(crate) key_file: String,
    /// Changes with the certificate, so a renewal changes the Caddy JSON and
    /// Caddy reloads the files.
    pub(crate) fingerprint: String,
}

/// The private key PEM of `stored` when its chain is valid at `now`, names its
/// host and matches the key. Caddy refuses a whole configuration for one bad
/// pair, so a bad row must only lose its own host.
pub(crate) fn usable_key(
    key: &[u8; KEY_LENGTH],
    stored: &StoredCertificate,
    now: i64,
) -> Result<Vec<u8>, String> {
    let chain = rustls_pemfile::certs(&mut stored.certificate_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "The certificate is not valid PEM.".to_string())?;
    let leaf = chain.first().ok_or("The certificate is empty.")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|_| "The certificate cannot be parsed.".to_string())?;
    let validity = parsed.validity();
    if validity.not_before.timestamp() > now || validity.not_after.timestamp() <= now {
        return Err("The certificate is not valid now.".into());
    }
    let names_host = parsed
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|names| {
            names
                .value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(name) if name.eq_ignore_ascii_case(&stored.host)))
        });
    if !names_host {
        return Err("The certificate does not name its host.".into());
    }
    let private_pem = open(key, &stored.host, &stored.key_sealed)?;
    let private_key = rustls_pemfile::private_key(&mut private_pem.as_slice())
        .ok()
        .flatten()
        .ok_or("The certificate key is not valid PEM.")?;
    rustls::sign::CertifiedKey::from_der(
        chain,
        private_key,
        &rustls::crypto::ring::default_provider(),
    )
    .and_then(|certified| certified.keys_match())
    .map_err(|_| "The certificate does not match its key.".to_string())?;
    Ok(private_pem)
}

/// The UID and GID of the Caddy service user.
fn ingress_owner() -> Result<(u32, u32), String> {
    let id = |flag: &str| {
        Command::new("id")
            .args([flag, INGRESS_USER])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
            .ok_or_else(|| "The Coolify ingress service user is missing.".to_string())
    };
    Ok((id("-u")?, id("-g")?))
}

fn file_stem(host: &str) -> String {
    hash(host.as_bytes())[..32].to_string()
}

/// Writes the usable certificates of the routed `hosts` for Caddy and returns
/// them. Unusable rows are skipped. Files of other hosts stay until
/// [`remove_stale`] runs, after Caddy dropped them.
pub(crate) fn write_certificates(
    root: &Path,
    key: &[u8; KEY_LENGTH],
    stored: &[StoredCertificate],
    hosts: &HashSet<&str>,
    now: i64,
) -> Result<Vec<LoadedCertificate>, String> {
    let usable = stored
        .iter()
        .filter(|certificate| hosts.contains(certificate.host.as_str()))
        .filter_map(|certificate| match usable_key(key, certificate, now) {
            Ok(private_pem) => Some((certificate, private_pem)),
            Err(error) => {
                tracing::debug!(host = %certificate.host, %error, "skipped an ingress certificate");
                None
            }
        })
        .collect::<Vec<_>>();
    if usable.is_empty() {
        return Ok(Vec::new());
    }
    let directory = root.join(CERTIFICATES_DIR);
    let owner = if root == Path::new("/") {
        Some(ingress_owner()?)
    } else {
        None
    };
    let set_owner = |path: &Path, mode: u32| -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| "The ingress certificate permissions could not be set.".to_string())?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(path, Some(uid), Some(gid))
                .map_err(|_| "The ingress certificate owner could not be set.".to_string())?;
        }
        Ok(())
    };
    fs::create_dir_all(&directory)
        .map_err(|_| "The ingress certificate directory could not be created.".to_string())?;
    set_owner(&directory, 0o700)?;
    let mut loaded = Vec::with_capacity(usable.len());
    for (certificate, private_pem) in usable {
        let stem = file_stem(&certificate.host);
        let files = [
            (
                format!("{stem}.crt"),
                certificate.certificate_pem.as_bytes(),
            ),
            (format!("{stem}.key"), private_pem.as_slice()),
        ];
        for (name, contents) in &files {
            let path = directory.join(name);
            write_if_changed(&path, contents, 0o600)?;
            set_owner(&path, 0o600)?;
        }
        let in_service = |name: &str| {
            PathBuf::from("/")
                .join(CERTIFICATES_DIR)
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        loaded.push(LoadedCertificate {
            host: certificate.host.clone(),
            certificate_file: in_service(&files[0].0),
            key_file: in_service(&files[1].0),
            fingerprint: hash(certificate.certificate_pem.as_bytes())[..16].to_string(),
        });
    }
    loaded.sort();
    Ok(loaded)
}

/// Removes certificate files that the loaded configuration does not use.
pub(crate) fn remove_stale(root: &Path, loaded: &[LoadedCertificate]) -> Result<(), String> {
    let directory = root.join(CERTIFICATES_DIR);
    let Ok(entries) = fs::read_dir(&directory) else {
        return Ok(());
    };
    let keep = loaded
        .iter()
        .flat_map(|certificate| [&certificate.certificate_file, &certificate.key_file])
        .filter_map(|path| Path::new(path).file_name())
        .collect::<HashSet<_>>();
    for entry in entries.flatten() {
        if !keep.contains(entry.file_name().as_os_str()) {
            remove_file(&entry.path())?;
        }
    }
    Ok(())
}

/// The certificate state of every host, when this Node is the issuer. Empty
/// on other Nodes and when Corrosion cannot answer.
pub(crate) fn issuer_statuses(root: &Path) -> Vec<IngressCertificateStatus> {
    if read_issuer(root).is_none() {
        return Vec::new();
    }
    let Ok(Some(identity)) = crate::discovery::read_identity(root) else {
        return Vec::new();
    };
    let sql = "SELECT host, status, not_after, error, next_attempt_at FROM tls_certificates ORDER BY host LIMIT 10000";
    crate::discovery::corrosion_api(
        &identity.owner_node_ip,
        "queries",
        &serde_json::to_vec(sql).unwrap_or_default(),
    )
    .and_then(|output| crate::ingress::parse_query_events(&output))
    .map(|rows| {
        rows.iter()
            .filter_map(|row| {
                let text =
                    |index: usize| row.get(index).and_then(Value::as_str).map(str::to_string);
                let number = |index: usize| row.get(index).and_then(Value::as_i64);
                Some(IngressCertificateStatus {
                    host: text(0)?,
                    status: text(1)?,
                    not_after: number(2)?,
                    error: text(3)?,
                    next_attempt_at: number(4)?,
                })
            })
            .collect()
    })
    .unwrap_or_default()
}
