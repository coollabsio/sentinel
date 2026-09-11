use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

const AUDIENCE: &str = "flux";
const PURPOSE: &str = "v5-control-channel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialClaims {
    pub subject: String,
    pub capabilities: Vec<String>,
    pub protocol_min: u32,
    pub protocol_max: u32,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialErrorKind {
    Format,
    Algorithm,
    KeyId,
    Signature,
    Claims,
    Lifetime,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid Flux credential: {kind:?}")]
pub struct CredentialError {
    kind: CredentialErrorKind,
}

impl CredentialError {
    pub fn kind(&self) -> CredentialErrorKind {
        self.kind
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    purpose: String,
    sub: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    caps: Vec<String>,
    pmin: u32,
    pmax: u32,
}

pub struct CredentialVerifier {
    key_id: String,
    key: VerifyingKey,
    issuer: String,
    max_lifetime: Duration,
}

impl CredentialVerifier {
    pub fn new(
        key_id: impl Into<String>,
        key: [u8; 32],
        issuer: impl Into<String>,
        max_lifetime: Duration,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            key: VerifyingKey::from_bytes(&key).expect("32-byte Ed25519 key"),
            issuer: issuer.into(),
            max_lifetime,
        }
    }

    pub fn verify(&self, token: &str) -> Result<CredentialClaims, CredentialError> {
        let mut parts = token.split('.');
        let header_part = parts
            .next()
            .ok_or_else(|| error(CredentialErrorKind::Format))?;
        let claims_part = parts
            .next()
            .ok_or_else(|| error(CredentialErrorKind::Format))?;
        let signature_part = parts
            .next()
            .ok_or_else(|| error(CredentialErrorKind::Format))?;
        if parts.next().is_some() {
            return Err(error(CredentialErrorKind::Format));
        }
        let header: Header = decode_json(header_part)?;
        if header.alg != "EdDSA" {
            return Err(error(CredentialErrorKind::Algorithm));
        }
        if header.kid.as_deref() != Some(&self.key_id) {
            return Err(error(CredentialErrorKind::KeyId));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_part)
            .map_err(|_| error(CredentialErrorKind::Format))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| error(CredentialErrorKind::Format))?;
        self.key
            .verify(
                format!("{header_part}.{claims_part}").as_bytes(),
                &signature,
            )
            .map_err(|_| error(CredentialErrorKind::Signature))?;
        let claims: Claims = decode_json(claims_part)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let valid = claims.iss == self.issuer
            && claims.aud == AUDIENCE
            && claims.purpose == PURPOSE
            && !claims.sub.is_empty()
            && !claims.jti.is_empty()
            && claims.pmin > 0
            && claims.pmin <= claims.pmax
            && !claims.caps.is_empty()
            && claims
                .caps
                .iter()
                .all(|capability| !capability.is_empty() && capability != "*")
            && claims.iat <= now + 30
            && claims.nbf <= now
            && claims.exp > now;
        if !valid {
            return Err(error(CredentialErrorKind::Claims));
        }
        let lifetime = claims
            .exp
            .checked_sub(claims.iat)
            .ok_or_else(|| error(CredentialErrorKind::Lifetime))?;
        if lifetime <= 0 || lifetime as u64 > self.max_lifetime.as_secs() {
            return Err(error(CredentialErrorKind::Lifetime));
        }
        Ok(CredentialClaims {
            subject: claims.sub,
            capabilities: claims.caps,
            protocol_min: claims.pmin,
            protocol_max: claims.pmax,
            expires_at: claims.exp,
        })
    }
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, CredentialError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| error(CredentialErrorKind::Format))?;
    serde_json::from_slice(&bytes).map_err(|_| error(CredentialErrorKind::Format))
}

fn error(kind: CredentialErrorKind) -> CredentialError {
    CredentialError { kind }
}
