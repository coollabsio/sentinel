use std::fmt;
use std::time::Duration;

use reqwest::StatusCode;
use sentinel_protocol::{
    CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING, PROTOCOL_MAX, PROTOCOL_MIN, select_protocol,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const ASSIGNMENT_PATH: &str = "/api/v1/sentinel/control/assignment";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ASSIGNMENT_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_HEARTBEAT_SECONDS: u64 = 10;
const MAX_HEARTBEAT_SECONDS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentErrorKind {
    InvalidConfiguration,
    InvalidResponse,
    Authentication,
    Unsupported,
    Incompatible,
    RateLimited,
    Temporary,
}

#[derive(Debug, thiserror::Error)]
pub enum AssignmentError {
    #[error("invalid assignment client configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid assignment response: {0}")]
    InvalidResponse(&'static str),
    #[error("assignment authentication was rejected")]
    AuthenticationRejected,
    #[error("Coolify does not support Sentinel control assignment")]
    Unsupported,
    #[error("Sentinel control assignment is incompatible")]
    Incompatible,
    #[error("assignment request was rate limited")]
    RateLimited { retry_after: Option<Duration> },
    #[error("assignment service is temporarily unavailable")]
    Temporary,
}

impl AssignmentError {
    pub fn kind(&self) -> AssignmentErrorKind {
        match self {
            Self::InvalidConfiguration(_) => AssignmentErrorKind::InvalidConfiguration,
            Self::InvalidResponse(_) => AssignmentErrorKind::InvalidResponse,
            Self::AuthenticationRejected => AssignmentErrorKind::Authentication,
            Self::Unsupported => AssignmentErrorKind::Unsupported,
            Self::Incompatible => AssignmentErrorKind::Incompatible,
            Self::RateLimited { .. } => AssignmentErrorKind::RateLimited,
            Self::Temporary => AssignmentErrorKind::Temporary,
        }
    }
}

pub struct Assignment {
    server_id: String,
    flux_url: Url,
    credential: String,
    credential_expires_at: OffsetDateTime,
    protocol_min: u32,
    protocol_max: u32,
    heartbeat_interval: Duration,
}

impl Assignment {
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn flux_url(&self) -> &Url {
        &self.flux_url
    }

    pub fn credential(&self) -> &str {
        &self.credential
    }

    pub fn credential_expires_at(&self) -> OffsetDateTime {
        self.credential_expires_at
    }

    pub fn protocol_min(&self) -> u32 {
        self.protocol_min
    }

    pub fn protocol_max(&self) -> u32 {
        self.protocol_max
    }

    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }
}

impl fmt::Debug for Assignment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Assignment")
            .field("server_id", &self.server_id)
            .field("flux_url", &self.flux_url)
            .field("credential", &"[REDACTED]")
            .field("credential_expires_at", &self.credential_expires_at)
            .field("protocol_min", &self.protocol_min)
            .field("protocol_max", &self.protocol_max)
            .field("heartbeat_interval", &self.heartbeat_interval)
            .finish()
    }
}

#[derive(Debug)]
pub enum AssignmentOutcome {
    Enabled(Assignment),
    Disabled { retry_after: Duration },
}

pub struct AssignmentClient {
    client: reqwest::Client,
    assignment_url: Url,
    token: String,
    sentinel_version: String,
}

impl AssignmentClient {
    pub fn new(
        endpoint: &str,
        token: &str,
        sentinel_version: &str,
    ) -> Result<Self, AssignmentError> {
        let assignment_url = assignment_url(endpoint)?;
        if token.is_empty() {
            return Err(AssignmentError::InvalidConfiguration("token is empty"));
        }
        if sentinel_version.is_empty() {
            return Err(AssignmentError::InvalidConfiguration(
                "Sentinel version is empty",
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AssignmentError::InvalidConfiguration("HTTP client could not start"))?;

        Ok(Self {
            client,
            assignment_url,
            token: token.to_string(),
            sentinel_version: sentinel_version.to_string(),
        })
    }

    pub async fn request(&self) -> Result<AssignmentOutcome, AssignmentError> {
        let request = AssignmentRequest {
            sentinel_version: &self.sentinel_version,
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            capabilities: [CAPABILITY_SYSTEM_PING, CAPABILITY_SYSTEM_INFO],
        };
        let mut response = self
            .client
            .post(self.assignment_url.clone())
            .bearer_auth(&self.token)
            .json(&request)
            .send()
            .await
            .map_err(|_| AssignmentError::Temporary)?;

        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(AssignmentError::AuthenticationRejected);
            }
            StatusCode::NOT_FOUND => return Err(AssignmentError::Unsupported),
            StatusCode::CONFLICT => return Err(AssignmentError::Incompatible),
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .map(Duration::from_secs);
                return Err(AssignmentError::RateLimited { retry_after });
            }
            status if status.is_server_error() => return Err(AssignmentError::Temporary),
            status if !status.is_success() => {
                return Err(AssignmentError::InvalidResponse(
                    "assignment request was rejected",
                ));
            }
            _ => {}
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AssignmentError::Temporary)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_ASSIGNMENT_RESPONSE_BYTES {
                return Err(AssignmentError::InvalidResponse(
                    "response exceeds size limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let response: AssignmentResponse = serde_json::from_slice(&body)
            .map_err(|_| AssignmentError::InvalidResponse("response is not valid JSON"))?;
        response.validate()
    }
}

impl fmt::Debug for AssignmentClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssignmentClient")
            .field("assignment_url", &self.assignment_url)
            .field("token", &"[REDACTED]")
            .field("sentinel_version", &self.sentinel_version)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AssignmentRequest<'a> {
    sentinel_version: &'a str,
    protocol_min: u32,
    protocol_max: u32,
    capabilities: [&'static str; 2],
}

#[derive(Deserialize)]
struct AssignmentResponse {
    enabled: bool,
    server_id: Option<String>,
    flux_url: Option<String>,
    credential: Option<String>,
    credential_expires_at: Option<String>,
    protocol_min: Option<u32>,
    protocol_max: Option<u32>,
    heartbeat_interval_seconds: Option<u64>,
    retry_after_seconds: Option<u64>,
}

impl AssignmentResponse {
    fn validate(self) -> Result<AssignmentOutcome, AssignmentError> {
        if !self.enabled {
            let retry_after = self
                .retry_after_seconds
                .filter(|seconds| *seconds > 0)
                .ok_or(AssignmentError::InvalidResponse(
                    "disabled assignment has no positive retry delay",
                ))?;
            return Ok(AssignmentOutcome::Disabled {
                retry_after: Duration::from_secs(retry_after),
            });
        }

        let server_id = required(self.server_id, "server ID is missing")?;
        let credential = required(self.credential, "credential is missing")?;
        let flux_url = required(self.flux_url, "Flux URL is missing")?;
        let flux_url = parse_service_url(&flux_url)
            .map_err(|_| AssignmentError::InvalidResponse("Flux URL is invalid"))?;
        let expires_at = required(self.credential_expires_at, "credential expiry is missing")?;
        let credential_expires_at = OffsetDateTime::parse(&expires_at, &Rfc3339)
            .map_err(|_| AssignmentError::InvalidResponse("credential expiry is invalid"))?;
        let protocol_min = self.protocol_min.ok_or(AssignmentError::InvalidResponse(
            "protocol minimum is missing",
        ))?;
        let protocol_max = self.protocol_max.ok_or(AssignmentError::InvalidResponse(
            "protocol maximum is missing",
        ))?;
        if select_protocol(PROTOCOL_MIN, PROTOCOL_MAX, protocol_min, protocol_max).is_none() {
            return Err(AssignmentError::InvalidResponse(
                "protocol range is incompatible",
            ));
        }
        let heartbeat_seconds =
            self.heartbeat_interval_seconds
                .ok_or(AssignmentError::InvalidResponse(
                    "heartbeat interval is missing",
                ))?;
        if !(MIN_HEARTBEAT_SECONDS..=MAX_HEARTBEAT_SECONDS).contains(&heartbeat_seconds) {
            return Err(AssignmentError::InvalidResponse(
                "heartbeat interval is outside allowed limits",
            ));
        }

        Ok(AssignmentOutcome::Enabled(Assignment {
            server_id,
            flux_url,
            credential,
            credential_expires_at,
            protocol_min,
            protocol_max,
            heartbeat_interval: Duration::from_secs(heartbeat_seconds),
        }))
    }
}

fn required(value: Option<String>, message: &'static str) -> Result<String, AssignmentError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(AssignmentError::InvalidResponse(message))
}

fn assignment_url(endpoint: &str) -> Result<Url, AssignmentError> {
    let mut endpoint = parse_service_url(endpoint)
        .map_err(|_| AssignmentError::InvalidConfiguration("endpoint is invalid"))?;
    let base_path = endpoint.path().trim_end_matches('/');
    endpoint.set_path(&format!("{base_path}{ASSIGNMENT_PATH}"));
    Ok(endpoint)
}

fn parse_service_url(value: &str) -> Result<Url, ()> {
    let url = Url::parse(value).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    Ok(url)
}
