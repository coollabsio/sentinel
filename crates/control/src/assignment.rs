use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use config::ControlTlsConfig;
use reqwest::StatusCode;
use sentinel_protocol::{
    CAPABILITY_CONTAINER_LIST, CAPABILITY_SYSTEM_INFO, CAPABILITY_SYSTEM_PING,
    CAPABILITY_WORKLOAD_DEPLOY, CAPABILITY_WORKLOAD_LIFECYCLE, PROTOCOL_MAX, PROTOCOL_MIN,
    select_protocol,
};
use serde::{Deserialize, Serialize};
use store::CommandJournal;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const ASSIGNMENT_PATH: &str = "/api/v1/sentinel/control/assignment";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ASSIGNMENT_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_HEARTBEAT_SECONDS: u64 = 10;
const MAX_HEARTBEAT_SECONDS: u64 = 120;
const DEFAULT_RATE_LIMIT_RETRY_DELAY: Duration = Duration::from_secs(60);
const AUTHENTICATION_RETRY_DELAY: Duration = Duration::from_secs(15 * 60);
const UNSUPPORTED_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);
const MAX_TEMPORARY_RETRY_SECONDS: u64 = 60;

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
    trust_bundle_version: u64,
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

    pub fn trust_bundle_version(&self) -> u64 {
        self.trust_bundle_version
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
            .field("trust_bundle_version", &self.trust_bundle_version)
            .finish()
    }
}

#[derive(Debug)]
pub enum AssignmentOutcome {
    Enabled(Assignment),
    Disabled { retry_after: Duration },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollStatus {
    Disabled,
    Enabled,
    Error(AssignmentErrorKind),
}

pub(crate) fn retry_delay(
    error: &AssignmentError,
    temporary_attempt: u32,
    jitter_seed: u64,
) -> Duration {
    match error {
        AssignmentError::AuthenticationRejected => AUTHENTICATION_RETRY_DELAY,
        AssignmentError::Unsupported
        | AssignmentError::Incompatible
        | AssignmentError::InvalidConfiguration(_)
        | AssignmentError::InvalidResponse(_) => UNSUPPORTED_RETRY_DELAY,
        AssignmentError::RateLimited { retry_after } => {
            retry_after.unwrap_or(DEFAULT_RATE_LIMIT_RETRY_DELAY)
        }
        AssignmentError::Temporary => {
            let ceiling = 1_u64
                .checked_shl(temporary_attempt.min(6))
                .unwrap_or(MAX_TEMPORARY_RETRY_SECONDS)
                .min(MAX_TEMPORARY_RETRY_SECONDS);
            Duration::from_secs(1 + jitter_seed % ceiling)
        }
    }
}

fn jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        .into()
}

pub struct AssignmentClient {
    client: reqwest::Client,
    assignment_url: Url,
    token: String,
    sentinel_version: String,
    control_tls: ControlTlsConfig,
    command_journal: CommandJournal,
}

impl AssignmentClient {
    pub fn new(
        endpoint: &str,
        token: &str,
        sentinel_version: &str,
        control_tls: ControlTlsConfig,
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
            control_tls,
            command_journal: CommandJournal::open_in_memory(7, 100_000).map_err(|_| {
                AssignmentError::InvalidConfiguration("command journal could not start")
            })?,
        })
    }

    pub fn with_command_journal(mut self, command_journal: CommandJournal) -> Self {
        self.command_journal = command_journal;
        self
    }

    pub async fn request(&self) -> Result<AssignmentOutcome, AssignmentError> {
        let request = AssignmentRequest {
            sentinel_version: &self.sentinel_version,
            protocol_min: PROTOCOL_MIN,
            protocol_max: PROTOCOL_MAX,
            capabilities: [
                CAPABILITY_SYSTEM_PING,
                CAPABILITY_SYSTEM_INFO,
                CAPABILITY_CONTAINER_LIST,
                CAPABILITY_WORKLOAD_DEPLOY,
                CAPABILITY_WORKLOAD_LIFECYCLE,
            ],
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

    pub async fn run(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        tracing::info!("Sentinel control assignment polling started");
        let mut last_status = None;
        let mut temporary_attempt = 0;
        let mut connection_attempt = 0;
        let command_executor = Arc::new(tokio::sync::Mutex::new(
            crate::commands::CommandExecutor::with_journal(
                &self.sentinel_version,
                self.command_journal.clone(),
            ),
        ));

        loop {
            if *shutdown.borrow() {
                break;
            }

            let outcome = tokio::select! {
                _ = shutdown.changed() => break,
                outcome = self.request() => outcome,
            };

            let (status, retry_after) = match outcome {
                Ok(AssignmentOutcome::Disabled { retry_after }) => {
                    temporary_attempt = 0;
                    connection_attempt = 0;
                    let status = PollStatus::Disabled;
                    if last_status != Some(status) {
                        tracing::info!(
                            retry_after_seconds = retry_after.as_secs(),
                            "Sentinel control assignment is disabled"
                        );
                    }
                    (status, retry_after)
                }
                Ok(AssignmentOutcome::Enabled(assignment)) => {
                    temporary_attempt = 0;
                    let status = PollStatus::Enabled;
                    let retry_after = match crate::connection::connect(
                        &assignment,
                        &self.sentinel_version,
                        self.control_tls.clone(),
                        shutdown.clone(),
                        command_executor.clone(),
                    )
                    .await
                    {
                        Ok(()) => {
                            connection_attempt = 0;
                            Duration::from_secs(1)
                        }
                        Err(error) => {
                            let retry_after = retry_delay(
                                &AssignmentError::Temporary,
                                connection_attempt,
                                jitter_seed(),
                            );
                            tracing::warn!(%error, retry_after_seconds = retry_after.as_secs(), "Sentinel Flux connection failed");
                            connection_attempt = connection_attempt.saturating_add(1);
                            retry_after
                        }
                    };
                    (status, retry_after)
                }
                Err(error) => {
                    connection_attempt = 0;
                    let kind = error.kind();
                    let status = PollStatus::Error(kind);
                    let retry_after = retry_delay(&error, temporary_attempt, jitter_seed());
                    if last_status != Some(status) {
                        tracing::warn!(
                            error = %error,
                            retry_after_seconds = retry_after.as_secs(),
                            "Sentinel control assignment request failed"
                        );
                    }
                    if matches!(error, AssignmentError::Temporary) {
                        temporary_attempt = temporary_attempt.saturating_add(1);
                    } else {
                        temporary_attempt = 0;
                    }
                    (status, retry_after)
                }
            };
            last_status = Some(status);

            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(retry_after) => {}
            }
        }

        tracing::info!("Sentinel control assignment polling stopped");
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
    capabilities: [&'static str; 5],
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
    trust_bundle_version: Option<u64>,
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
        let trust_bundle_version = self
            .trust_bundle_version
            .filter(|version| *version > 0)
            .ok_or(AssignmentError::InvalidResponse(
                "trust bundle version is missing or invalid",
            ))?;

        Ok(AssignmentOutcome::Enabled(Assignment {
            server_id,
            flux_url,
            credential,
            credential_expires_at,
            protocol_min,
            protocol_max,
            heartbeat_interval: Duration::from_secs(heartbeat_seconds),
            trust_bundle_version,
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
