//! The certificate issuer: on the one ingress Node that Coolify marks as the
//! issuer, orders and renews a certificate for every routed host with ACME
//! HTTP-01, and stores it in Corrosion for every ingress Node to serve.
//!
//! One issuer per cluster replaces a distributed lock. Before the CA validates
//! a challenge, the issuer checks that every ingress Node already serves it, so
//! Corrosion replication cannot fail a validation. A host whose DNS does not
//! point to an ingress Node is not ordered, which protects the CA's failed
//! validation limit. Renewals keep running while Coolify is unavailable.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::ingress_tls::{IssuerSettings, KEY_LENGTH, open, seal};

pub(crate) const TICK: Duration = Duration::from_secs(60);
/// At most this many orders per tick, so a large cluster ramps up slowly and
/// stays below the CA's order rate limits.
const MAX_ORDERS_PER_TICK: usize = 5;
const ORDER_TIMEOUT: Duration = Duration::from_secs(300);
const CHALLENGE_TTL_SECONDS: i64 = 900;
const SELF_CHECK_ATTEMPTS: usize = 30;
const SELF_CHECK_INTERVAL: Duration = Duration::from_secs(2);
const DNS_RETRY_SECONDS: i64 = 600;
const MIN_BACKOFF_SECONDS: i64 = 3_600;
const MAX_BACKOFF_SECONDS: i64 = 86_400;
/// A certificate of a host without a route is kept this long, so a domain
/// that comes back soon needs no new order.
const ORPHAN_GRACE_SECONDS: i64 = 7 * 86_400;
const MAX_ERROR_LENGTH: usize = 500;

/// One `tls_certificates` row as the issuer plans with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertificateState {
    pub(crate) host: String,
    pub(crate) certificate_pem: String,
    pub(crate) status: String,
    pub(crate) next_attempt_at: i64,
    pub(crate) updated_at: i64,
}

fn states_query_sql() -> &'static str {
    "SELECT host, certificate_pem, status, next_attempt_at, updated_at FROM tls_certificates ORDER BY host"
}

fn parse_states(rows: &[Vec<Value>]) -> Vec<CertificateState> {
    rows.iter()
        .filter_map(|row| {
            let text = |index: usize| row.get(index).and_then(Value::as_str).map(str::to_string);
            let number = |index: usize| row.get(index).and_then(Value::as_i64);
            Some(CertificateState {
                host: text(0)?,
                certificate_pem: text(1)?,
                status: text(2)?,
                next_attempt_at: number(3)?,
                updated_at: number(4)?,
            })
        })
        .collect()
}

/// Whether a certificate must be renewed: in the last third of its lifetime,
/// or unreadable.
pub(crate) fn renewal_due(certificate_pem: &str, now: i64) -> bool {
    let Some(leaf) = rustls_pemfile::certs(&mut certificate_pem.as_bytes())
        .next()
        .and_then(Result::ok)
    else {
        return true;
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return true;
    };
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    not_after - now < (not_after - not_before) / 3
}

fn not_after(certificate_pem: &str) -> i64 {
    rustls_pemfile::certs(&mut certificate_pem.as_bytes())
        .next()
        .and_then(Result::ok)
        .and_then(|leaf| {
            x509_parser::parse_x509_certificate(leaf.as_ref())
                .ok()
                .map(|(_, parsed)| parsed.validity().not_after.timestamp())
        })
        .unwrap_or_default()
}

/// What one tick does: the hosts to order now, and the bookkeeping writes for
/// certificates of hosts that lost their route.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct TickPlan {
    pub(crate) order: Vec<String>,
    pub(crate) housekeeping: Vec<Value>,
}

pub(crate) fn plan(hosts: &BTreeSet<String>, states: &[CertificateState], now: i64) -> TickPlan {
    let by_host = states
        .iter()
        .map(|state| (state.host.as_str(), state))
        .collect::<HashMap<_, _>>();
    let mut plan = TickPlan::default();
    for host in hosts {
        let due = match by_host.get(host.as_str()) {
            None => true,
            Some(state) => {
                state.next_attempt_at <= now
                    && (state.certificate_pem.is_empty()
                        || renewal_due(&state.certificate_pem, now))
            }
        };
        if due && plan.order.len() < MAX_ORDERS_PER_TICK {
            plan.order.push(host.clone());
        }
        if by_host
            .get(host.as_str())
            .is_some_and(|state| state.status == "orphaned")
        {
            plan.housekeeping.push(json!([
                "UPDATE tls_certificates SET status = CASE WHEN certificate_pem != '' THEN 'issued' ELSE 'pending' END, updated_at = ? WHERE host = ? AND status = 'orphaned'",
                [now, host]
            ]));
        }
    }
    for state in states.iter().filter(|state| !hosts.contains(&state.host)) {
        if state.status != "orphaned" {
            plan.housekeeping.push(json!([
                "UPDATE tls_certificates SET status = 'orphaned', updated_at = ? WHERE host = ?",
                [now, state.host]
            ]));
        } else if state.updated_at < now - ORPHAN_GRACE_SECONDS {
            plan.housekeeping.push(json!([
                "DELETE FROM tls_certificates WHERE host = ? AND status = 'orphaned'",
                [state.host]
            ]));
        }
    }
    plan.housekeeping.push(json!([
        "DELETE FROM acme_challenges WHERE expires_at < ?",
        [now]
    ]));
    plan
}

/// The next attempt after a failure: doubles the previous wait, from one hour
/// to one day.
pub(crate) fn backoff(previous: Option<&CertificateState>, now: i64) -> i64 {
    let wait = previous
        .filter(|state| state.status == "failed")
        .map(|state| (state.next_attempt_at - state.updated_at) * 2)
        .unwrap_or(MIN_BACKOFF_SECONDS)
        .clamp(MIN_BACKOFF_SECONDS, MAX_BACKOFF_SECONDS);
    now + wait
}

enum IssueError {
    /// The host does not resolve to an ingress Node.
    Dns(String),
    Failed(String),
}

impl<E: std::fmt::Display> From<E> for IssueError {
    fn from(error: E) -> Self {
        Self::Failed(error.to_string())
    }
}

fn truncate(message: &str) -> String {
    message.chars().take(MAX_ERROR_LENGTH).collect()
}

/// Runs a blocking Corrosion call off the async runtime.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|_| "A Corrosion call failed.".to_string())?
}

async fn query(owner: &str, sql: &'static str) -> Result<Vec<Vec<Value>>, String> {
    let owner = owner.to_string();
    blocking(move || {
        crate::discovery::corrosion_api(
            &owner,
            "queries",
            &serde_json::to_vec(sql).unwrap_or_default(),
        )
        .and_then(|output| crate::ingress::parse_query_events(&output))
    })
    .await
}

async fn write(owner: &str, transaction: Vec<Value>) -> Result<(), String> {
    let owner = owner.to_string();
    blocking(move || crate::discovery::post_transaction(&owner, &transaction)).await
}

fn account_context(directory_url: &str) -> String {
    format!("acme-account:{directory_url}")
}

/// The ACME client: the system roots, or only the configured test CA.
fn builder(root: &Path, settings: &IssuerSettings) -> Result<AccountBuilder, String> {
    if settings.custom_ca {
        return Account::builder_with_root(crate::ingress_tls::acme_ca_file(root))
            .map_err(|error| format!("The ACME CA certificate could not be loaded: {error}"));
    }
    Account::builder().map_err(|error| error.to_string())
}

/// The ACME account for the directory: from Corrosion, or registered once and
/// stored there, so a new issuer keeps the same account.
async fn account(
    root: &Path,
    owner: &str,
    key: &[u8; KEY_LENGTH],
    settings: &IssuerSettings,
) -> Result<Account, String> {
    let directory_url = settings.directory_url.as_str();
    let rows = query(
        owner,
        "SELECT directory_url, credentials_sealed FROM acme_accounts",
    )
    .await?;
    let stored = rows.iter().find_map(|row| {
        (row.first().and_then(Value::as_str) == Some(directory_url))
            .then(|| row.get(1).and_then(Value::as_str).map(str::to_string))
            .flatten()
    });
    let context = account_context(directory_url);
    if let Some(sealed) = stored {
        let credentials: AccountCredentials = open(key, &context, &sealed).and_then(|plain| {
            serde_json::from_slice(&plain)
                .map_err(|_| "The stored ACME account is invalid.".to_string())
        })?;
        return builder(root, settings)?
            .from_credentials(credentials)
            .await
            .map_err(|error| format!("The ACME account could not be restored: {error}"));
    }
    let (account, credentials) = builder(root, settings)?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await
        .map_err(|error| format!("The ACME account could not be registered: {error}"))?;
    let plain = serde_json::to_vec(&credentials)
        .map_err(|_| "The ACME account could not be encoded.".to_string())?;
    write(
        owner,
        vec![json!([
            "INSERT INTO acme_accounts (directory_url, credentials_sealed, updated_at) VALUES (?, ?, ?) ON CONFLICT (directory_url) DO UPDATE SET credentials_sealed = excluded.credentials_sealed, updated_at = excluded.updated_at",
            [directory_url, seal(key, &context, &plain)?, crate::network::unix_seconds()]
        ])],
    )
    .await?;
    tracing::info!(directory_url, "registered an ACME account");
    Ok(account)
}

/// The public addresses of ingress Nodes that `host` resolves to: the ones
/// the CA validates through. Fails when there is none.
async fn check_dns(host: &str, ingress: &[IpAddr]) -> Result<Vec<IpAddr>, IssueError> {
    let found = tokio::net::lookup_host((host, 80))
        .await
        .map(|addresses| addresses.map(|address| address.ip()).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut targets = found
        .iter()
        .filter(|address| ingress.contains(address))
        .copied()
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    if !targets.is_empty() {
        return Ok(targets);
    }
    let found = if found.is_empty() {
        "no address".to_string()
    } else {
        found
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    Err(IssueError::Dns(format!(
        "{host} resolves to {found}, not to an ingress server."
    )))
}

/// Waits until every ingress Node that the host resolves to serves the
/// challenge answer on its public address, the path the CA uses. An ingress
/// Node that DNS does not point to cannot fail a validation, so an offline one
/// does not block orders. The cluster firewall drops port 80 over WireGuard,
/// so the check does not use it.
async fn self_check(
    host: &str,
    token: &str,
    key_authorization: &str,
    ingress: &[IpAddr],
) -> Result<(), IssueError> {
    let url = format!("http://{host}/.well-known/acme-challenge/{token}");
    for public_ip in ingress {
        let address = SocketAddr::new(*public_ip, 80);
        let client = reqwest::Client::builder()
            .no_proxy()
            .resolve(host, address)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()?;
        let mut served = false;
        for _ in 0..SELF_CHECK_ATTEMPTS {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
                && response
                    .text()
                    .await
                    .is_ok_and(|body| body == key_authorization)
            {
                served = true;
                break;
            }
            tokio::time::sleep(SELF_CHECK_INTERVAL).await;
        }
        if !served {
            return Err(IssueError::Failed(format!(
                "The ingress server {public_ip} does not serve the challenge for {host}."
            )));
        }
    }
    Ok(())
}

/// Orders one certificate. Returns the certificate chain and private key PEM.
async fn issue(
    account: &Account,
    owner: &str,
    host: &str,
    ingress: &[IpAddr],
) -> Result<(String, String), IssueError> {
    let targets = check_dns(host, ingress).await?;
    let identifiers = [Identifier::Dns(host.to_string())];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
    let mut authorizations = order.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => {
                return Err(IssueError::Failed(format!(
                    "The CA reports the authorization as {status:?}."
                )));
            }
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| IssueError::Failed("The CA offers no HTTP-01 challenge.".into()))?;
        let token = challenge.token.clone();
        let key_authorization = challenge.key_authorization().as_str().to_string();
        write(
            owner,
            vec![json!([
                "INSERT INTO acme_challenges (token, host, key_authorization, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT (token) DO UPDATE SET host = excluded.host, key_authorization = excluded.key_authorization, expires_at = excluded.expires_at",
                [token, host, key_authorization, crate::network::unix_seconds() + CHALLENGE_TTL_SECONDS]
            ])],
        )
        .await?;
        self_check(host, &token, &key_authorization, &targets).await?;
        challenge.set_ready().await?;
    }
    let retries = RetryPolicy::new().timeout(Duration::from_secs(120));
    let status = order.poll_ready(&retries).await?;
    if status != OrderStatus::Ready {
        let problem = order
            .state()
            .error
            .as_ref()
            .and_then(|problem| problem.detail.clone())
            .unwrap_or_else(|| format!("{status:?}"));
        return Err(IssueError::Failed(format!(
            "The CA did not validate {host}: {problem}"
        )));
    }
    let private_key_pem = order.finalize().await?;
    let certificate_pem = order.poll_certificate(&retries).await?;
    Ok((certificate_pem, private_key_pem))
}

/// The certificate row after one order: the new certificate, or the failure
/// and the next attempt. A failure keeps the stored certificate.
fn result_row(
    key: &[u8; KEY_LENGTH],
    host: &str,
    outcome: Result<(String, String), IssueError>,
    previous: Option<&CertificateState>,
    now: i64,
) -> Result<Value, String> {
    let (status, error, next_attempt_at) = match outcome {
        Ok((certificate_pem, private_key_pem)) => {
            return Ok(json!([
                "INSERT INTO tls_certificates (host, certificate_pem, key_sealed, not_after, status, error, next_attempt_at, updated_at) VALUES (?, ?, ?, ?, 'issued', '', 0, ?) ON CONFLICT (host) DO UPDATE SET certificate_pem = excluded.certificate_pem, key_sealed = excluded.key_sealed, not_after = excluded.not_after, status = excluded.status, error = excluded.error, next_attempt_at = excluded.next_attempt_at, updated_at = excluded.updated_at",
                [
                    host,
                    certificate_pem,
                    seal(key, host, private_key_pem.as_bytes())?,
                    not_after(&certificate_pem),
                    now
                ]
            ]));
        }
        Err(IssueError::Dns(message)) => ("dns_mismatch", message, now + DNS_RETRY_SECONDS),
        Err(IssueError::Failed(message)) => ("failed", message, backoff(previous, now)),
    };
    Ok(json!([
        "INSERT INTO tls_certificates (host, status, error, next_attempt_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (host) DO UPDATE SET status = excluded.status, error = excluded.error, next_attempt_at = excluded.next_attempt_at, updated_at = excluded.updated_at",
        [host, status, truncate(&error), next_attempt_at, now]
    ]))
}

/// The account in use, kept between ticks for one directory.
#[derive(Default)]
struct IssuerState {
    account: Option<(String, Account)>,
}

async fn tick(root: &Path, state: &mut IssuerState) -> Result<(), String> {
    let Some(settings) = crate::ingress_tls::read_issuer(root) else {
        state.account = None;
        return Ok(());
    };
    let Some(key) = crate::ingress_tls::read_key(root) else {
        return Ok(());
    };
    let root_owned = root.to_path_buf();
    let Some(identity) = blocking(move || crate::discovery::read_identity(&root_owned)).await?
    else {
        return Ok(());
    };
    let owner = identity.owner_node_ip;
    let routes = {
        let owner = owner.clone();
        blocking(move || crate::ingress::read_stored_routes(&owner)).await?
    };
    let hosts = routes
        .routes
        .into_iter()
        .map(|route| route.host)
        .collect::<BTreeSet<_>>();
    let states = parse_states(&query(&owner, states_query_sql()).await?);
    let now = crate::network::unix_seconds();
    let plan = plan(&hosts, &states, now);
    write(&owner, plan.housekeeping).await?;
    if plan.order.is_empty() {
        return Ok(());
    }
    let account = account_for(root, state, &owner, &key, &settings).await?;
    for host in plan.order {
        let outcome = tokio::time::timeout(
            ORDER_TIMEOUT,
            issue(&account, &owner, &host, &settings.public_ips),
        )
        .await
        .unwrap_or_else(|_| Err(IssueError::Failed("The order timed out.".into())));
        match &outcome {
            Ok(_) => tracing::info!(%host, "issued an ingress certificate"),
            Err(IssueError::Dns(error)) => {
                tracing::info!(%host, %error, "skipped an ingress certificate")
            }
            Err(IssueError::Failed(error)) => {
                tracing::warn!(%host, %error, "could not issue an ingress certificate")
            }
        }
        let previous = states.iter().find(|state| state.host == host);
        let row = result_row(
            &key,
            &host,
            outcome,
            previous,
            crate::network::unix_seconds(),
        )?;
        write(
            &owner,
            vec![
                row,
                json!(["DELETE FROM acme_challenges WHERE host = ?", [host]]),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn account_for(
    root: &Path,
    state: &mut IssuerState,
    owner: &str,
    key: &[u8; KEY_LENGTH],
    settings: &IssuerSettings,
) -> Result<Account, String> {
    if let Some((directory_url, account)) = &state.account
        && *directory_url == settings.directory_url
    {
        return Ok(account.clone());
    }
    let account = account(root, owner, key, settings).await?;
    state.account = Some((settings.directory_url.clone(), account.clone()));
    Ok(account)
}

/// Runs the issuer every [`TICK`] until shutdown. It does nothing on Nodes
/// that are not the issuer.
pub(crate) async fn run(root: PathBuf, mut shutdown: watch::Receiver<bool>) {
    crate::connection::install_crypto_provider();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state = IssuerState::default();
    let mut last_error: Option<String> = None;
    loop {
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {}
        }
        match tick(&root, &mut state).await {
            Ok(()) => {
                if last_error.take().is_some() {
                    tracing::info!("the certificate issuer recovered");
                }
            }
            Err(error) => {
                if last_error.as_deref() != Some(error.as_str()) {
                    tracing::warn!(%error, "the certificate issuer could not run");
                }
                last_error = Some(error);
            }
        }
    }
}
