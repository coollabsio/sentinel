#![forbid(unsafe_code)]

mod credential;
mod internal_api;
mod negotiation;
mod registry;
mod reporter;
mod service;
mod tls;

pub use credential::{CredentialClaims, CredentialError, CredentialErrorKind, CredentialVerifier};
pub use internal_api::serve as serve_internal_api;
pub use negotiation::{Negotiated, negotiate};
pub use registry::{CommandDispatchError, ConnectionInfo, ConnectionRegistry, now_millis};
pub use reporter::{ConnectedEvent, EventReporter};
pub use service::AgentService;
pub use tls::{TlsConfigurationError, load_server_tls};

#[cfg(test)]
mod tests;
