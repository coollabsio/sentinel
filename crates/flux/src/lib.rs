#![forbid(unsafe_code)]

mod credential;
mod internal_api;
mod negotiation;
mod registry;
mod reporter;
mod service;

pub use credential::{CredentialClaims, CredentialError, CredentialErrorKind, CredentialVerifier};
pub use internal_api::serve as serve_internal_api;
pub use negotiation::{Negotiated, negotiate};
pub use registry::{CommandDispatchError, ConnectionInfo, ConnectionRegistry, now_millis};
pub use reporter::EventReporter;
pub use service::AgentService;

#[cfg(test)]
mod tests;
