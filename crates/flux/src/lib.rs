#![forbid(unsafe_code)]

mod credential;
mod negotiation;
mod registry;
mod reporter;
mod service;

pub use credential::{CredentialClaims, CredentialError, CredentialErrorKind, CredentialVerifier};
pub use negotiation::{Negotiated, negotiate};
pub use registry::{ConnectionInfo, ConnectionRegistry, now_millis};
pub use reporter::EventReporter;
pub use service::AgentService;

#[cfg(test)]
mod tests;
