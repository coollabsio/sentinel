#![forbid(unsafe_code)]

mod acme;
mod assignment;
mod builder;
mod commands;
mod connection;
mod container_logs;
mod discovery;
mod ingress;
mod ingress_tls;
mod logs;
mod network;
mod registry;
mod restore;
mod trust;

pub use assignment::{
    Assignment, AssignmentClient, AssignmentError, AssignmentErrorKind, AssignmentOutcome,
};
pub use connection::{FluxConnectionError, FluxTransport};
pub use logs::{LogLayer, log_layer};
pub use network::corrosion_schema;

#[cfg(test)]
mod tests;
