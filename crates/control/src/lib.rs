#![forbid(unsafe_code)]

mod assignment;
mod commands;
mod connection;
mod container_logs;
mod discovery;
mod ingress;
mod logs;
mod network;
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
