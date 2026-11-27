#![forbid(unsafe_code)]

mod acme;
mod assignment;
mod builder;
mod cdi;
mod commands;
mod connection;
mod container_logs;
mod container_socket;
mod convergence;
mod database_dump;
mod discovery;
mod exec;
mod files;
mod image_prune;
mod image_transfer;
mod ingress;
mod ingress_options;
mod ingress_tls;
mod isolation;
mod logs;
mod network;
mod registry;
mod restore;
mod runtime_options;
mod secrets;
mod terminal;
mod trust;
mod volume_backup;
mod volume_transfer;
mod volumes;
mod workload_set;
mod workload_user;

pub use assignment::{
    Assignment, AssignmentClient, AssignmentError, AssignmentErrorKind, AssignmentOutcome,
};
pub use connection::{FluxConnectionError, FluxTransport};
pub use logs::{LogLayer, log_layer};
pub use network::corrosion_schema;

#[cfg(test)]
mod tests;
