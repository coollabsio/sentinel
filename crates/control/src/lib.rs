#![forbid(unsafe_code)]

mod assignment;
mod commands;
mod connection;

pub use assignment::{
    Assignment, AssignmentClient, AssignmentError, AssignmentErrorKind, AssignmentOutcome,
};
pub use connection::{FluxConnectionError, FluxTransport};

#[cfg(test)]
mod tests;
