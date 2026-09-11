#![forbid(unsafe_code)]

mod assignment;

pub use assignment::{
    Assignment, AssignmentClient, AssignmentError, AssignmentErrorKind, AssignmentOutcome,
};

#[cfg(test)]
mod tests;
