//! VisiPass core: the pure parts shared by the daemon and the CLI.
//!
//! Nothing here performs I/O. Item metadata types deliberately have no `value`
//! field, so decoding a backend's output drops secret values before anything
//! else sees them.

pub mod audit;
pub mod backend;
pub mod env;
pub mod find;
pub mod generate;
pub mod ipc;
pub mod kamal;
pub mod mask;
pub mod model;
pub mod paths;
pub mod refs;
pub mod secret;
pub mod template;
pub mod time;
pub mod totp;

/// An expected error. Printed as `visipass: <message>` with exit code 1.
/// Messages must never contain a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Failure {}

pub type Result<T, E = Failure> = std::result::Result<T, E>;
