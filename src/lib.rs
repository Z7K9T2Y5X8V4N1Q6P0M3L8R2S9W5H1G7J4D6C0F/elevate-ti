//! A safe, idiomatic Rust library to obtain Windows `TrustedInstaller` privileges.

pub mod error;
pub mod security;
pub mod session;
pub mod strategy;

pub use error::{ElevateError, ProcessAccessFailure, ProcessDiagnostic};
pub use security::{
    ExecutionContext, InteractiveDesktop, Privilege, Sid, Token, TokenCommand, TokenType,
};
pub use session::{
    ElevationStatus, elevated_command, elevated_command_on, headless_command, relaunch, status,
};
pub use strategy::{ElevationStrategy, SessionTarget, TrustedInstallerStrategy};
