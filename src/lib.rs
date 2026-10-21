//! A safe, idiomatic Rust library to obtain Windows `TrustedInstaller` privileges.
//!
//! # Overview
//!
//! `elevate-ti` provides zero-cost, high-level abstractions to verify and acquire
//! `NT SERVICE\TrustedInstaller` privileges on Windows, allowing processes to relaunch
//! themselves or spawn sub-processes into active interactive desktops or headless
//! background sessions.

pub mod error;
pub mod security;
pub mod session;
pub mod strategy;

pub use error::ElevateError;
pub use security::{ImpersonationGuard, Privilege, Sid, Token, TokenCommand, TokenType};
pub use session::{ElevationStatus, elevated_command, relaunch, status};
pub use strategy::{ElevationStrategy, SessionTarget, TrustedInstallerStrategy};
