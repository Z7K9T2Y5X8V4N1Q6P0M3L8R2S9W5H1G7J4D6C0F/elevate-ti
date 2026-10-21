//! Pluggable privilege elevation strategies.

pub mod winlogon_ti;

pub use winlogon_ti::{SessionTarget, TrustedInstallerStrategy};

use crate::{error::ElevateError, security::Token};

/// Contract for privilege elevation mechanisms.
pub trait ElevationStrategy {
    /// Execute the strategy and return a fully elevated primary security token.
    fn acquire_primary_token(&self) -> Result<Token, ElevateError>;
}
