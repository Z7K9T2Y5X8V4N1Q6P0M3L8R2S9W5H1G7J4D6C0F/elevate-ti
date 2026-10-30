//! Pluggable privilege elevation strategies.

pub mod token_duplication;
pub use token_duplication::{SessionTarget, TrustedInstallerStrategy};

use crate::{error::ElevateError, security::token::Token};

/// Contract for privilege elevation mechanisms.
pub trait ElevationStrategy {
    /// Execute the strategy and return a fully elevated primary security token.
    fn acquire_primary_token(&self) -> Result<Token, ElevateError>;
}
