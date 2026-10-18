//! High-level elevation status checking and process relaunch orchestration.

use windows::core::{PCWSTR, w};

use crate::{
    error::ElevateError,
    security::{Token, TokenCommand},
    strategy::{ElevationStrategy, TrustedInstallerStrategy},
};

/// `TrustedInstaller` Service Well-Known SID string (`NT SERVICE\TrustedInstaller`).
const TRUSTED_INSTALLER_SID: PCWSTR =
    w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

/// The elevation status of the current running process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationStatus {
    /// The process is running with genuine `TrustedInstaller` privileges.
    Elevated,
    /// The process requires elevation to obtain `TrustedInstaller` privileges.
    RequiresElevation,
}

/// Check whether the current process holds the `TrustedInstaller` SID in its group tokens.
pub fn status() -> Result<ElevationStatus, ElevateError> {
    let token = Token::current()?;
    if token.has_sid(TRUSTED_INSTALLER_SID)? {
        Ok(ElevationStatus::Elevated)
    } else {
        Ok(ElevationStatus::RequiresElevation)
    }
}

/// Create a new [`TokenCommand`] configured with an elevated `TrustedInstaller` token.
pub fn elevated_command() -> Result<TokenCommand<'static>, ElevateError> {
    let strategy = TrustedInstallerStrategy::default();
    let token = Box::leak(Box::new(strategy.acquire_primary_token()?));
    Ok(TokenCommand::new(token))
}

/// Restart the current executable under `TrustedInstaller` identity in the active user desktop session.
pub fn relaunch() -> Result<(), ElevateError> {
    elevated_command()?.current_exe()?.spawn()
}
