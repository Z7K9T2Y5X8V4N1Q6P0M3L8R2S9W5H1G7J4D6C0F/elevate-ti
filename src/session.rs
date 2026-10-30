//! High-level elevation status checking.

use windows::core::{PCWSTR, w};

use crate::{
    error::ElevateError,
    security::{Command, token::Token},
};

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

/// Restart the current executable under `TrustedInstaller` identity in the active user desktop.
#[inline]
pub fn relaunch() -> Result<(), ElevateError> {
    Command::relaunch()
}
