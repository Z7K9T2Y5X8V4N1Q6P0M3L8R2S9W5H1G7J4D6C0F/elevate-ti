//! High-level elevation status checking and process relaunch orchestration.

use windows::core::{PCWSTR, w};

use crate::{
    error::ElevateError,
    security::{ExecutionContext, InteractiveDesktop, Token, TokenCommand},
    strategy::{ElevationStrategy, TrustedInstallerStrategy},
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

/// Create a [`TokenCommand`] targeting the caller's standard interactive desktop (`WinSta0\Default`).
pub fn elevated_command() -> Result<TokenCommand, ElevateError> {
    elevated_command_on(InteractiveDesktop::Default)
}

/// Create a [`TokenCommand`] targeting a specific interactive desktop.
///
/// Supports standard desktops (`Default`, `Winlogon`, `Screensaver`) as well
/// as custom window stations created for sandboxes or virtual displays.
///
/// # Examples
///
/// Launching onto the secure Winlogon desktop (visible at lock screen / UAC prompts):
/// ```no_run
/// use elevate_ti::{elevated_command_on, InteractiveDesktop};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// elevated_command_on(InteractiveDesktop::Winlogon)?
///     .exe("%SystemRoot%\\System32\\cmd.exe")
///     .spawn()?;
/// # Ok(())
/// # }
/// ```
///
/// Launching onto a custom sandbox window station and desktop:
/// ```no_run
/// use elevate_ti::{elevated_command_on, InteractiveDesktop};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// elevated_command_on(InteractiveDesktop::custom("MySandboxStation\\IsolatedDesktop"))?
///     .exe("%SystemRoot%\\System32\\cmd.exe")
///     .spawn()?;
/// # Ok(())
/// # }
/// ```
pub fn elevated_command_on(desktop: InteractiveDesktop) -> Result<TokenCommand, ElevateError> {
    let strategy = TrustedInstallerStrategy::new(
        std::time::Duration::from_secs(30),
        ExecutionContext::Interactive(desktop.clone()),
    );
    let token = strategy.acquire_primary_token()?;
    Ok(TokenCommand::new(token, Some(desktop)))
}

/// Create a [`TokenCommand`] configured strictly for headless Session 0 execution.
///
/// Has no desktop binding, making it mathematically impossible to trigger desktop DACL collisions.
pub fn headless_command() -> Result<TokenCommand, ElevateError> {
    let strategy = TrustedInstallerStrategy::new(
        std::time::Duration::from_secs(30),
        ExecutionContext::Headless,
    );
    let token = strategy.acquire_primary_token()?;
    Ok(TokenCommand::new(token, None))
}

/// Restart the current executable under `TrustedInstaller` identity in the active user desktop.
pub fn relaunch() -> Result<(), ElevateError> {
    elevated_command()?.current_exe()?.spawn()
}
