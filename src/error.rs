//! Domain error types for `TrustedInstaller` elevation operations.

use std::io;
use thiserror::Error;

/// The central error type for all privilege elevation and Windows security operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ElevateError {
    /// A raw Win32 subsystem call failed.
    #[error("Win32 API '{operation}' failed: {source}")]
    Win32 {
        /// Name of the Win32 function that failed.
        operation: &'static str,
        /// Underlying Windows error code and message.
        #[source]
        source: windows::core::Error,
    },

    /// The calling process is not running with elevated Administrator privileges.
    #[error(
        "Administrator privileges required: process must be run as Administrator (elevated) to acquire TrustedInstaller privileges"
    )]
    AdministratorRequired,

    /// A required Windows privilege is not held by the process token.
    #[error(
        "Privilege '{privilege}' is not held by the process token (run as Administrator to obtain it)"
    )]
    PrivilegeNotHeld {
        /// Name of the missing privilege (e.g. `SeDebugPrivilege`).
        privilege: &'static str,
    },

    /// A required genuine Windows SYSTEM process was not found.
    #[error("Required system process '{0}' was not found in active session")]
    ProcessNotFound(String),

    /// A Windows service failed to start or entered a failed state.
    #[error("Service '{name}' failed unexpectedly")]
    ServiceFailed {
        /// Name of the target service.
        name: String,
    },

    /// Waiting for a service to reach running state timed out.
    #[error("Service '{name}' failed to reach running state within {seconds}s")]
    ServiceTimeout {
        /// Name of the target service.
        name: String,
        /// Elapsed time before giving up.
        seconds: u64,
    },

    /// Caller is running in Session 0 (non-interactive service context).
    #[error(
        "Session 0 is not supported with CallerSession target; use SessionTarget::AnyInteractive, Explicit, or ExecutionContext::Headless"
    )]
    SessionZeroNotSupported,

    /// No active interactive session with a logged-on user was found.
    #[error("No interactive desktop session available on this machine")]
    NoInteractiveSession,

    /// An I/O error occurred during path resolution or execution.
    #[error("I/O query failed: {0}")]
    Io(#[from] io::Error),

    /// Executable path was not provided prior to launch.
    #[error("Target executable path must be specified")]
    MissingExePath,

    /// A query to token information returned corrupted or out-of-bounds data.
    #[error("Token information buffer is invalid or empty")]
    InvalidTokenBuffer,
}
