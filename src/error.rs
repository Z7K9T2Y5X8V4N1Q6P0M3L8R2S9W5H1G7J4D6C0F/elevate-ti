//! Domain error types for `TrustedInstaller` elevation operations.

use std::io;
use thiserror::Error;

/// The central error type for all privilege elevation and Windows security operations.
#[non_exhaustive]
#[derive(Debug, Error)]
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

    /// A required Windows privilege could not be enabled.
    #[error("Privilege '{0}' could not be assigned")]
    PrivilegeNotAssigned(&'static str),

    /// A required genuine Windows SYSTEM process was not found.
    #[error("Required system process '{0}' was not found in active session")]
    ProcessNotFound(String),

    /// Waiting for a service to reach running state timed out.
    #[error("Service '{name}' failed to reach running state within {seconds}s")]
    ServiceTimeout {
        /// Name of the target service.
        name: String,
        /// Elapsed time before giving up.
        seconds: u64,
    },

    /// An I/O error occurred during path resolution or execution.
    #[error("I/O query failed: {0}")]
    Io(#[from] io::Error),

    /// Executable path was not provided prior to launch.
    #[error("Target executable path must be specified")]
    MissingExePath,

    /// A query to token information returned corrupted or out-of-bounds data.
    #[error("Token information buffer is invalid or empty")]
    InvalidTokenBuffer,

    /// A service stopped unexpectedly after a start request was dispatched.
    #[error("Service '{name}' stopped unexpectedly after start was requested")]
    ServiceFailed {
        /// Name of the target service.
        name: String,
    },
}
