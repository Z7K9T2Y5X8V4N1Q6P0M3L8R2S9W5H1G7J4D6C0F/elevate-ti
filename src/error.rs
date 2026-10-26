//! Domain error types for `TrustedInstaller` elevation operations.

use std::io;
use thiserror::Error;
use windows::Win32::Foundation::E_ACCESSDENIED;

/// Cause of process or token acquisition failure.
///
/// Designed as a pure scalar structure without external crate dependencies,
/// supporting direct programmatic pattern matching and serialization.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProcessAccessFailure {
    /// The binary backing the target process is located outside the canonical System32 directory.
    #[error("Binary path is outside canonical System32")]
    NotInSystem32,

    /// The token was accessible, but lacks SYSTEM SID, requisite privileges, or integrity level.
    #[error("Token accessible, but lacks SYSTEM rights or privileges")]
    InsufficientPrivileges,

    /// Explicit kernel-level access denial (0x80070005), typically caused by PPL, VBS, or EDR/AV drivers.
    #[error("Access denied [0x{hresult:08X}: {message}] (PPL/VBS/EDR intervention)")]
    AccessDenied {
        /// Underlying Win32 HRESULT code.
        hresult: u32,
        /// Formatted error message text.
        message: String,
    },

    /// Other Win32 API failure with an explicit HRESULT code.
    #[error("Win32 Error [0x{hresult:08X}: {message}]")]
    Win32Error {
        /// Underlying Win32 HRESULT code.
        hresult: u32,
        /// Formatted error message text.
        message: String,
    },

    /// Non-Win32 or internal logic error without an HRESULT code.
    #[error("Error: {message}")]
    InternalError {
        /// Formatted error message text.
        message: String,
    },
}

/// Diagnostic item for an individual candidate process inspected during SYSTEM token resolution.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("PID {pid} ({name}): {reason}")]
pub struct ProcessDiagnostic {
    /// Process ID (PID) of the candidate process.
    pub pid: u32,
    /// Executable name of the candidate process (e.g. `services.exe`).
    pub name: String,
    /// Concrete reason why the process could not be utilized.
    pub reason: ProcessAccessFailure,
}

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
    #[error(
        "Service '{name}' failed unexpectedly (win32 exit code: {exit_code}{})",
        if *exit_code == 1066 {
            format!(", service-specific exit code: {service_exit_code}")
        } else {
            String::new()
        }
    )]
    ServiceFailed {
        /// Name of the target service.
        name: String,
        /// Win32 exit code reported by the service (`dwWin32ExitCode`).
        exit_code: u32,
        /// Service-specific exit code reported by the service (`dwServiceSpecificExitCode`).
        service_exit_code: u32,
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

    /// No interactive session with a logged-on user was found.
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

    /// Binding token to the target Windows Session ID failed post-verification readback.
    #[error(
        "Session ID mismatch: requested binding to session {expected}, but verified as {actual}"
    )]
    SessionBindingFailed {
        /// Requested session ID.
        expected: u32,
        /// Actual session ID read back from the token.
        actual: u32,
    },

    /// All candidate SYSTEM processes in Session 0 could not be accessed.
    #[error(
            "Failed to acquire a viable SYSTEM token. Inspected {} candidate(s):{}",
            diagnostics.len(),
            format_diagnostics(diagnostics)
        )]
    NoViableSystemProcess {
        /// Full diagnostic log detailing why each inspected candidate was rejected.
        diagnostics: Vec<ProcessDiagnostic>,
    },
}

fn format_diagnostics(diagnostics: &[ProcessDiagnostic]) -> String {
    if diagnostics.is_empty() {
        return String::new();
    }
    format!(
        "\n  * {}",
        diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n  * ")
    )
}

impl ElevateError {
    /// Normalizes any error variant into a structured [`ProcessAccessFailure`].
    pub(crate) fn to_access_failure(&self) -> ProcessAccessFailure {
        match self {
            Self::Win32 { source, .. } => {
                let hresult = source.code().0 as u32;
                let message = format!("{source}");

                if source.code() == E_ACCESSDENIED {
                    ProcessAccessFailure::AccessDenied { hresult, message }
                } else {
                    ProcessAccessFailure::Win32Error { hresult, message }
                }
            }
            other => ProcessAccessFailure::InternalError {
                message: other.to_string(),
            },
        }
    }
}
