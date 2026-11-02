//! Advanced Windows privilege elevation engine supporting both interactive and headless contexts.

use std::{
    collections::HashSet,
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    slice,
    time::Duration,
};

use windows::{
    Win32::{
        Foundation::MAX_PATH,
        Security::WinLocalSystemSid,
        System::{
            RemoteDesktop::{
                WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
                WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
            },
            SystemInformation::GetSystemDirectoryW,
            SystemServices::SECURITY_MANDATORY_SYSTEM_RID,
            Threading::{
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    },
    core::PWSTR,
};

use crate::{
    SessionDiagnostic,
    error::{ElevateError, ProcessAccessFailure, ProcessDiagnostic},
    security::{
        ExecutionContext, ProcessSnapshot, ServiceManager, Token,
        guard::{HandleGuard, WtsMemoryGuard},
        privilege::Privilege,
        token::TokenType,
        win32,
    },
};

const DEFAULT_SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

/// The canonical Session 0 SYSTEM process used as the elevation pivot.
///
/// `services.exe` is explicitly selected because it is not subjected to PPL (Protected Process Light)
/// protections in modern Windows (unlike `lsass.exe` with RunAs-PPL or `wininit.exe` with WinTCB-Light),
/// ensuring unrestricted token access under `SeDebugPrivilege`.
const DEFAULT_SYSTEM_PROCESS: &str = "services.exe";

/// Target session binding policy for elevated tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionTarget {
    /// Bind token to the caller's active interactive session.
    #[default]
    CallerSession,
    /// Explicitly bind token to a specified Session ID.
    Explicit(u32),
    /// Automatically find the best active interactive desktop session.
    AnyInteractive,
}

/// Chained elevation engine utilizing SYSTEM tokens to acquire `TrustedInstaller`.
pub struct Elevator {
    service_timeout: Duration,
    context: ExecutionContext,
    session_target: SessionTarget,
    preferred_system_process: String,
}

impl Default for Elevator {
    fn default() -> Self {
        Self {
            service_timeout: DEFAULT_SERVICE_TIMEOUT,
            context: ExecutionContext::default(),
            session_target: SessionTarget::default(),
            preferred_system_process: DEFAULT_SYSTEM_PROCESS.to_string(),
        }
    }
}

impl Elevator {
    /// Create a new elevation instance specifying timeout and host execution context.
    pub fn new(context: ExecutionContext) -> Self {
        Self {
            context,
            ..Default::default()
        }
    }

    /// Set a custom execution context.
    #[must_use]
    pub fn with_context(mut self, context: ExecutionContext) -> Self {
        self.context = context;
        self
    }

    /// Set a custom service startup timeout.
    #[must_use]
    pub fn with_service_timeout(mut self, timeout: Duration) -> Self {
        self.service_timeout = timeout;
        self
    }

    /// Override the preferred candidate Session 0 SYSTEM process name (default: "services.exe").
    #[must_use]
    pub fn with_preferred_system_process(mut self, name: impl Into<String>) -> Self {
        self.preferred_system_process = name.into();
        self
    }

    /// Configure a custom session target policy for interactive contexts.
    #[must_use]
    pub fn with_session_target(mut self, target: SessionTarget) -> Self {
        self.session_target = target;
        self
    }

    /// Returns a reference to the configured host execution context.
    #[must_use]
    pub const fn context(&self) -> &ExecutionContext {
        &self.context
    }

    /// Execute elevation and return a fully elevated primary security token.
    pub fn acquire_primary_token(&self) -> Result<Token, ElevateError> {
        let current_token = Token::current()?;
        if !current_token.is_elevated_admin()? {
            return Err(ElevateError::AdministratorRequired);
        }

        current_token.enable_privileges(&[Privilege::Debug, Privilege::Impersonate])?;

        let target_session = match self.context {
            ExecutionContext::Headless => None,
            ExecutionContext::Interactive(_) => {
                Some(resolve_session(&current_token, &self.session_target)?)
            }
        };

        let ti_pid = ServiceManager::open()?
            .service("TrustedInstaller")?
            .start_and_wait(self.service_timeout)?;

        // Resolve an accessible SYSTEM process entirely from Session 0,
        // avoiding PPL locks on interactive winlogon.exe or lsass.exe.
        let system_pid = self.resolve_system_process()?;
        let system_token = Token::from_pid(system_pid)?.duplicate(TokenType::Impersonation)?;

        // Execute primary token duplication strictly within the bounded impersonation scope.
        // Impersonating SYSTEM grants SeTcbPrivilege, permitting explicit TokenSessionId reassignment.
        let ti_primary_token = system_token.with_impersonation(|| {
            let token = Token::from_pid(ti_pid)?.duplicate(TokenType::Primary)?;

            if let Some(expected_session) = target_session {
                token.set_session_id(expected_session)?;

                // Readback verification: ensure the session assignment took effect in kernel space
                // and did not silently fail to prevent silent Session 0 window drop.
                let actual_session = token.session_id()?;
                if actual_session != expected_session {
                    return Err(ElevateError::SessionBindingFailed {
                        expected: expected_session,
                        actual: actual_session,
                    });
                }
            }
            Ok(token)
        })?;

        Ok(ti_primary_token)
    }

    /// Resolve an accessible Session 0 SYSTEM process PID to serve as the elevation pivot.
    ///
    /// Prioritizes the configured preferred process (e.g. `services.exe`) after verifying it resides
    /// in the canonical System32 directory and holds genuine Session 0 SYSTEM privileges. If that fails,
    /// falls back to scanning other running processes.
    fn resolve_system_process(&self) -> Result<u32, ElevateError> {
        let system32_path = get_system32_path()?;

        let processes: Vec<_> = ProcessSnapshot::new()?.collect();
        let mut diagnostics = Vec::new();
        let mut checked_pids = HashSet::new();

        for &(pid, ref name) in &processes {
            if !name.eq_ignore_ascii_case(&self.preferred_system_process) {
                continue;
            }

            checked_pids.insert(pid);

            let image_path = match get_process_image_path(pid) {
                Ok(path) => path,
                Err(e) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
                    });
                    continue;
                }
            };

            if !is_in_system32(&image_path, &system32_path) {
                diagnostics.push(ProcessDiagnostic {
                    pid,
                    name: name.clone(),
                    reason: ProcessAccessFailure::NotInSystem32,
                });
                continue;
            }

            let token = match Token::from_pid(pid) {
                Ok(token) => token,
                Err(e) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
                    });
                    continue;
                }
            };

            match verify_session0_system_token(&token) {
                Ok(()) => return Ok(pid),
                Err(reason) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason,
                    });
                }
            }
        }

        let current_pid = std::process::id();
        for &(pid, ref name) in &processes {
            if pid <= 4 || pid == current_pid || checked_pids.contains(&pid) {
                continue;
            }

            let exe_path = match get_process_image_path(pid) {
                Ok(path) => path,
                Err(e) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
                    });
                    continue;
                }
            };
            if !is_in_system32(&exe_path, &system32_path) {
                continue;
            }

            let token = match Token::from_pid(pid) {
                Ok(token) => token,
                Err(e) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
                    });
                    continue;
                }
            };

            match verify_session0_system_token(&token) {
                Ok(()) => return Ok(pid),
                Err(ProcessAccessFailure::NotSystemSid { .. }) => {}
                Err(reason) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason,
                    });
                }
            }
        }

        Err(ElevateError::NoViableSystemProcess { diagnostics })
    }
}

/// Resolve the target Windows Session ID according to the specified [`SessionTarget`] policy.
fn resolve_session(token: &Token, session_target: &SessionTarget) -> Result<u32, ElevateError> {
    match session_target {
        SessionTarget::CallerSession => {
            let session_id = token.session_id()?;
            if session_id == 0 {
                return Err(ElevateError::SessionZeroNotSupported);
            }
            Ok(session_id)
        }
        SessionTarget::Explicit(session_id) => Ok(*session_id),
        SessionTarget::AnyInteractive => find_any_interactive_session(),
    }
}

/// Enumerate all active Windows sessions and find an interactive session with a logged-on user.
fn find_any_interactive_session() -> Result<u32, ElevateError> {
    let mut session_info_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;

    win32!(WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &raw mut session_info_ptr,
        &raw mut count,
    ))?;

    let _guard = WtsMemoryGuard(session_info_ptr.cast());

    if session_info_ptr.is_null() || count == 0 {
        return Err(ElevateError::InvalidSystemBuffer);
    }

    let sessions = unsafe { slice::from_raw_parts(session_info_ptr, count as usize) };
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };

    let mut candidate: Option<u32> = None;
    let mut diagnostics = Vec::new();

    for session in sessions {
        if session.State != WTSActive {
            continue;
        }

        match has_logged_on_user(session.SessionId) {
            Ok(true) => {
                if session.SessionId == console_session_id {
                    return Ok(session.SessionId);
                }

                if candidate.is_none() {
                    candidate = Some(session.SessionId);
                }
            }
            Ok(false) => {
                diagnostics.push(SessionDiagnostic {
                    session_id: session.SessionId,
                    reason: ProcessAccessFailure::InternalError {
                        message:
                            "Active session has an empty or unassigned username (e.g. lock screen)"
                                .to_string(),
                    },
                });
            }
            Err(e) => {
                diagnostics.push(SessionDiagnostic {
                    session_id: session.SessionId,
                    reason: e.to_access_failure(),
                });
            }
        }
    }

    candidate.ok_or(ElevateError::NoInteractiveSession { diagnostics })
}

/// Query whether a specific Windows Session currently has an authenticated user logged on.
fn has_logged_on_user(session_id: u32) -> Result<bool, ElevateError> {
    let mut raw_ptr = PWSTR::null();
    let mut bytes_returned = 0u32;

    win32!(WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        session_id,
        WTSUserName,
        &raw mut raw_ptr,
        &raw mut bytes_returned,
    ))?;

    if raw_ptr.is_null() {
        return Err(ElevateError::InvalidBuffer);
    }

    let _guard = WtsMemoryGuard(raw_ptr.0.cast());

    Ok(unsafe { *raw_ptr.0 != 0 })
}

/// Retrieve the canonical path to the Windows System32 directory (e.g. `C:\Windows\System32`).
fn get_system32_path() -> Result<PathBuf, ElevateError> {
    let mut buf = [0u16; MAX_PATH as usize];

    let char_count = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if char_count == 0 {
        return Err(ElevateError::SystemDirectoryNotFound);
    }

    if char_count >= buf.len() {
        return Err(ElevateError::PathBufferTooSmall {
            needed: char_count,
            capacity: buf.len(),
        });
    }

    Ok(wide_to_path(&buf[..char_count]))
}

/// Query the full executable image file path for a running process by its PID.
fn get_process_image_path(pid: u32) -> Result<PathBuf, ElevateError> {
    let process = win32!(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))?;
    let _guard = HandleGuard(process);

    let mut buf = [0u16; 1024];
    let mut char_count = buf.len() as u32;

    win32!(QueryFullProcessImageNameW(
        process,
        PROCESS_NAME_FORMAT(0),
        PWSTR(buf.as_mut_ptr()),
        &raw mut char_count,
    ))?;
    if char_count == 0 {
        return Err(ElevateError::ProcessImagePathUnavailable { pid });
    }

    Ok(wide_to_path(&buf[..char_count as usize]))
}

/// Convert a slice of UTF-16 code units into a [`PathBuf`].
#[inline]
fn wide_to_path(wide: &[u16]) -> PathBuf {
    PathBuf::from(OsString::from_wide(wide))
}

/// Verify that the given executable path is located directly inside the System32 directory.
fn is_in_system32(exe_path: &Path, system32_path: &Path) -> bool {
    exe_path
        .parent()
        .and_then(|p| p.to_str())
        .zip(system32_path.to_str())
        .is_some_and(|(parent, system32)| parent.eq_ignore_ascii_case(system32))
}

/// Verifies whether a candidate process token qualifies as a viable Session 0 SYSTEM elevation pivot.
fn verify_session0_system_token(token: &Token) -> Result<(), ProcessAccessFailure> {
    let is_system_sid = token
        .is_well_known_user(WinLocalSystemSid)
        .map_err(|e| e.to_access_failure())?;
    if !is_system_sid {
        let sid = token.user_sid().map_err(|e| e.to_access_failure())?;
        return Err(ProcessAccessFailure::NotSystemSid { sid });
    }

    let actual = token.session_id().map_err(|e| e.to_access_failure())?;
    if actual != 0 {
        return Err(ProcessAccessFailure::SessionMismatch {
            expected: 0,
            actual,
        });
    }

    if token.is_restricted().map_err(|e| e.to_access_failure())? {
        return Err(ProcessAccessFailure::RestrictedToken);
    }

    let level = token.integrity_level().map_err(|e| e.to_access_failure())?;
    let expected = SECURITY_MANDATORY_SYSTEM_RID as u32;
    if level < expected {
        return Err(ProcessAccessFailure::LowIntegrityLevel { level, expected });
    }

    let has_impersonate = token
        .has_privilege_present(Privilege::Impersonate)
        .map_err(|e| e.to_access_failure())?;
    if !has_impersonate {
        return Err(ProcessAccessFailure::MissingPrivilege {
            privilege: Privilege::Impersonate.as_str(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InteractiveDesktop;
    use windows::core::{PCWSTR, w};

    const TRUSTED_INSTALLER_SID: PCWSTR =
        w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    // Helper: Ensure the current test runner has Administrator rights and SeDebugPrivilege.
    fn assert_elevated_context() {
        let current_token =
            Token::current().expect("Failed to open current process security token");

        assert!(
            current_token.is_elevated_admin().unwrap_or(false),
            "Test execution requires an elevated Administrator context. \
             Please run from an Administrator prompt."
        );

        current_token.enable_privileges(&[Privilege::Debug]).expect(
            "Administrator context lacks SeDebugPrivilege! \
             Your system policy (secpol.msc) or EDR may have stripped this privilege.",
        );
    }

    // Ensure the default configuration targets the active interactive user desktop.
    #[test]
    fn elevator_default_context_is_interactive_default() {
        assert_eq!(
            *Elevator::default().context(),
            ExecutionContext::Interactive(InteractiveDesktop::Default)
        );
    }

    // Ensure we can query the Windows System32 directory path (e.g. C:\Windows\System32) without failure.
    #[test]
    fn get_system32_path_locates_valid_system_directory() {
        let path = get_system32_path().expect("System32 directory path must be resolvable");
        let path_str = path.to_string_lossy().to_lowercase();
        assert!(
            path_str.contains("system32"),
            "System directory must contain 'system32', got: {path_str}"
        );
    }

    // Edge case: Querying invalid or non-existent PIDs (like PID 0 or PID max) should return a clean Win32 error, not crash.
    #[test]
    fn get_process_image_path_with_invalid_pids_returns_win32_error() {
        match get_process_image_path(0) {
            Err(ElevateError::Win32 { operation, .. }) => {
                assert_eq!(operation, "OpenProcess");
            }
            other => panic!("Expected Win32 OpenProcess error for PID 0, got: {other:?}"),
        }

        match get_process_image_path(u32::MAX - 1) {
            Err(ElevateError::Win32 { operation, .. }) => {
                assert_eq!(operation, "OpenProcess");
            }
            other => panic!("Expected Win32 OpenProcess error for bogus PID, got: {other:?}"),
        }
    }

    // Ensure `get_process_image_path` can successfully retrieve the full executable path of a running process.
    #[test]
    fn get_process_image_path_returns_valid_path_for_current_process() {
        let system32_path = get_system32_path().unwrap();
        let current_pid = std::process::id();

        let path = get_process_image_path(current_pid)
            .expect("Should be able to query current process image path");

        // A normal test binary lives in target\debug\..., so it should never be inside System32.
        assert!(
            !is_in_system32(&path, &system32_path),
            "The test binary ({path:?}) should not be located in System32"
        );
    }

    // Verify that `is_in_system32` only returns true for files directly inside the System32 folder.
    #[test]
    fn is_in_system32_matches_only_direct_children() {
        let system32_path = Path::new(r"C:\Windows\System32");

        // Files directly inside System32 should match (case-insensitive).
        assert!(is_in_system32(
            Path::new(r"C:\Windows\System32\services.exe"),
            system32_path
        ));
        assert!(is_in_system32(
            Path::new(r"c:\windows\system32\svchost.exe"),
            system32_path
        ));

        // Subdirectories, parent directories, or other drives should not match.
        assert!(!is_in_system32(
            Path::new(r"C:\Windows\System32\drivers\etc"),
            system32_path
        ));
        assert!(!is_in_system32(
            Path::new(r"C:\Windows\explorer.exe"),
            system32_path
        ));
        assert!(!is_in_system32(
            Path::new(r"D:\Tools\fake_services.exe"),
            system32_path
        ));
    }

    // Ensure `verify_session0_system_token` accepts only genuine Local System (WinLocalSystemSid) tokens
    // residing strictly in Session 0, rejecting both non-system accounts and interactive system tokens.
    #[test]
    fn verify_session0_system_token_rejects_non_system_or_non_session0_tokens() {
        let current_token = Token::current().unwrap();
        let is_system_sid = current_token.is_well_known_user(WinLocalSystemSid).unwrap();
        let current_session = current_token.session_id().unwrap();

        let result = verify_session0_system_token(&current_token);

        if is_system_sid && current_session == 0 {
            assert!(
                result.is_ok(),
                "Session 0 Local System token must be accepted"
            );
        } else if !is_system_sid {
            assert!(
                matches!(result, Err(ProcessAccessFailure::NotSystemSid { .. })),
                "Non-system token must be rejected with NotSystemSid"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(ProcessAccessFailure::SessionMismatch { expected: 0, .. })
                ),
                "System token outside Session 0 must be rejected with SessionMismatch"
            );
        }
    }

    // Verify `resolve_session` correctly returns the current active desktop session ID,
    // and strictly preserves explicitly provided session IDs.
    #[test]
    fn resolve_session_returns_active_or_explicit_session() {
        let current_token = Token::current().unwrap();
        let current_session = current_token.session_id().unwrap();

        // 1. Explicit target: must strictly return whatever session ID was passed in.
        assert_eq!(
            resolve_session(&current_token, &SessionTarget::Explicit(42)).unwrap(),
            42
        );

        // 2. CallerSession target: since this test runs in an interactive user session (Session >= 1),
        // it must return the active session ID without errors.
        assert_eq!(
            resolve_session(&current_token, &SessionTarget::CallerSession).unwrap(),
            current_session
        );
    }

    // End-to-end test: Acquire a genuine TrustedInstaller token strictly bound to Session 0 (Headless).
    #[test]
    #[ignore = "requires elevated Administrator privileges"]
    fn acquire_primary_token_headless_binds_to_session_zero() {
        assert_elevated_context();

        let elevator = Elevator::new(ExecutionContext::Headless);
        let token = elevator
            .acquire_primary_token()
            .expect("Failed to acquire TrustedInstaller token in headless mode");

        assert!(
            token
                .has_sid(TRUSTED_INSTALLER_SID)
                .expect("Failed to query SID"),
            "Acquired token must possess genuine TrustedInstaller SID"
        );

        let session_id = token.session_id().expect("Failed to read session ID");
        assert_eq!(
            session_id, 0,
            "Headless token must be strictly bound to Session 0"
        );
    }

    // End-to-end test: Acquire a genuine TrustedInstaller token bound to the active user's desktop session.
    #[test]
    #[ignore = "requires elevated Administrator privileges and an active desktop session"]
    fn acquire_primary_token_interactive_binds_to_caller_session() {
        assert_elevated_context();

        let elevator = Elevator::default(); // Defaults to Interactive desktop
        let token = elevator
            .acquire_primary_token()
            .expect("Failed to acquire TrustedInstaller token for interactive session");

        assert!(
            token
                .has_sid(TRUSTED_INSTALLER_SID)
                .expect("Failed to query SID"),
            "Acquired token must possess genuine TrustedInstaller SID"
        );

        let caller_session = Token::current().unwrap().session_id().unwrap();
        let session_id = token.session_id().expect("Failed to read session ID");
        assert_eq!(
            session_id, caller_session,
            "Interactive token must match the caller's active desktop session ID"
        );
    }
}
