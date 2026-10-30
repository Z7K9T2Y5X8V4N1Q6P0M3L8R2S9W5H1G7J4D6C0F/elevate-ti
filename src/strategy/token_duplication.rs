//! Advanced Windows privilege elevation strategy supporting both interactive and headless contexts.

use std::{
    collections::HashSet,
    ffi::c_void,
    path::{Path, PathBuf},
    slice,
    time::Duration,
};

use windows::{
    Win32::{
        Foundation::MAX_PATH,
        System::{
            RemoteDesktop::{
                WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
                WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
                WTSUserName,
            },
            SystemInformation::GetSystemDirectoryW,
            SystemServices::SECURITY_MANDATORY_SYSTEM_RID,
            Threading::{
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    },
    core::{PWSTR, w},
};

use crate::{
    SessionDiagnostic,
    error::{ElevateError, ProcessAccessFailure, ProcessDiagnostic},
    security::{
        ExecutionContext, HandleGuard, ProcessSnapshot, ServiceManager,
        privilege::Privilege,
        token::{Token, TokenType},
        win32,
    },
    strategy::ElevationStrategy,
};

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// The canonical Session 0 SYSTEM process used as the elevation pivot.
///
/// `services.exe` is explicitly selected because it is not subjected to PPL (Protected Process Light)
/// protections in modern Windows (unlike `lsass.exe` with RunAs-PPL or `wininit.exe` with WinTCB-Light),
/// ensuring unrestricted token access under `SeDebugPrivilege`.
const DEFAULT_SYSTEM_PROCESS: &str = "services.exe";

struct WtsMemoryGuard(*mut c_void);

impl Drop for WtsMemoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                WTSFreeMemory(self.0);
            }
        }
    }
}

/// Target session binding strategy.
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

/// Chained elevation strategy utilizing SYSTEM tokens to acquire `TrustedInstaller`.
pub struct TrustedInstallerStrategy {
    service_timeout: Duration,
    context: ExecutionContext,
    session_target: SessionTarget,
    preferred_system_process: String,
}

impl Default for TrustedInstallerStrategy {
    fn default() -> Self {
        Self {
            service_timeout: Duration::from_secs(30),
            context: ExecutionContext::default(),
            session_target: SessionTarget::default(),
            preferred_system_process: DEFAULT_SYSTEM_PROCESS.to_string(),
        }
    }
}

impl TrustedInstallerStrategy {
    /// Create a new strategy specifying timeout and host execution context.
    pub fn new(service_timeout: Duration, context: ExecutionContext) -> Self {
        Self {
            service_timeout,
            context,
            session_target: SessionTarget::CallerSession,
            preferred_system_process: DEFAULT_SYSTEM_PROCESS.to_string(),
        }
    }

    /// Override or append custom candidate Session 0 SYSTEM process names.
    #[must_use]
    pub fn with_preferred_processes(mut self, process: impl Into<String>) -> Self {
        self.preferred_system_process = process.into();
        self
    }

    /// Configure a custom session target policy for interactive contexts.
    #[must_use]
    pub fn with_session_target(mut self, session_target: SessionTarget) -> Self {
        self.session_target = session_target;
        self
    }

    /// Returns a reference to the configured host execution context.
    #[must_use]
    pub const fn context(&self) -> &ExecutionContext {
        &self.context
    }

    /// Resolves an accessible, unrestricted SYSTEM process in Session 0 via a two-stage scan.
    fn resolve_system_process(&self) -> Result<u32, ElevateError> {
        let system32_path = get_system32_path()?;

        // Snapshot is collected into an owned vector to allow multiple iterations
        // without consuming or attempting to clone non-cloneable Win32 handles.
        let processes: Vec<(u32, String)> = ProcessSnapshot::new()?.collect();
        let mut diagnostics = Vec::new();
        let mut checked_pids = HashSet::new();

        // Stage 1: Inspect the single preferred system process (default: services.exe)
        for &(pid, ref name) in &processes {
            if !name.eq_ignore_ascii_case(&self.preferred_system_process) {
                continue;
            }

            checked_pids.insert(pid);

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

            match verify_system_token(&token, Some(0)) {
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

        // Stage 2: Fallback scan across all accessible Session 0 processes
        let current_pid = std::process::id();
        for &(pid, ref name) in &processes {
            if pid <= 4 || pid == current_pid || checked_pids.contains(&pid) {
                continue;
            }

            // Both stages enforce system32 physical path validation for defense-in-depth
            let exe_path = match get_process_image_path(pid) {
                Ok(path) => path,
                Err(e) => {
                    // Security blocks (e.g. AccessDenied from PPL/EDR) are recorded for troubleshooting.
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
                    // Security blocks (e.g. AccessDenied from PPL/EDR) are recorded for troubleshooting.
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
                    });
                    continue;
                }
            };

            match verify_system_token(&token, Some(0)) {
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

impl ElevationStrategy for TrustedInstallerStrategy {
    fn acquire_primary_token(&self) -> Result<Token, ElevateError> {
        let current_token = Token::current()?;
        // Fast-fail before attempting SCM or system process operations
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
            .service(w!("TrustedInstaller"))?
            .start_and_wait("TrustedInstaller", self.service_timeout)?;

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
}

fn resolve_session(caller_token: &Token, target: &SessionTarget) -> Result<u32, ElevateError> {
    match target {
        SessionTarget::CallerSession => {
            let id = caller_token.session_id()?;
            if id == 0 {
                return Err(ElevateError::SessionZeroNotSupported);
            }
            Ok(id)
        }
        SessionTarget::Explicit(id) => Ok(*id),
        SessionTarget::AnyInteractive => find_any_interactive_session(),
    }
}

/// Resolves an active, user-authenticated Windows session for interactive UI delegation.
///
/// Implements a prioritized two-tier session election algorithm:
/// 1. **Primary Target**: The physical console session (`WTSGetActiveConsoleSessionId`)
///    directly connected to local video/input peripherals.
/// 2. **Fallback Target**: The first active authenticated remote desktop (RDP) session.
fn find_any_interactive_session() -> Result<u32, ElevateError> {
    let mut p_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;

    // Enumerate all active and inactive terminal sessions in the local subsystem.
    win32!(WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &raw mut p_info,
        &raw mut count,
    ))?;

    let _session_list_guard = WtsMemoryGuard(p_info.cast());

    // Defensive boundary check: In modern Windows, Session 0 is universally guaranteed to exist.
    // If the API returns a null pointer or 0 count despite succeeding, the Terminal Services buffer
    // is corrupted or intercepted by faulty third-party API hooks/EDR drivers.
    if p_info.is_null() || count == 0 {
        return Err(ElevateError::InvalidTokenBuffer);
    }

    let sessions = unsafe { slice::from_raw_parts(p_info, count as usize) };
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };

    let mut candidate: Option<u32> = None;
    let mut diagnostics = Vec::new();

    for s in sessions {
        // Filter out disconnected (WTSDisconnected), paused, or terminating sessions.
        // `WTSActive` guarantees the session's display and input channels are actively engaged.
        if s.State != WTSActive {
            continue;
        }

        // Validate that an authenticated, human user is actually logged into this session.
        // A session in `WTSActive` state may still just be resting at the Windows Logon/Lock screen (LogonUI).
        match has_logged_on_user(s.SessionId) {
            Ok(true) => {
                // Priority 1: Physical Console match.
                // The user is sitting directly in front of the machine's primary display and peripherals.
                // Short-circuit immediately to avoid spawning onto an incidental background RDP session.
                if s.SessionId == console_session_id {
                    return Ok(s.SessionId);
                }

                // Priority 2: Remote / RDP session fallback.
                // First-fit arbitration: preserve the first discovered authenticated remote user session,
                // while continuing the scan in case the physical console session appears later.
                if candidate.is_none() {
                    candidate = Some(s.SessionId);
                }
            }
            Ok(false) => {
                // The session is physically or remotely connected (Active), but has no bound user identity
                // (e.g. at the login credential prompt, or a headless display dummy/emulator).
                diagnostics.push(SessionDiagnostic {
                    session_id: s.SessionId,
                    reason: ProcessAccessFailure::InternalError {
                        message:
                            "Active session has an empty or unassigned username (e.g. lock screen)"
                                .to_string(),
                    },
                });
            }
            Err(e) => {
                // Record API-level access denial or system errors (e.g. 0x80070005 ACCESS_DENIED)
                // for structured diagnostics instead of silently ignoring the underlying root cause.
                diagnostics.push(SessionDiagnostic {
                    session_id: s.SessionId,
                    reason: e.to_access_failure(),
                });
            }
        }
    }

    // Unpack candidate: returns `Ok(session_id)` if an RDP fallback candidate was located.
    // If all candidates were rejected or inaccessible, converts `None` into a detailed error
    // containing the post-mortem diagnostics log of every rejected session.
    candidate.ok_or(ElevateError::NoInteractiveSession { diagnostics })
}

/// Query whether a specific Windows Session currently has an authenticated user logged on.
///
/// Returns `Ok(true)` only if a non-empty username string is bound to the target session.
fn has_logged_on_user(session_id: u32) -> Result<bool, ElevateError> {
    let mut raw_ptr = PWSTR::null();
    let mut bytes = 0u32;

    win32!(WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        session_id,
        WTSUserName,
        &raw mut raw_ptr,
        &raw mut bytes,
    ))?;

    if raw_ptr.is_null() {
        return Err(ElevateError::InvalidTokenBuffer);
    }

    let _username_buf_guard = WtsMemoryGuard(raw_ptr.0.cast());

    // SAFETY: Terminal Services guarantees a valid null-terminated UTF-16 wide string buffer on success.
    // In C-style wide strings, an empty username (`""`) begins immediately with the null terminator `\0` (0x0000).
    // Inspecting the 0th `u16` character is an O(1) non-allocating check:
    // - `*raw_ptr.0 == 0`: Empty string (unauthenticated session / login screen).
    // - `*raw_ptr.0 != 0`: Non-empty string (authenticated user actively logged on).
    Ok(unsafe { *raw_ptr.0 != 0 })
}

/// Retrieve the canonical System32 directory (e.g. `C:\Windows\System32`).
fn get_system32_path() -> Result<PathBuf, ElevateError> {
    let mut buf = [0u16; MAX_PATH as usize];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return Err(ElevateError::SystemDirectoryNotFound);
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

/// Query the full executable image path backing an active process.
fn get_process_image_path(pid: u32) -> Result<PathBuf, ElevateError> {
    let process = win32!(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid))?;
    let _guard = HandleGuard(process);

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;

    win32!(QueryFullProcessImageNameW(
        process,
        PROCESS_NAME_FORMAT(0),
        PWSTR(buf.as_mut_ptr()),
        &raw mut size,
    ))?;

    if size == 0 {
        return Err(ElevateError::InvalidTokenBuffer);
    }

    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..size as usize],
    )))
}

/// Pure path verification: checks whether a binary is physically located in the System32 folder.
fn is_in_system32(exe_path: &Path, system32: &Path) -> bool {
    exe_path
        .parent()
        .and_then(|p| p.to_str())
        .zip(system32.to_str())
        .is_some_and(|(parent, sys)| parent.eq_ignore_ascii_case(sys))
}

/// Verifies whether an opened Token has full, unrestricted SYSTEM capabilities.
fn verify_system_token(
    token: &Token,
    target_session: Option<u32>,
) -> Result<(), ProcessAccessFailure> {
    let sid = token.user_sid().map_err(|e| e.to_access_failure())?;
    if sid != LOCAL_SYSTEM_SID {
        return Err(ProcessAccessFailure::NotSystemSid { sid });
    }

    if let Some(expected) = target_session {
        let actual = token.session_id().map_err(|e| e.to_access_failure())?;
        if actual != expected {
            return Err(ProcessAccessFailure::SessionMismatch { expected, actual });
        }
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

    #[test]
    fn strategy_default_context_is_interactive_default() {
        assert_eq!(
            *TrustedInstallerStrategy::default().context(),
            ExecutionContext::Interactive(InteractiveDesktop::Default)
        );
    }

    #[test]
    fn get_system32_directory_succeeds() {
        let path = get_system32_path().expect("System32 directory must be resolvable");
        let path = path.to_string_lossy().to_lowercase();
        assert!(
            path.contains("system32"),
            "Path must contain 'system32', got: {path}"
        );
    }

    #[test]
    fn get_process_image_path_invalid_pids_fail_with_win32_error() {
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

    #[test]
    fn current_process_image_path_resolves_and_not_in_system32() {
        let system32 = get_system32_path().unwrap();
        let current_pid = std::process::id();

        let path = get_process_image_path(current_pid)
            .expect("Should be able to query current process image path");

        assert!(
            !is_in_system32(&path, &system32),
            "The test binary ({path:?}) should not appear to be in System32"
        );
    }

    #[test]
    fn is_in_system32_path_matching() {
        let system32 = Path::new(r"C:\Windows\System32");

        assert!(is_in_system32(
            Path::new(r"C:\Windows\System32\services.exe"),
            system32
        ));
        assert!(is_in_system32(
            Path::new(r"c:\windows\system32\svchost.exe"),
            system32
        ));
        assert!(!is_in_system32(
            Path::new(r"C:\Windows\System32\drivers\etc"),
            system32
        ));
        assert!(!is_in_system32(
            Path::new(r"C:\Windows\explorer.exe"),
            system32
        ));
        assert!(!is_in_system32(
            Path::new(r"D:\Tools\fake_services.exe"),
            system32
        ));
    }

    #[test]
    fn verify_system_token_rejects_non_system_token() {
        let token = Token::current().unwrap();
        let result = verify_system_token(&token, None);
        match result {
            Err(ProcessAccessFailure::NotSystemSid { sid }) => {
                assert!(sid.starts_with("S-1-"), "Rejected SID must be valid: {sid}");
                assert_ne!(sid, LOCAL_SYSTEM_SID);
            }
            Ok(()) => {}
            Err(other) => {
                panic!("Expected NotSystemSid or Ok, got: {other:?}");
            }
        }
    }

    #[test]
    fn verify_system_token_with_session_mismatch() {
        let token = Token::current().unwrap();
        let result = verify_system_token(&token, Some(99));
        match result {
            Err(ProcessAccessFailure::SessionMismatch { expected, actual }) => {
                assert_eq!(expected, 99);
                assert_ne!(actual, 99);
            }
            Err(ProcessAccessFailure::NotSystemSid { .. }) => {}
            other => panic!("Expected SessionMismatch or NotSystemSid, got: {other:?}"),
        }
    }

    #[test]
    fn test_caller_session_matches_current_env() {
        let token = Token::current().unwrap();
        let session = token.session_id().unwrap();

        let result = resolve_session(&token, &SessionTarget::CallerSession);
        match result {
            Ok(s) => assert_eq!(s, session),
            Err(ElevateError::SessionZeroNotSupported) => assert_eq!(session, 0),
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    // =======================================================================
    // Elevated tests — require Administrator + SeDebugPrivilege + SCM access
    // =======================================================================

    const TRUSTED_INSTALLER_SID: windows::core::PCWSTR =
        w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    fn assert_elevated_context() {
        let token = Token::current().expect("Failed to open current process security token");

        assert!(
            token.is_elevated_admin().unwrap_or(false),
            "Test execution requires an elevated Administrator context. \
             Please run from an Administrator prompt."
        );

        token.enable_privileges(&[Privilege::Debug]).expect(
            "Administrator context lacks SeDebugPrivilege! \
             Your system policy (secpol.msc) or EDR may have stripped this privilege.",
        );
    }

    #[test]
    #[ignore = "requires elevated Administrator privileges"]
    fn test_acquire_primary_token_session_zero() {
        assert_elevated_context();

        let strategy =
            TrustedInstallerStrategy::new(Duration::from_secs(30), ExecutionContext::Headless);
        let token = strategy
            .acquire_primary_token()
            .expect("Must acquire TrustedInstaller token in Session 0");

        assert!(
            token
                .has_sid(TRUSTED_INSTALLER_SID)
                .expect("Must query SID membership"),
            "Acquired token must possess genuine TrustedInstaller SID"
        );

        let session_id = token.session_id().expect("Must read session ID");
        assert_eq!(
            session_id, 0,
            "Headless execution context must strictly bind to Session 0"
        );
    }

    #[test]
    #[ignore = "requires elevated Administrator privileges and an active desktop session"]
    fn test_acquire_primary_token_caller_session() {
        assert_elevated_context();

        let strategy = TrustedInstallerStrategy::default();
        match strategy.acquire_primary_token() {
            Ok(token) => {
                assert!(
                    token
                        .has_sid(TRUSTED_INSTALLER_SID)
                        .expect("Must query SID membership"),
                    "Acquired token must possess genuine TrustedInstaller SID"
                );

                let caller_session = Token::current().unwrap().session_id().unwrap();
                assert_eq!(
                    token.session_id().unwrap(),
                    caller_session,
                    "Token must match the caller's active interactive session ID"
                );
            }
            Err(ElevateError::SessionZeroNotSupported) => {
                eprintln!(
                    "[INFO] Running inside Session 0 (CI runner/headless); fast-fail verified."
                );
            }
            Err(e) => panic!("Unexpected failure acquiring token for caller session: {e}"),
        }
    }

    #[test]
    #[ignore = "requires elevated Administrator privileges"]
    fn test_acquired_token_session_id_readback() {
        assert_elevated_context();

        let strategy =
            TrustedInstallerStrategy::new(Duration::from_secs(30), ExecutionContext::Headless);
        let token = strategy.acquire_primary_token().unwrap();

        let session_id = token.session_id().expect("Must query session ID");
        assert_eq!(
            session_id, 0,
            "Headless token must be strictly confined to Session 0"
        );
    }
}
