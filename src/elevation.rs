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
        Foundation::{HANDLE, MAX_PATH},
        Security::WinLocalSystemSid,
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_NT,
        },
        System::{
            RemoteDesktop::{
                WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
                WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
            },
            SystemInformation::GetSystemDirectoryW,
            SystemServices::SECURITY_MANDATORY_SYSTEM_RID,
            Threading::{
                OpenProcess, PROCESS_NAME_NATIVE, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
            },
        },
    },
    core::{HSTRING, PCWSTR, PWSTR},
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

/// Elevation execution audit report capturing real kernel-level pivot and session details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevationReport {
    /// PID of the SYSTEM process actually utilized as the elevation pivot.
    pub pivot_pid: u32,
    /// Image name of the SYSTEM process actually utilized as the elevation pivot.
    pub pivot_process_name: String,
    /// Target Windows Session ID to which the token was successfully bound.
    pub target_session: u32,
    /// Process ID of the started `TrustedInstaller` service host.
    pub ti_pid: u32,
}

/// Resolved SYSTEM elevation pivot details holding the pre-acquired token to prevent PID reuse.
#[derive(Debug)]
struct SystemPivot {
    pid: u32,
    name: String,
    token: Token,
}

/// Chained elevation engine utilizing SYSTEM tokens to acquire `TrustedInstaller`.
#[derive(Debug)]
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

    /// Returns the configured service startup timeout.
    #[must_use]
    pub const fn service_timeout(&self) -> Duration {
        self.service_timeout
    }

    /// Returns a reference to the configured session target policy.
    #[must_use]
    pub const fn session_target(&self) -> &SessionTarget {
        &self.session_target
    }

    /// Execute elevation and return a fully elevated primary security token containing provenance report.
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
        // The token is acquired directly from the verified process handle to prevent TOCTOU PID reuse.
        let pivot = self.resolve_system_process()?;
        let system_token = pivot.token.duplicate(TokenType::Impersonation)?;

        // Execute primary token duplication strictly within the bounded impersonation scope.
        // Impersonating SYSTEM grants SeTcbPrivilege, permitting explicit TokenSessionId reassignment.
        let (ti_primary_token, actual_session) = system_token.with_impersonation(|| {
            let token = Token::from_pid(ti_pid)?.duplicate(TokenType::Primary)?;

            let session = if let Some(expected_session) = target_session {
                token.set_session_id(expected_session)?;

                // Readback verification: ensure the session assignment took effect in kernel space
                // and did not silently fail to prevent silent Session 0 window drop.
                let verified_session = token.session_id()?;
                if verified_session != expected_session {
                    return Err(ElevateError::SessionBindingFailed {
                        expected: expected_session,
                        actual: verified_session,
                    });
                }
                verified_session
            } else {
                token.session_id()?
            };

            Ok((token, session))
        })?;

        let report = ElevationReport {
            pivot_pid: pivot.pid,
            pivot_process_name: pivot.name,
            target_session: actual_session,
            ti_pid,
        };

        Ok(ti_primary_token.with_report(report))
    }

    /// Resolve an accessible Session 0 SYSTEM process to serve as the elevation pivot.
    ///
    /// Pins the candidate process via an active handle during image path verification and token
    /// extraction, immunizing the elevation pipeline against TOCTOU PID recycling attacks.
    fn resolve_system_process(&self) -> Result<SystemPivot, ElevateError> {
        let system32_native_path = get_canonical_system32_native_path()?;
        let mut diagnostics = Vec::new();
        let mut checked_pids = HashSet::new();

        // Pass 1: Prioritize the preferred SYSTEM process (zero-allocation string filtering)
        let mut snapshot = ProcessSnapshot::new()?;
        while let Some(proc) = snapshot.next_entry() {
            if !proc.eq_ignore_ascii_case(&self.preferred_system_process) {
                continue;
            }

            let pid = proc.pid;
            checked_pids.insert(pid);

            match inspect_candidate_process(pid, &system32_native_path) {
                Ok(token) => {
                    return Ok(SystemPivot {
                        pid,
                        name: proc.to_string_lossy(),
                        token,
                    });
                }
                Err(reason) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: proc.to_string_lossy(),
                        reason,
                    });
                }
            }
        }

        // Pass 2: Fallback scan across all other running processes
        let current_pid = std::process::id();
        let mut fallback_snapshot = ProcessSnapshot::new()?;
        while let Some(proc) = fallback_snapshot.next_entry() {
            let pid = proc.pid;
            if pid <= 4 || pid == current_pid || checked_pids.contains(&pid) {
                continue;
            }

            match inspect_candidate_process(pid, &system32_native_path) {
                Ok(token) => {
                    return Ok(SystemPivot {
                        pid,
                        name: proc.to_string_lossy(),
                        token,
                    });
                }
                Err(
                    ProcessAccessFailure::NotSystemSid { .. } | ProcessAccessFailure::NotInSystem32,
                ) => {
                    // Suppress normal non-target process rejections to avoid noisy fallback diagnostics
                }
                Err(reason) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: proc.to_string_lossy(),
                        reason,
                    });
                }
            }
        }

        Err(ElevateError::NoViableSystemProcess { diagnostics })
    }
}

/// Inspect a candidate process atomically using a pinned handle, verifying image path and token qualifications.
fn inspect_candidate_process(
    pid: u32,
    system32_native_path: &Path,
) -> Result<Token, ProcessAccessFailure> {
    // Pin the process by opening it once with both image query and token query access rights.
    // As long as this handle remains open, the kernel preserves the underlying EPROCESS structure,
    // making PID reuse physically impossible during the entire inspection and token extraction.
    let process = HandleGuard(
        win32!(OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
            false,
            pid
        ))
        .map_err(|e| e.to_access_failure())?,
    );

    let image_native_path =
        get_process_image_native_path_from_handle(process.0).map_err(|e| e.to_access_failure())?;

    if !is_in_system32(&image_native_path, system32_native_path) {
        return Err(ProcessAccessFailure::NotInSystem32);
    }

    let token = Token::from_process_handle(process.0).map_err(|e| e.to_access_failure())?;
    verify_session0_system_token(&token)?;

    Ok(token)
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
        Some(WTS_CURRENT_SERVER_HANDLE),
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
        Some(WTS_CURRENT_SERVER_HANDLE),
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
pub(crate) fn get_system32_path() -> Result<PathBuf, ElevateError> {
    let mut buf = [0u16; MAX_PATH as usize];

    let char_count = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if char_count == 0 {
        return Err(ElevateError::Win32 {
            operation: "GetSystemDirectoryW",
            source: windows::core::Error::from_thread(),
        });
    }
    if char_count >= buf.len() {
        return Err(ElevateError::PathBufferTooSmall {
            needed: char_count,
            capacity: buf.len(),
        });
    }

    Ok(wide_to_path(&buf[..char_count]))
}

/// Query the resolved NT device path of the canonical System32 directory (e.g. `\Device\HarddiskVolume3\Windows\System32`).
///
/// Resolves symlinks, directory junctions, and virtual volume remappings via kernel-level handle querying.
pub(crate) fn get_canonical_system32_native_path() -> Result<PathBuf, ElevateError> {
    let sys32_dos = get_system32_path()?;
    let path_hstring = HSTRING::from(sys32_dos.as_os_str());

    // FILE_FLAG_BACKUP_SEMANTICS is required to obtain a handle to a directory object.
    let dir_handle = HandleGuard(win32!(CreateFileW(
        PCWSTR(path_hstring.as_ptr()),
        FILE_GENERIC_READ.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    ))?);

    let mut buf = [0u16; 1024];
    let char_count =
        unsafe { GetFinalPathNameByHandleW(dir_handle.0, &mut buf, VOLUME_NAME_NT) } as usize;
    if char_count == 0 {
        return Err(ElevateError::Win32 {
            operation: "GetFinalPathNameByHandleW",
            source: windows::core::Error::from_thread(),
        });
    }
    if char_count >= buf.len() {
        return Err(ElevateError::PathBufferTooSmall {
            needed: char_count,
            capacity: buf.len(),
        });
    }

    Ok(wide_to_path(&buf[..char_count]))
}

/// Query the native NT device path of a running process image from an already open process handle.
///
/// Uses `PROCESS_NAME_NATIVE` to completely bypass DOS drive letter substitutions (`subst`),
/// junction points, and user-space symlink redirection.
pub(crate) fn get_process_image_native_path_from_handle(
    process_handle: HANDLE,
) -> Result<PathBuf, ElevateError> {
    let mut buf = [0u16; 1024];
    let mut char_count = buf.len() as u32;

    win32!(QueryFullProcessImageNameW(
        process_handle,
        PROCESS_NAME_NATIVE,
        PWSTR(buf.as_mut_ptr()),
        &raw mut char_count,
    ))?;

    Ok(wide_to_path(&buf[..char_count as usize]))
}

/// Convert a slice of UTF-16 code units into a [`PathBuf`].
#[inline]
fn wide_to_path(wide: &[u16]) -> PathBuf {
    PathBuf::from(OsString::from_wide(wide))
}

/// Verify that the given executable path is located directly inside the System32 directory
/// by comparing their normalized NT kernel device paths.
pub(crate) fn is_in_system32(exe_native_path: &Path, system32_native_path: &Path) -> bool {
    exe_native_path
        .parent()
        .and_then(|p| p.to_str())
        .zip(system32_native_path.to_str())
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

    #[test]
    fn elevator_default_context_is_interactive_default() {
        assert_eq!(
            *Elevator::default().context(),
            ExecutionContext::Interactive(InteractiveDesktop::Default)
        );
    }

    #[test]
    fn elevator_configuration_getters_reflect_parameters() {
        let elevator = Elevator::default()
            .with_service_timeout(Duration::from_secs(12))
            .with_session_target(SessionTarget::Explicit(99))
            .with_context(ExecutionContext::Headless);

        assert_eq!(elevator.service_timeout(), Duration::from_secs(12));
        assert_eq!(*elevator.session_target(), SessionTarget::Explicit(99));
        assert_eq!(*elevator.context(), ExecutionContext::Headless);
    }

    #[test]
    fn get_system32_path_locates_valid_system_directory() {
        let path = get_system32_path().expect("System32 directory path must be resolvable");
        let path = path.to_string_lossy().to_lowercase();
        assert!(
            path.contains("system32"),
            "System directory must contain 'system32', got: {path}"
        );
    }

    #[test]
    fn get_canonical_system32_native_path_resolves_to_device_volume() {
        let path = get_canonical_system32_native_path()
            .expect("System32 canonical NT path must be resolvable");
        let path = path.to_string_lossy();
        assert!(
            path.starts_with(r"\Device\"),
            "Canonical NT path must start with '\\Device\\', got: {path}"
        );
        assert!(
            path.to_lowercase().ends_with(r"\system32"),
            "Canonical NT path must end with '\\system32', got: {path}"
        );
    }

    /// Verifies that `inspect_candidate_process` correctly opens a real running process
    /// but strictly rejects it because its binary does not reside in System32.
    #[test]
    fn inspect_candidate_process_rejects_current_non_system32_process() {
        let system32_native_path = get_canonical_system32_native_path()
            .expect("System32 canonical NT path must be resolvable");
        let current_pid = std::process::id();

        let result = inspect_candidate_process(current_pid, &system32_native_path);

        assert!(
            matches!(result, Err(ProcessAccessFailure::NotInSystem32)),
            "inspect_candidate_process must reject the current test process with NotInSystem32, got: {result:?}"
        );
    }

    /// Verifies that constructing a Token from an invalid process handle correctly yields an `OpenProcessToken` Win32 error.
    #[test]
    fn token_from_process_handle_with_invalid_handle_returns_win32_error() {
        let result = Token::from_process_handle(HANDLE::default());
        match result {
            Err(ElevateError::Win32 { operation, .. }) => {
                assert_eq!(operation, "OpenProcessToken");
            }
            other => panic!("Expected Win32 OpenProcessToken error, got: {other:?}"),
        }
    }

    #[test]
    fn is_in_system32_matches_only_direct_children_with_nt_paths() {
        let system32_nt = Path::new(r"\Device\HarddiskVolume3\Windows\System32");

        assert!(is_in_system32(
            Path::new(r"\Device\HarddiskVolume3\Windows\System32\services.exe"),
            system32_nt
        ));
        assert!(is_in_system32(
            Path::new(r"\device\harddiskvolume3\windows\system32\svchost.exe"),
            system32_nt
        ));
        assert!(!is_in_system32(
            Path::new(r"\Device\HarddiskVolume3\Windows\System32\drivers\etc"),
            system32_nt
        ));
        assert!(!is_in_system32(
            Path::new(r"\Device\HarddiskVolume3\Windows\explorer.exe"),
            system32_nt
        ));
        assert!(!is_in_system32(
            Path::new(r"\Device\HarddiskVolume4\Windows\System32\fake_services.exe"),
            system32_nt
        ));
    }

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

    #[test]
    fn resolve_session_returns_active_or_explicit_session() {
        let current_token = Token::current().unwrap();
        let current_session = current_token.session_id().unwrap();

        assert_eq!(
            resolve_session(&current_token, &SessionTarget::Explicit(42)).unwrap(),
            42
        );

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

        let report = token.report().expect("Token must contain elevation report");
        assert_eq!(report.target_session, 0);
        assert!(report.pivot_pid > 0);
        assert_ne!(report.pivot_process_name, "");
    }

    // End-to-end test: Acquire a genuine TrustedInstaller token bound to the active user's desktop session.
    #[test]
    #[ignore = "requires elevated Administrator privileges and an active desktop session"]
    fn acquire_primary_token_interactive_binds_to_caller_session() {
        assert_elevated_context();

        let elevator = Elevator::default();
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

        let report = token.report().expect("Token must contain elevation report");
        assert_eq!(report.target_session, caller_session);
        assert!(report.pivot_pid > 0);
        assert_ne!(report.pivot_process_name, "");
    }
}
