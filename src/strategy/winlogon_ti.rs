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
    error::{ElevateError, ProcessAccessFailure, ProcessDiagnostic},
    security::{
        ExecutionContext, HandleGuard, Privilege, ProcessSnapshot, ServiceManager, Token,
        TokenType, win32,
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
        let system32 = get_system32_directory().ok_or_else(|| {
            ElevateError::ProcessNotFound("system32 directory unresolvable".to_string())
        })?;

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

            if !is_system32_binary(pid, &system32) {
                diagnostics.push(ProcessDiagnostic {
                    pid,
                    name: name.clone(),
                    reason: ProcessAccessFailure::NotInSystem32,
                });
                continue;
            }

            match Token::from_pid(pid) {
                Ok(token) => {
                    if is_viable_system_token(&token, Some(0)) {
                        return Ok(pid);
                    }
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: ProcessAccessFailure::InsufficientPrivileges,
                    });
                }
                Err(e) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
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
            if !is_system32_binary(pid, &system32) {
                continue;
            }

            match Token::from_pid(pid) {
                Ok(token) => {
                    if is_viable_system_token(&token, Some(0)) {
                        return Ok(pid);
                    }
                    // Deliberate design decision:
                    // In Stage 2, processes that are accessible but lack SYSTEM privileges (e.g.
                    // network services or non-admin worker tokens) are expected and therefore
                    // skipped without recording to avoid polluting the diagnostic report.
                }
                Err(e) => {
                    // Security blocks (e.g. AccessDenied from PPL/EDR) are recorded for troubleshooting.
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason: e.to_access_failure(),
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

fn find_any_interactive_session() -> Result<u32, ElevateError> {
    let mut p_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;

    win32!(WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &raw mut p_info,
        &raw mut count,
    ))?;

    let _session_list_guard = WtsMemoryGuard(p_info.cast());

    if p_info.is_null() || count == 0 {
        return Err(ElevateError::NoInteractiveSession);
    }

    let sessions = unsafe { slice::from_raw_parts(p_info, count as usize) };
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };

    let mut candidate: Option<u32> = None;

    for s in sessions {
        if s.State != WTSActive || !has_logged_on_user(s.SessionId) {
            continue;
        }

        if s.SessionId == console_session_id {
            return Ok(s.SessionId);
        }

        if candidate.is_none() {
            candidate = Some(s.SessionId);
        }
    }

    candidate.ok_or(ElevateError::NoInteractiveSession)
}

fn has_logged_on_user(session_id: u32) -> bool {
    let mut raw_ptr = PWSTR::null();
    let mut bytes = 0u32;

    let res = win32!(WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE,
        session_id,
        WTSUserName,
        &raw mut raw_ptr,
        &raw mut bytes,
    ));

    if res.is_err() || raw_ptr.is_null() {
        return false;
    }

    let _username_buf_guard = WtsMemoryGuard(raw_ptr.0.cast());
    unsafe { *raw_ptr.0 != 0 }
}

/// Retrieve the canonical System32 directory (e.g. `C:\Windows\System32`).
fn get_system32_directory() -> Option<PathBuf> {
    let mut buf = [0u16; MAX_PATH as usize];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if len == 0 || len > buf.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..len])))
}

/// Verifies whether the executable backing a process is physically located in the System32 folder.
fn is_system32_binary(pid: u32, system32: &Path) -> bool {
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
    else {
        return false;
    };
    let _guard = HandleGuard(process);

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;

    let res = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &raw mut size,
        )
    };

    if res.is_err() || size == 0 {
        return false;
    }

    let exe_path = PathBuf::from(String::from_utf16_lossy(&buf[..size as usize]));
    exe_path
        .parent()
        .and_then(|p| p.to_str())
        .zip(system32.to_str())
        .is_some_and(|(parent, sys)| parent.eq_ignore_ascii_case(sys))
}

/// Verifies whether an opened Token has full, unrestricted SYSTEM capabilities.
fn is_viable_system_token(token: &Token, target_session: Option<u32>) -> bool {
    let is_system = token.user_sid().is_ok_and(|sid| sid == LOCAL_SYSTEM_SID);
    if !is_system {
        return false;
    }

    if target_session.is_some_and(|expected| !token.session_id().is_ok_and(|s| s == expected)) {
        return false;
    }

    if token.is_restricted().unwrap_or(true) {
        return false;
    }

    let is_system_il = token
        .integrity_level()
        .is_ok_and(|il| il >= SECURITY_MANDATORY_SYSTEM_RID as u32);
    if !is_system_il {
        return false;
    }

    token
        .has_privilege_present(Privilege::Impersonate)
        .unwrap_or(false)
}
