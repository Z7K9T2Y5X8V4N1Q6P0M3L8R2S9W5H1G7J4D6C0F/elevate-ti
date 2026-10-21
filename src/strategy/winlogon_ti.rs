//! Advanced Windows privilege elevation strategy supporting both interactive and headless contexts.

use std::{ffi::c_void, time::Duration};

use windows::{
    Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
        WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
    },
    core::{PWSTR, w},
};

use crate::{
    error::ElevateError,
    security::{Privilege, ProcessSnapshot, ServiceManager, Token, TokenType, win32},
    strategy::ElevationStrategy,
};

/// Local System Account Well-Known SID string (`NT AUTHORITY\SYSTEM`).
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// RAII guard to safely free memory allocated by Windows Terminal Services (WTS).
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

/// Target interactive/headless session choice when generating the elevated token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SessionTarget {
    /// Bind token to the caller's active interactive session.
    /// Fast-fails with [`ElevateError::SessionZeroNotSupported`] if running in Session 0.
    #[default]
    CallerSession,

    /// Explicitly bind token to a specified Session ID.
    Explicit(u32),

    /// Automatically find the best active interactive desktop session (preferring physical console).
    /// Ideal for Session 0 background services that want to spawn UI onto the active user screen.
    AnyInteractive,

    /// Do not bind to any interactive desktop session.
    /// Returns a raw `TrustedInstaller` primary token inside Session 0.
    /// Ideal for headless system repairs, file operations, and registry manipulation.
    NoSession,
}

/// Chained elevation strategy utilizing SYSTEM tokens to acquire `TrustedInstaller`.
pub struct TrustedInstallerStrategy {
    service_timeout: Duration,
    session_target: SessionTarget,
}

impl Default for TrustedInstallerStrategy {
    fn default() -> Self {
        Self {
            service_timeout: Duration::from_secs(30),
            session_target: SessionTarget::default(),
        }
    }
}

impl TrustedInstallerStrategy {
    /// Create a strategy with custom service timeout and default caller session.
    pub const fn with_timeout(service_timeout: Duration) -> Self {
        Self {
            service_timeout,
            session_target: SessionTarget::CallerSession,
        }
    }

    /// Override the session target strategy while keeping default timeout.
    pub fn with_session_target(session_target: SessionTarget) -> Self {
        Self {
            service_timeout: Duration::from_secs(30),
            session_target,
        }
    }

    /// Full constructor.
    pub fn new(service_timeout: Duration, session_target: SessionTarget) -> Self {
        Self {
            service_timeout,
            session_target,
        }
    }
}

impl ElevationStrategy for TrustedInstallerStrategy {
    fn acquire_primary_token(&self) -> Result<Token, ElevateError> {
        // 1. Enable administrative debug and impersonation privileges.
        let current_token = Token::current()?;
        current_token.enable_privileges(&[Privilege::Debug, Privilege::Impersonate])?;

        // 2. Resolve intended session ID (None indicates Headless/NoSession).
        let target_session = resolve_session(&current_token, &self.session_target)?;

        // 3. Ensure TrustedInstaller service is started and retrieve its PID.
        let ti_pid = ServiceManager::open()?
            .service(w!("TrustedInstaller"))?
            .start_and_wait("TrustedInstaller", self.service_timeout)?;

        // 4. Locate an accessible SYSTEM process to borrow SYSTEM context.
        let system_pid = match target_session {
            Some(session_id) => find_system_process("winlogon.exe", session_id)?,
            None => find_any_system_process()?,
        };

        // 5. Temporarily impersonate the SYSTEM token.
        let _impersonation_guard = Token::from_pid(system_pid)?
            .duplicate(TokenType::Impersonation)?
            .impersonate()?;

        // 6. Duplicate the primary token of TrustedInstaller while acting as SYSTEM.
        let ti_primary_token = Token::from_pid(ti_pid)?.duplicate(TokenType::Primary)?;

        // 7. Breakthrough Session 0 isolation if an interactive desktop session is requested.
        if let Some(session_id) = target_session {
            ti_primary_token.set_session_id(session_id)?;
        }

        Ok(ti_primary_token)
    }
}

/// Resolve the concrete Session ID based on caller policy.
fn resolve_session(
    caller_token: &Token,
    target: &SessionTarget,
) -> Result<Option<u32>, ElevateError> {
    match target {
        SessionTarget::CallerSession => {
            let id = caller_token.session_id()?;
            if id == 0 {
                return Err(ElevateError::SessionZeroNotSupported);
            }
            Ok(Some(id))
        }
        SessionTarget::Explicit(id) => Ok(Some(*id)),
        SessionTarget::AnyInteractive => find_any_interactive_session().map(Some),
        SessionTarget::NoSession => Ok(None),
    }
}

/// Find the most appropriate active interactive user session using Terminal Services APIs.
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

    let sessions = unsafe { std::slice::from_raw_parts(p_info, count as usize) };
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };

    let mut candidate: Option<u32> = None;

    for s in sessions {
        if s.State != WTSActive {
            continue;
        }

        if !has_logged_on_user(s.SessionId) {
            continue;
        }

        // Prefer physical console session immediately if active.
        if s.SessionId == console_session_id {
            return Ok(s.SessionId);
        }

        if candidate.is_none() {
            candidate = Some(s.SessionId);
        }
    }

    candidate.ok_or(ElevateError::NoInteractiveSession)
}

/// Check if a session has an active, logged-on interactive username.
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

    // Name clearly indicates RAII ownership of the queried username buffer.
    let _username_buf_guard = WtsMemoryGuard(raw_ptr.0.cast());

    // Check if the username string starts with non-null character.
    unsafe { *raw_ptr.0 != 0 }
}

/// Find a genuine SYSTEM process ID by name inside the specified session.
fn find_system_process(process_name: &str, session_id: u32) -> Result<u32, ElevateError> {
    for (pid, name) in ProcessSnapshot::new()? {
        if !name.eq_ignore_ascii_case(process_name) {
            continue;
        }

        if let Ok(token) = Token::from_pid(pid) {
            let is_matching_session = token.session_id().is_ok_and(|s| s == session_id);
            let is_system_user = token.user_sid().is_ok_and(|sid| sid == LOCAL_SYSTEM_SID);

            if is_matching_session && is_system_user {
                return Ok(pid);
            }
        }
    }

    Err(ElevateError::ProcessNotFound(process_name.to_string()))
}

/// Dynamically locate an accessible SYSTEM process in Session 0 by lowest PID.
/// Automatically filters out PPL protected processes by checking handle access.
fn find_any_system_process() -> Result<u32, ElevateError> {
    let current_pid = std::process::id();
    let mut best: Option<u32> = None;

    for (pid, _) in ProcessSnapshot::new()? {
        if pid == current_pid || pid <= 4 {
            // Skip self and system idle/kernel process
            continue;
        }

        // Token::from_pid performs OpenProcess. PPL or inaccessible processes will error out here.
        let Ok(token) = Token::from_pid(pid) else {
            continue;
        };

        let is_system = token.user_sid().is_ok_and(|sid| sid == LOCAL_SYSTEM_SID);
        let is_session0 = token.session_id().is_ok_and(|s| s == 0);

        if is_system && is_session0 {
            best = Some(best.map_or(pid, |prev| prev.min(pid)));
        }
    }

    best.ok_or_else(|| {
        ElevateError::ProcessNotFound("accessible Session 0 SYSTEM process".to_string())
    })
}
