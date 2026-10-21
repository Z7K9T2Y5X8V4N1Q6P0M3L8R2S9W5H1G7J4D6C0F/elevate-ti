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
    security::{
        ExecutionContext, Privilege, ProcessSnapshot, ServiceManager, Token, TokenType, win32,
    },
    strategy::ElevationStrategy,
};

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

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
}

impl Default for TrustedInstallerStrategy {
    fn default() -> Self {
        Self {
            service_timeout: Duration::from_secs(30),
            context: ExecutionContext::default(),
            session_target: SessionTarget::default(),
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
        }
    }

    /// Configure a custom session target policy for interactive contexts.
    #[must_use]
    pub fn with_session_target(mut self, session_target: SessionTarget) -> Self {
        self.session_target = session_target;
        self
    }

    /// Returns a reference to the configured host execution context.
    ///
    /// Useful for telemetry, structured logging, or dispatching logic based
    /// on whether elevation is interactive or headless.
    #[must_use]
    pub const fn context(&self) -> &ExecutionContext {
        &self.context
    }
}

impl ElevationStrategy for TrustedInstallerStrategy {
    fn acquire_primary_token(&self) -> Result<Token, ElevateError> {
        let current_token = Token::current()?;
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

        let system_pid = match target_session {
            Some(session_id) => find_system_process("winlogon.exe", session_id)?,
            None => find_any_system_process()?,
        };

        let _impersonation_guard = Token::from_pid(system_pid)?
            .duplicate(TokenType::Impersonation)?
            .impersonate()?;

        let ti_primary_token = Token::from_pid(ti_pid)?.duplicate(TokenType::Primary)?;

        if let Some(session_id) = target_session {
            ti_primary_token.set_session_id(session_id)?;
        }

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

    let sessions = unsafe { std::slice::from_raw_parts(p_info, count as usize) };
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

fn find_any_system_process() -> Result<u32, ElevateError> {
    let current_pid = std::process::id();
    let mut best: Option<u32> = None;

    for (pid, _) in ProcessSnapshot::new()? {
        if pid == current_pid || pid <= 4 {
            continue;
        }

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
