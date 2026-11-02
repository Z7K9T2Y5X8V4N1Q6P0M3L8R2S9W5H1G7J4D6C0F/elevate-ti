//! Advanced Windows privilege elevation engine supporting both interactive and headless contexts.

use std::{
    collections::HashSet,
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

const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
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

    /// Finds a usable, unrestricted SYSTEM process inside Session 0 using a two-stage scan.
    ///
    /// # The Search Strategy
    /// - **Stage 1 (Primary Strategy)**: Target `services.exe` first. It runs 24/7, lives in Session 0,
    ///   and Windows does not lock it down with `WinTCB` PPL armor.
    /// - **Stage 2 (Fallback Strategy)**: If `services.exe` is blocked (e.g. by hyper-aggressive third-party
    ///   antivirus hooks), scan all other accessible processes to find another valid Session 0 SYSTEM daemon.
    fn resolve_system_process(&self) -> Result<u32, ElevateError> {
        let system32_path = get_system32_path()?;

        // The Windows ToolHelp snapshot is a one-way street: once you iterate to the end,
        // you cannot rewind it back to the start.
        // We collect all processes into a `Vec` upfront so we can loop through them twice
        // (Stage 1 for services.exe, and Stage 2 for the fallback scan).
        let processes: Vec<(u32, String)> = ProcessSnapshot::new()?.collect();
        // Collects rejection reasons for failed candidates. If both stages fail,
        // we print this full list so the user sees exactly why each process was rejected.
        let mut diagnostics = Vec::new();
        // Tracks PIDs already inspected in Stage 1 to avoid wasting time checking them again in Stage 2.
        let mut checked_pids = HashSet::new();

        // Stage 1: Try the preferred target first (defaults to "services.exe").
        for &(pid, ref name) in &processes {
            if !name.eq_ignore_ascii_case(&self.preferred_system_process) {
                continue;
            }

            checked_pids.insert(pid);

            // Step 1: Query the actual executable path on disk.
            // If we can't even query the path (e.g. access denied), log why and move on.
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
            // Step 2: Path verification. Stop imposter processes running from C:\Temp\services.exe.
            if !is_in_system32(&image_path, &system32_path) {
                diagnostics.push(ProcessDiagnostic {
                    pid,
                    name: name.clone(),
                    reason: ProcessAccessFailure::NotInSystem32,
                });
                continue;
            }

            // Step 3: Open the process token.
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

            // Step 4: Run the 5-point safety check (Session 0, real SYSTEM SID, un-restricted, etc.).
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

        // Stage 2: Fallback scan across all other running processes.
        let current_pid = std::process::id();
        for &(pid, ref name) in &processes {
            // Skip:
            // - PID 0 (System Idle) & PID 4 (System Kernel): You cannot open user-mode tokens for the kernel.
            // - Current PID: We can't elevate by stealing from our own unprivileged self.
            // - Already checked PIDs: Don't repeat work from Stage 1.
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

                // If a process is simply running under a normal user account or network service,
                // that's totally expected during a full-system scan—don't pollute our error log with it.
                Err(ProcessAccessFailure::NotSystemSid { .. }) => {}

                // But if it IS a SYSTEM process and failed for another weird reason (e.g. restricted or demoted),
                // log it in diagnostics so the user knows why it was rejected.
                Err(reason) => {
                    diagnostics.push(ProcessDiagnostic {
                        pid,
                        name: name.clone(),
                        reason,
                    });
                }
            }
        }

        // If both stages failed, return all collected diagnostics explaining why each candidate was rejected.
        Err(ElevateError::NoViableSystemProcess { diagnostics })
    }
}

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

/// Resolves an active, user-authenticated Windows session for interactive UI delegation.
///
/// Implements a prioritized two-tier session election algorithm:
/// 1. **Primary Target**: The physical console session (`WTSGetActiveConsoleSessionId`)
///    directly connected to local video/input peripherals.
/// 2. **Fallback Target**: The first active authenticated remote desktop (RDP) session.
fn find_any_interactive_session() -> Result<u32, ElevateError> {
    let mut session_info_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;

    // Enumerate all active and inactive terminal sessions in the local subsystem.
    win32!(WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &raw mut session_info_ptr,
        &raw mut count,
    ))?;

    let _guard = WtsMemoryGuard(session_info_ptr.cast());

    // Defensive boundary check: In modern Windows, Session 0 is universally guaranteed to exist.
    // If the API returns a null pointer or 0 count despite succeeding, the Terminal Services buffer
    // is corrupted or intercepted by faulty third-party API hooks/EDR drivers.
    if session_info_ptr.is_null() || count == 0 {
        return Err(ElevateError::InvalidSystemBuffer);
    }

    let sessions = unsafe { slice::from_raw_parts(session_info_ptr, count as usize) };
    let console_session_id = unsafe { WTSGetActiveConsoleSessionId() };

    let mut candidate: Option<u32> = None;
    let mut diagnostics = Vec::new();

    for session in sessions {
        // Filter out disconnected (WTSDisconnected), paused, or terminating sessions.
        // `WTSActive` guarantees the session's display and input channels are actively engaged.
        if session.State != WTSActive {
            continue;
        }

        // Validate that an authenticated, human user is actually logged into this session.
        // A session in `WTSActive` state may still just be resting at the Windows Logon/Lock screen (LogonUI).
        match has_logged_on_user(session.SessionId) {
            Ok(true) => {
                // Priority 1: Physical Console match.
                // The user is sitting directly in front of the machine's primary display and peripherals.
                // Short-circuit immediately to avoid spawning onto an incidental background RDP session.
                if session.SessionId == console_session_id {
                    return Ok(session.SessionId);
                }

                // Priority 2: Remote / RDP session fallback.
                // First-fit arbitration: preserve the first discovered authenticated remote user session,
                // while continuing the scan in case the physical console session appears later.
                if candidate.is_none() {
                    candidate = Some(session.SessionId);
                }
            }
            Ok(false) => {
                // The session is physically or remotely connected (Active), but has no bound user identity
                // (e.g. at the login credential prompt, or a headless display dummy/emulator).
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
                // Record API-level access denial or system errors (e.g. 0x80070005 ACCESS_DENIED)
                // for structured diagnostics instead of silently ignoring the underlying root cause.
                diagnostics.push(SessionDiagnostic {
                    session_id: session.SessionId,
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

    // SAFETY: Terminal Services guarantees a valid null-terminated UTF-16 wide string buffer on success.
    // In C-style wide strings, an empty username (`""`) begins immediately with the null terminator `\0` (0x0000).
    // Inspecting the 0th `u16` character is an O(1) non-allocating check:
    // - `*raw_ptr.0 == 0`: Empty string (unauthenticated session / login screen).
    // - `*raw_ptr.0 != 0`: Non-empty string (authenticated user actively logged on).
    Ok(unsafe { *raw_ptr.0 != 0 })
}

/// Retrieve the canonical System32 directory path (e.g. `C:\Windows\System32`).
fn get_system32_path() -> Result<PathBuf, ElevateError> {
    let mut buf = [0u16; MAX_PATH as usize];
    let char_count = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if char_count == 0 || char_count > buf.len() {
        return Err(ElevateError::SystemDirectoryNotFound);
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..char_count])))
}

/// Query the full executable image path backing an active process.
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

    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..char_count as usize],
    )))
}

/// Pure path verification: checks whether a binary lives directly inside the System32 folder.
///
/// # Why check the file path? Why not just trust the process name?
/// Relying only on process names (like `"services.exe"`) is completely broken:
/// Anyone can write a fake binary, name it `services.exe`, drop it in `C:\Temp\services.exe`,
/// and run it. If our elevation code blindly trusted process names, we could accidentally
/// hijack a malicious imposter process instead of the real Windows service!
///
/// Real Windows core services live strictly inside `%SystemRoot%\System32`, which is locked down
/// by the OS and writable only by `TrustedInstaller`. Verifying the physical folder path guarantees
/// we only steal tokens from genuine Windows system binaries.
///
/// # Why must it be a DIRECT child (`exe_path.parent()`)?
/// We strictly require the parent directory to match `System32`:
/// - **Allowed**: `C:\Windows\System32\services.exe` (parent is `System32`).
/// - **Rejected**: `C:\Windows\System32\drivers\etc\fake.exe` (parent is `drivers\etc`, rejected!).
/// - **Rejected**: `C:\Windows\explorer.exe` (outside `System32`, rejected!).
///
/// This stops someone from hiding an executable in writable subfolders inside the Windows directory.
fn is_in_system32(exe_path: &Path, system32_path: &Path) -> bool {
    exe_path
        .parent()
        .and_then(|p| p.to_str())
        .zip(system32_path.to_str())
        .is_some_and(|(parent, system32)| parent.eq_ignore_ascii_case(system32))
}

/// Checks if this token is a real, unrestricted SYSTEM token running in Session 0.
///
/// # Why steal from Session 0 instead of `winlogon.exe`?
/// You might see lazy elevation scripts on GitHub grab `winlogon.exe` in user sessions (Session 1+).
/// On a standard, unhardened Home Edition PC, that often works because `winlogon.exe` runs as SYSTEM
/// and isn't locked down by default.
///
/// But targeting `winlogon.exe` is a trap that blows up in real-world environments:
/// 1. **PPL & Credential Guard**: In corporate networks, enterprise editions, or machines with
///    Credential Guard enabled, Windows wraps interactive auth processes in PPL (Protected Process Light).
///    When that happens, calling `OpenProcess` on `winlogon.exe` fails with `0x00000005 (ACCESS_DENIED)`—even
///    if you are an Administrator holding `SeDebugPrivilege`.
/// 2. **Headless / CI Disaster**: `winlogon.exe` only exists when someone is actually logged into
///    a physical desktop! If your code runs inside a Windows background service, a scheduled task,
///    or a headless CI/CD runner (like GitHub Actions), there is NO user desktop, and `winlogon.exe`
///    won't even exist.
///
/// That is why we strictly pivot through Session 0 (`services.exe`):
/// - It is running 24/7 on every Windows machine, whether a monitor is plugged in or not.
/// - It is not locked behind user-session PPL armor, making it work universally across Home, Pro,
///   Enterprise, and headless server environments.
///
/// # Why 5 separate checks? (What happens if we skip them?)
/// Just finding a token that says "SYSTEM" in Session 0 isn't enough. Without these checks:
/// - We might steal a sandboxed Defender/Antivirus worker that has its permissions neutered.
/// - We might steal a hardened service token whose integrity level was dropped down to standard user.
/// - We might steal a token lacking impersonation rights, breaking our thread-stealing code later.
fn verify_session0_system_token(token: &Token) -> Result<(), ProcessAccessFailure> {
    // Check 1: Make sure the token actually belongs to Local System ("S-1-5-18").
    // If we skip this, we might accidentally grab a service running as "LocalService" (S-1-5-19)
    // or "NetworkService" (S-1-5-20), which have nowhere near the power of true SYSTEM.
    let sid = token.user_sid().map_err(|e| e.to_access_failure())?;
    if sid != LOCAL_SYSTEM_SID {
        return Err(ProcessAccessFailure::NotSystemSid { sid });
    }

    // Check 2: Confirm this token actually lives in Session 0.
    // If we accidentally grab a SYSTEM token from Session 1 (a logged-in desktop),
    // our code will blow up the moment we try to use it in background environments or headless CI.
    let actual = token.session_id().map_err(|e| e.to_access_failure())?;
    if actual != 0 {
        return Err(ProcessAccessFailure::SessionMismatch {
            expected: 0,
            actual,
        });
    }

    // Check 3: Check if Windows neutered this token (Restricted / Filtered token).
    // Some background workers run as SYSTEM, but Windows flags their token as "Restricted"
    // to lock them in a sandbox. A restricted token cannot be used to elevate anything.
    if token.is_restricted().map_err(|e| e.to_access_failure())? {
        return Err(ProcessAccessFailure::RestrictedToken);
    }

    // Check 4: Check the Integrity Level (must be SYSTEM altitude, 0x4000 or higher).
    // Windows allows services to drop their own integrity down to Medium or Low to protect themselves.
    // If we steal an integrity-demoted token, we won't have the permissions needed to hijack TrustedInstaller.
    let level = token.integrity_level().map_err(|e| e.to_access_failure())?;
    let expected = SECURITY_MANDATORY_SYSTEM_RID as u32;
    if level < expected {
        return Err(ProcessAccessFailure::LowIntegrityLevel { level, expected });
    }

    // Check 5: Make sure the token holds `SeImpersonatePrivilege`.
    // Our entire elevation strategy relies on borrowing this token onto our own thread.
    // If the token lacks this exact right, the Windows kernel will reject our upcoming
    // `ImpersonateLoggedOnUser` call and crash the pipeline.
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

    // Ensure `verify_session0_system_token` accepts only genuine Local System (S-1-5-18) tokens
    // residing strictly in Session 0, rejecting both non-system accounts and interactive system tokens.
    //
    // Context-dependent behavior:
    // - Normal dev/CI running on an interactive desktop (Session >= 1) will fail fast with NotSystemSid.
    // - If running as an interactive SYSTEM user (e.g. PsExec in Session 1+), it must fail with SessionMismatch.
    // - If running directly as a Session 0 daemon/service, it must pass verification.
    #[test]
    fn verify_session0_system_token_rejects_non_system_or_non_session0_tokens() {
        let current_token = Token::current().unwrap();
        let current_sid = current_token.user_sid().unwrap();
        let current_session = current_token.session_id().unwrap();

        let result = verify_session0_system_token(&current_token);

        if current_sid == LOCAL_SYSTEM_SID && current_session == 0 {
            assert!(
                result.is_ok(),
                "Session 0 Local System token must be accepted"
            );
        } else if current_sid != LOCAL_SYSTEM_SID {
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
