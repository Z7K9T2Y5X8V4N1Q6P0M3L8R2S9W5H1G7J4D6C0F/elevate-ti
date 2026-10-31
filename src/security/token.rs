//! Process and thread security token manipulation.

use std::{marker::PhantomData, mem, ptr, slice};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, HANDLE, LUID,
            SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, ImpersonateLoggedOnUser, IsTokenRestricted, IsValidSid,
            LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf, SE_PRIVILEGE_ENABLED,
            SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ACCESS_MASK,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ELEVATION, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
            TOKEN_USER, TokenElevation, TokenGroups, TokenImpersonation, TokenIntegrityLevel,
            TokenPrimary, TokenPrivileges, TokenSessionId, TokenUser,
        },
        System::{
            SystemServices::{MAXIMUM_ALLOWED, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            },
        },
    },
    core::PCWSTR,
};

use super::{guard::HandleGuard, privilege::Privilege, sid::Sid, win32};
use crate::error::ElevateError;

/// Target token type when duplicating an existing security token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Primary token for launching new process instances.
    Primary,
    /// Impersonation token for thread-level security context borrowing.
    Impersonation,
}

/// Strongly-typed RAII guard holding an open process or thread token handle.
pub struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

impl Token {
    /// Open the token belonging to the current application process.
    pub(crate) fn current() -> Result<Self, ElevateError> {
        let mut handle = HANDLE::default();
        win32!(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut handle
        ))?;
        Ok(Self(handle))
    }

    /// Open the security token belonging to an arbitrary running process by PID.
    pub(crate) fn from_pid(pid: u32) -> Result<Self, ElevateError> {
        let process = HandleGuard(win32!(OpenProcess(PROCESS_QUERY_INFORMATION, false, pid))?);
        let mut token = HANDLE::default();
        win32!(OpenProcessToken(
            process.0,
            TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
            &raw mut token
        ))?;
        Ok(Self(token))
    }

    /// Borrow the underlying raw Win32 `HANDLE`.
    pub const fn as_raw(&self) -> HANDLE {
        self.0
    }

    /// Duplicate this token as either a Primary or Impersonation token.
    pub(crate) fn duplicate(&self, token_type: TokenType) -> Result<Self, ElevateError> {
        let access = match token_type {
            TokenType::Primary => TOKEN_ALL_ACCESS,
            TokenType::Impersonation => TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
        };
        let raw_type = match token_type {
            TokenType::Primary => TokenPrimary,
            TokenType::Impersonation => TokenImpersonation,
        };

        let mut dup = HANDLE::default();
        win32!(DuplicateTokenEx(
            self.0,
            access,
            None,
            SecurityImpersonation,
            raw_type,
            &raw mut dup
        ))?;
        Ok(Self(dup))
    }

    /// Enable the specified administrative privileges on this token.
    ///
    /// If the token does not hold the privilege (e.g. running as non-elevated user),
    /// this returns [`ElevateError::PrivilegeNotHeld`].
    pub(crate) fn enable_privileges(&self, privileges: &[Privilege]) -> Result<(), ElevateError> {
        for &privilege in privileges {
            let mut luid = LUID::default();
            win32!(LookupPrivilegeValueW(
                PCWSTR::null(),
                privilege.as_pcwstr(),
                &raw mut luid
            ))?;

            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            unsafe { SetLastError(WIN32_ERROR(0)) };
            win32!(AdjustTokenPrivileges(
                self.0,
                false,
                Some(ptr::from_ref(&privileges)),
                mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                None,
                None,
            ))?;

            // AdjustTokenPrivileges returns TRUE even if privileges were not assigned
            // (ERROR_NOT_ALL_ASSIGNED), which indicates the token does not hold this privilege.
            if unsafe { GetLastError() } != ERROR_SUCCESS {
                return Err(ElevateError::PrivilegeNotHeld {
                    privilege: privilege.as_str(),
                });
            }
        }
        Ok(())
    }

    /// Check whether this token is running with elevated Administrator privileges.
    pub(crate) fn is_elevated_admin(&self) -> Result<bool, ElevateError> {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut bytes_needed = 0u32;

        win32!(GetTokenInformation(
            self.0,
            TokenElevation,
            Some(ptr::from_mut(&mut elevation).cast()),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &raw mut bytes_needed
        ))?;

        Ok(elevation.TokenIsElevated != 0)
    }

    /// Check whether this token is a Restricted Token.
    ///
    /// # Errors
    /// Returns an error if querying token status fails with a genuine OS error (e.g. invalid handle).
    pub(crate) fn is_restricted(&self) -> Result<bool, ElevateError> {
        unsafe { SetLastError(WIN32_ERROR(0)) };
        match unsafe { IsTokenRestricted(self.0) } {
            Ok(()) => Ok(true),
            Err(source) => {
                let err = unsafe { GetLastError() };
                if err == ERROR_SUCCESS {
                    Ok(false)
                } else {
                    Err(ElevateError::Win32 {
                        operation: "IsTokenRestricted",
                        source,
                    })
                }
            }
        }
    }

    /// Query the Integrity Level RID of this token (e.g. 0x4000 = SYSTEM, 0x3000 = HIGH).
    ///
    /// # Why are we parsing a SID here?
    /// An integrity level is fundamentally just a number (e.g. 0x4000 for SYSTEM).
    /// However, when Microsoft introduced Mandatory Integrity Control (MIC) in Windows Vista,
    /// instead of altering the core ACL model with a new data structure, they retrofitted
    /// integrity levels into "pseudo-SIDs" for backwards compatibility.
    ///
    /// Unlike normal user/group SIDs (`S-1-5-...`), an integrity label SID uses authority `16`
    /// (`SECURITY_MANDATORY_LABEL_AUTHORITY`), formatted as:
    ///
    /// ```text
    /// S-1-16-0x4000  (SYSTEM)
    /// S-1-16-0x3000  (HIGH / Administrator)
    /// S-1-16-0x2000  (MEDIUM / Standard User)
    /// S-1-16-0x1000  (LOW / Sandbox)
    /// ```
    ///
    /// The actual numeric level is stored as the final `SubAuthority` value of this pseudo-SID.
    pub(crate) fn integrity_level(&self) -> Result<u32, ElevateError> {
        let buf = self.query_info_buffer(TokenIntegrityLevel)?;
        let label = unsafe { &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };

        let sid = label.Label.Sid;

        // Defensive check: Ensure the pseudo-SID pointer is valid and properly formatted
        // before dereferencing, protecting against corrupted tokens or hooked APIs.
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(ElevateError::InvalidSid);
        }

        // An integrity pseudo-SID must contain at least one SubAuthority (which holds the RID).
        let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
        if count_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        let count = unsafe { *count_ptr };
        if count == 0 {
            return Err(ElevateError::InvalidSid);
        }

        // Extract the last SubAuthority (at index `count - 1`), which directly yields
        // the numeric integrity RID (e.g. extracting `0x4000` from `S-1-16-0x4000`).
        let sub_auth_ptr = unsafe { GetSidSubAuthority(sid, count as u32 - 1) };
        if sub_auth_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        Ok(unsafe { *sub_auth_ptr })
    }

    /// Check whether a specific privilege is present in this token's privilege table.
    pub(crate) fn has_privilege_present(&self, privilege: Privilege) -> Result<bool, ElevateError> {
        let mut target_luid = LUID::default();
        win32!(LookupPrivilegeValueW(
            PCWSTR::null(),
            privilege.as_pcwstr(),
            &raw mut target_luid
        ))?;

        let buf = self.query_info_buffer(TokenPrivileges)?;
        let base = buf.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let count = unsafe { (*base).PrivilegeCount as usize };
        if count == 0 {
            return Ok(false);
        }

        let privs_offset = mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        let privs_ptr = unsafe { base.byte_add(privs_offset).cast::<LUID_AND_ATTRIBUTES>() };
        let slice = unsafe { slice::from_raw_parts(privs_ptr, count) };

        Ok(slice.iter().any(|p| p.Luid == target_luid))
    }

    /// Query the Windows Session ID currently associated with this token.
    pub(crate) fn session_id(&self) -> Result<u32, ElevateError> {
        let mut session_id = 0u32;
        let mut bytes_needed = 0u32;
        win32!(GetTokenInformation(
            self.0,
            TokenSessionId,
            Some(ptr::from_mut(&mut session_id).cast()),
            mem::size_of::<u32>() as u32,
            &raw mut bytes_needed
        ))?;
        Ok(session_id)
    }

    /// Explicitly assign a Windows Session ID to this token.
    pub(crate) fn set_session_id(&self, session_id: u32) -> Result<(), ElevateError> {
        win32!(SetTokenInformation(
            self.0,
            TokenSessionId,
            ptr::from_ref(&session_id).cast(),
            mem::size_of::<u32>() as u32
        ))?;
        Ok(())
    }

    /// Execute a scoped operation while impersonating this token on the current OS thread.
    ///
    /// Guarantees that the impersonation context is bound to the enclosing scope and
    /// will always revert (`RevertToSelf`) on normal return or during panic unwinding.
    pub(crate) fn with_impersonation<F, R>(&self, f: F) -> Result<R, ElevateError>
    where
        F: FnOnce() -> Result<R, ElevateError>,
    {
        let _guard = self.impersonate()?;
        f()
    }

    /// Internal helper returning an RAII revert guard.
    pub(crate) fn impersonate(&self) -> Result<ImpersonationGuard, ElevateError> {
        win32!(ImpersonateLoggedOnUser(self.0))?;
        Ok(ImpersonationGuard {
            _marker: PhantomData,
        })
    }

    /// Retrieve the owner user SID string of this token.
    pub(crate) fn user_sid(&self) -> Result<String, ElevateError> {
        let buf = self.query_info_buffer(TokenUser)?;
        let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
        Sid::string_from_raw(user.User.Sid)
    }

    /// Check whether this token holds membership in the specified string SID.
    pub fn has_sid(&self, sid: PCWSTR) -> Result<bool, ElevateError> {
        let sid = Sid::parse(sid)?;
        let buf = self.query_info_buffer(TokenGroups)?;
        let base = buf.as_ptr().cast::<TOKEN_GROUPS>();
        let count = unsafe { (*base).GroupCount as usize };
        if count == 0 {
            return Ok(false);
        }

        let groups_offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_ptr = unsafe { base.byte_add(groups_offset).cast::<SID_AND_ATTRIBUTES>() };
        let slice = unsafe { slice::from_raw_parts(groups_ptr, count) };

        for group in slice {
            // SAFETY: `group.Sid` is guaranteed by the OS to point to a valid memory block within
            // the kernel-populated `TOKEN_GROUPS` buffer, and `target.as_raw()` is backed
            // by our own valid, live `Sid` instance. Neither pointer is modified concurrently.
            if unsafe { Sid::equal(group.Sid, sid.as_raw()) }? {
                // Defense-in-depth: Merely holding a SID in a token does not guarantee active membership.
                // UAC filtered tokens or restricted sandboxes mark sensitive SIDs with `SE_GROUP_USE_FOR_DENY_ONLY`,
                // effectively disabling them for access authorization while keeping them present in the token.
                // We ensure the SID is genuinely enabled (`SE_GROUP_ENABLED`) and not relegated to deny-only.
                let attrs = group.Attributes;
                let is_enabled = (attrs & (SE_GROUP_ENABLED as u32)) != 0;
                let is_deny_only = (attrs & (SE_GROUP_USE_FOR_DENY_ONLY as u32)) != 0;

                if is_enabled && !is_deny_only {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Query raw token information into a pointer-aligned memory buffer.
    ///
    /// # Why is this a two-stage query?
    /// Windows token information structures (such as groups, privileges, or labels) are
    /// dynamically sized and contain internal pointers and trailing arrays. The caller
    /// cannot know the required buffer size in advance.
    ///
    /// The standard Win32 pattern is a two-phase query:
    /// 1. **Probe Phase**: Call `GetTokenInformation` with a null buffer and length 0.
    ///    This call is **expected to fail** specifically with `ERROR_INSUFFICIENT_BUFFER`,
    ///    while the OS populates `bytes_needed` with the exact byte count required.
    ///    Any other error (such as `ERROR_ACCESS_DENIED` or `ERROR_INVALID_HANDLE`) indicates
    ///    a genuine OS failure that must be immediately reported rather than swallowed.
    /// 2. **Fetch Phase**: Allocate a suitably aligned buffer (using `Vec<usize>` to satisfy
    ///    pointer alignment requirements on 64-bit systems) and call the API again to populate it.
    fn query_info_buffer(
        &self,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, ElevateError> {
        let mut bytes_needed = 0u32;

        // Stage 1: Probe for required buffer capacity.
        unsafe {
            SetLastError(WIN32_ERROR(0));
            let _ = GetTokenInformation(self.0, class, None, 0, &raw mut bytes_needed);
            let last_error = GetLastError();
            // If the probe failed for any reason other than a buffer size shortfall
            // (e.g. access denied or invalid handle), immediately return the underlying Win32 error.
            if last_error != ERROR_INSUFFICIENT_BUFFER {
                return Err(ElevateError::Win32 {
                    operation: "GetTokenInformation (probe size)",
                    source: windows::core::Error::from_win32(),
                });
            }
        }

        // Defensive validation: ERROR_INSUFFICIENT_BUFFER guarantees bytes_needed > 0.
        // A zero length here indicates an impossible kernel state or corrupted return buffer.
        if bytes_needed == 0 {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        // Allocate a buffer guaranteed to be pointer-aligned (aligned to usize boundaries).
        let count = (bytes_needed as usize).div_ceil(mem::size_of::<usize>());
        let mut buf: Vec<usize> = vec![0; count];

        // Stage 2: Retrieve the actual token information payload.
        win32!(GetTokenInformation(
            self.0,
            class,
            Some(buf.as_mut_ptr().cast()),
            bytes_needed,
            &raw mut bytes_needed
        ))?;

        Ok(buf)
    }
}

/// Internal RAII guard representing active thread impersonation.
///
/// Marked as `!Send` and `!Sync` to guarantee it cannot cross thread boundaries
/// or `.await` suspension points.
pub(crate) struct ImpersonationGuard {
    _marker: PhantomData<*const ()>,
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::w;
    static_assertions::assert_not_impl_any!(ImpersonationGuard: Send, Sync);

    // =======================================================================
    // Non-elevated tests — safe to run in standard / CI environments
    // =======================================================================

    #[test]
    fn test_current_token_opens_successfully() {
        let token = Token::current();
        assert!(
            token.is_ok(),
            "Opening the current process token should always succeed"
        );
    }

    #[test]
    fn test_current_token_session_id_is_valid() {
        let token = Token::current().unwrap();
        let session = token.session_id();
        assert!(session.is_ok(), "Reading session ID must not fail");
    }

    #[test]
    fn test_current_token_user_sid_is_nonempty() {
        let token = Token::current().unwrap();
        let sid = token.user_sid().unwrap();
        assert!(
            sid.starts_with("S-1-"),
            "User SID must be a valid SID string, got: {sid}"
        );
    }

    #[test]
    fn test_is_elevated_admin_matches_integrity_level() {
        let token = Token::current().unwrap();

        let is_admin = token.is_elevated_admin().unwrap();
        let integrity_level = token.integrity_level().unwrap();

        if is_admin {
            assert!(
                integrity_level >= 0x3000,
                "Elevated admin must possess High/System integrity level (>= 0x3000), got: 0x{integrity_level:04X}"
            );
        } else {
            assert!(
                integrity_level < 0x3000,
                "Non-elevated user must possess Medium or lower integrity level (< 0x3000), got: 0x{integrity_level:04X}"
            );
        }
    }

    #[test]
    fn test_current_token_is_not_restricted() {
        let token = Token::current().unwrap();

        let is_restricted = token.is_restricted().unwrap();
        assert!(
            !is_restricted,
            "Current development/test process should not be a restricted token"
        );
    }

    #[test]
    fn test_has_sid_with_bogus_sid_returns_false() {
        let token = Token::current().unwrap();
        let has = token.has_sid(w!("S-1-5-80-0-0-0-0-999999")).unwrap();
        assert!(!has, "Token should not have a fabricated SID");
    }

    #[test]
    fn test_core_privileges_presence_matches_admin_status() {
        let token = Token::current().unwrap();
        let is_admin = token.is_elevated_admin().unwrap();

        let has_debug = token.has_privilege_present(Privilege::Debug).unwrap();
        let has_impersonate = token.has_privilege_present(Privilege::Impersonate).unwrap();

        if is_admin {
            assert!(
                has_debug,
                "Elevated administrator token must hold SeDebugPrivilege in its privilege table"
            );
            assert!(
                has_impersonate,
                "Elevated administrator token must hold SeImpersonatePrivilege in its privilege table"
            );
        }
    }
}
