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
            IsWellKnownSid, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, RevertToSelf,
            SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation,
            TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ELEVATION,
            TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES,
            TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenGroups, TokenImpersonation,
            TokenIntegrityLevel, TokenPrimary, TokenPrivileges, TokenSessionId, TokenUser,
            WELL_KNOWN_SID_TYPE,
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

    /// Checks whether this token is restricted.
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

    /// Query the mandatory integrity level RID of this security token.
    ///
    /// Retrieves the token's mandatory integrity label (`TokenIntegrityLevel`) and extracts
    /// the last sub-authority of the integrity SID (e.g. `0x3000` for High, `0x4000` for System).
    pub(crate) fn integrity_level(&self) -> Result<u32, ElevateError> {
        let buf = self.query_info_buffer(TokenIntegrityLevel)?;
        let label: &TOKEN_MANDATORY_LABEL = Self::cast_buffer(&buf);
        let sid = label.Label.Sid;
        if sid.0.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        let is_valid = unsafe { IsValidSid(sid) }.as_bool();
        if !is_valid {
            return Err(ElevateError::InvalidSid);
        }

        let count_ptr = unsafe { GetSidSubAuthorityCount(sid) };
        if count_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        let count = unsafe { *count_ptr };
        if count == 0 {
            return Err(ElevateError::InvalidSid);
        }

        let sub_auth_ptr = unsafe { GetSidSubAuthority(sid, count as u32 - 1) };
        if sub_auth_ptr.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        Ok(unsafe { *sub_auth_ptr })
    }

    /// Check whether a specific privilege is held (present) on this security token.
    ///
    /// Note that this checks for the presence of the privilege in the token, regardless
    /// of whether it is currently enabled (`SE_PRIVILEGE_ENABLED`) or disabled.
    pub(crate) fn has_privilege_present(&self, privilege: Privilege) -> Result<bool, ElevateError> {
        let mut luid = LUID::default();
        win32!(LookupPrivilegeValueW(
            PCWSTR::null(),
            privilege.as_pcwstr(),
            &raw mut luid
        ))?;

        let buf = self.query_info_buffer(TokenPrivileges)?;
        let privs: &TOKEN_PRIVILEGES = Self::cast_buffer(&buf);
        let count = privs.PrivilegeCount as usize;
        if count == 0 {
            return Ok(false);
        }

        let privs_offset = mem::offset_of!(TOKEN_PRIVILEGES, Privileges);
        let privs_ptr = unsafe {
            ptr::from_ref(privs)
                .byte_add(privs_offset)
                .cast::<LUID_AND_ATTRIBUTES>()
        };
        let slice = unsafe { slice::from_raw_parts(privs_ptr, count) };
        Ok(slice.iter().any(|p| p.Luid == luid))
    }

    /// Query the Windows Terminal Services (Remote Desktop) Session ID associated with this token.
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

    /// Reassign the Windows Session ID of this token (`TokenSessionId`).
    ///
    /// Requires the caller to hold `SeTcbPrivilege` (typically obtained by impersonating SYSTEM).
    pub(crate) fn set_session_id(&self, session_id: u32) -> Result<(), ElevateError> {
        win32!(SetTokenInformation(
            self.0,
            TokenSessionId,
            ptr::from_ref(&session_id).cast(),
            mem::size_of::<u32>() as u32
        ))?;
        Ok(())
    }

    /// Execute a closure under the impersonated security context of this token.
    ///
    /// Reverts impersonation back to the original identity automatically when the closure returns or drops.
    pub(crate) fn with_impersonation<F, R>(&self, f: F) -> Result<R, ElevateError>
    where
        F: FnOnce() -> Result<R, ElevateError>,
    {
        let _guard = self.impersonate()?;
        f()
    }

    pub(crate) fn impersonate(&self) -> Result<ImpersonationGuard, ElevateError> {
        win32!(ImpersonateLoggedOnUser(self.0))?;
        Ok(ImpersonationGuard {
            _marker: PhantomData,
        })
    }

    /// Query the user account SID string (`TokenUser`) associated with this token.
    pub(crate) fn user_sid(&self) -> Result<String, ElevateError> {
        let buf = self.query_info_buffer(TokenUser)?;
        let user: &TOKEN_USER = Self::cast_buffer(&buf);
        Sid::string_from_raw(user.User.Sid)
    }

    /// Check whether this token holds membership in the specified string SID.
    pub fn has_sid(&self, sid: PCWSTR) -> Result<bool, ElevateError> {
        let sid = Sid::parse(sid)?;
        let buf = self.query_info_buffer(TokenGroups)?;

        let groups: &TOKEN_GROUPS = Self::cast_buffer(&buf);
        let count = groups.GroupCount as usize;
        if count == 0 {
            return Ok(false);
        }

        let groups_offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_ptr = unsafe {
            ptr::from_ref(groups)
                .byte_add(groups_offset)
                .cast::<SID_AND_ATTRIBUTES>()
        };
        let slice = unsafe { slice::from_raw_parts(groups_ptr, count) };

        for group in slice {
            if unsafe { Sid::equal(group.Sid, sid.as_raw()) }? {
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

    /// Helper to query variable-length token information with automatic size probing and alignment.
    fn query_info_buffer(
        &self,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, ElevateError> {
        let mut bytes_needed = 0u32;

        unsafe {
            SetLastError(WIN32_ERROR(0));
            let _ = GetTokenInformation(self.0, class, None, 0, &raw mut bytes_needed);
            let last_error = GetLastError();
            if last_error != ERROR_INSUFFICIENT_BUFFER {
                return Err(ElevateError::Win32 {
                    operation: "GetTokenInformation (probe size)",
                    source: windows::core::Error::from_win32(),
                });
            }
        }

        if bytes_needed == 0 {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        let count = (bytes_needed as usize).div_ceil(mem::size_of::<usize>());
        let mut buf: Vec<usize> = vec![0; count];

        win32!(GetTokenInformation(
            self.0,
            class,
            Some(buf.as_mut_ptr().cast()),
            bytes_needed,
            &raw mut bytes_needed
        ))?;

        Ok(buf)
    }

    /// Checks whether the user SID associated with this token matches a specific well-known SID type.
    ///
    /// This bypasses string serialization and memory allocation by directly evaluating
    /// the underlying binary `PSID` via the native Win32 `IsWellKnownSid` API.
    pub(crate) fn is_well_known_user(
        &self,
        sid_type: WELL_KNOWN_SID_TYPE,
    ) -> Result<bool, ElevateError> {
        let buf = self.query_info_buffer(TokenUser)?;
        let user: &TOKEN_USER = Self::cast_buffer(&buf);
        let sid = user.User.Sid;

        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(ElevateError::InvalidSid);
        }

        Ok(unsafe { IsWellKnownSid(sid, sid_type) }.as_bool())
    }

    /// Cast an aligned usize buffer reference into the target token information struct reference.
    #[inline]
    fn cast_buffer<T>(buf: &[usize]) -> &T {
        debug_assert!(
            mem::size_of_val(buf) >= mem::size_of::<T>(),
            "Buffer too small for requested struct cast"
        );

        unsafe { &*buf.as_ptr().cast::<T>() }
    }
}

/// RAII scope guard ensuring impersonation is safely reverted back to the original caller on drop.
pub(crate) struct ImpersonationGuard {
    _marker: PhantomData<*const ()>,
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
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

    // Ensure we can always open the security token of the currently running process.
    #[test]
    fn current_token_opens_successfully() {
        let current_token = Token::current();
        assert!(
            current_token.is_ok(),
            "Opening the current process token should always succeed"
        );
    }

    // Ensure we can read the Windows Session ID from the token (Session 0 for services, 1+ for desktop).
    #[test]
    fn current_token_session_id_is_valid() {
        let current_token = Token::current().unwrap();
        let session = current_token.session_id();
        assert!(session.is_ok(), "Reading session ID must not fail");
    }

    // Ensure the token owner SID is valid and starts with the standard Windows SID prefix "S-1-".
    #[test]
    fn current_token_user_sid_is_nonempty_and_valid() {
        let current_token = Token::current().unwrap();
        let sid = current_token.user_sid().unwrap();
        assert!(
            sid.starts_with("S-1-"),
            "User SID must be a valid SID string starting with S-1-, got: {sid}"
        );
    }

    // Ensure the boolean elevation flag strictly aligns with the Mandatory Integrity Level:
    // Elevated Admin must be High/System (>= 0x3000), standard user must be Medium or lower (< 0x3000).
    #[test]
    fn is_elevated_admin_matches_integrity_level() {
        let current_token = Token::current().unwrap();

        let is_admin = current_token.is_elevated_admin().unwrap();
        let integrity_level = current_token.integrity_level().unwrap();

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

    // Normal developer processes and test runners should never be running with a restricted sandbox token.
    #[test]
    fn current_token_is_not_restricted() {
        let current_token = Token::current().unwrap();

        let is_restricted = current_token.is_restricted().unwrap();
        assert!(
            !is_restricted,
            "Current development/test process should not be a restricted token"
        );
    }

    // Ensure checking membership for a non-existent or fake SID safely returns false instead of failing.
    #[test]
    fn has_sid_with_bogus_sid_returns_false() {
        let current_token = Token::current().unwrap();
        let has = current_token
            .has_sid(w!("S-1-5-80-0-0-0-0-999999"))
            .unwrap();
        assert!(
            !has,
            "Token should not claim membership in a fake, non-existent SID"
        );
    }
}
