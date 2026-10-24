//! Process and thread security token manipulation.

use std::{marker::PhantomData, mem, ptr, slice};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID, SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, GetSidSubAuthority, GetSidSubAuthorityCount,
            GetTokenInformation, ImpersonateLoggedOnUser, IsTokenRestricted, LUID_AND_ATTRIBUTES,
            LookupPrivilegeValueW, RevertToSelf, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES,
            SecurityImpersonation, SetTokenInformation, TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_ALL_ACCESS, TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
            TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenElevation,
            TokenGroups, TokenImpersonation, TokenIntegrityLevel, TokenPrimary, TokenPrivileges,
            TokenSessionId, TokenUser,
        },
        System::{
            SystemServices::MAXIMUM_ALLOWED,
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            },
        },
    },
    core::PCWSTR,
};

use super::{HandleGuard, Sid, privilege::Privilege, win32};
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
    pub fn current() -> Result<Self, ElevateError> {
        let mut handle = HANDLE::default();
        win32!(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw mut handle
        ))?;
        Ok(Self(handle))
    }

    /// Open the security token belonging to an arbitrary running process by PID.
    pub fn from_pid(pid: u32) -> Result<Self, ElevateError> {
        let proc = HandleGuard(win32!(OpenProcess(PROCESS_QUERY_INFORMATION, false, pid))?);
        let mut token = HANDLE::default();
        win32!(OpenProcessToken(
            proc.0,
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
    pub fn duplicate(&self, token_type: TokenType) -> Result<Self, ElevateError> {
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
    pub fn enable_privileges(&self, privileges: &[Privilege]) -> Result<(), ElevateError> {
        for &privilege in privileges {
            let mut luid = LUID::default();
            win32!(LookupPrivilegeValueW(
                PCWSTR::null(),
                privilege.as_pcwstr(),
                &raw mut luid
            ))?;

            let privs = TOKEN_PRIVILEGES {
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
                Some(ptr::from_ref(&privs)),
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
    pub fn is_elevated_admin(&self) -> Result<bool, ElevateError> {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;

        win32!(GetTokenInformation(
            self.0,
            TokenElevation,
            Some(ptr::from_mut(&mut elevation).cast()),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &raw mut len
        ))?;

        Ok(elevation.TokenIsElevated != 0)
    }

    /// Check whether this token is a Restricted Token.
    pub fn is_restricted(&self) -> Result<bool, ElevateError> {
        Ok(unsafe { IsTokenRestricted(self.0) }.is_ok())
    }

    /// Query the Integrity Level RID of this token (e.g. 0x4000 = SYSTEM, 0x3000 = HIGH).
    pub fn integrity_level(&self) -> Result<u32, ElevateError> {
        let buf = self.query_info_buffer(TokenIntegrityLevel)?;
        let label = unsafe { &*buf.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };

        let count_ptr = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
        if count_ptr.is_null() {
            return Err(ElevateError::InvalidTokenBuffer);
        }
        let count = unsafe { *count_ptr };
        if count == 0 {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        let sub_auth_ptr = unsafe { GetSidSubAuthority(label.Label.Sid, count as u32 - 1) };
        if sub_auth_ptr.is_null() {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        Ok(unsafe { *sub_auth_ptr })
    }

    /// Check whether a specific privilege is present in this token's privilege table.
    pub fn has_privilege_present(&self, privilege: Privilege) -> Result<bool, ElevateError> {
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
    pub fn session_id(&self) -> Result<u32, ElevateError> {
        let mut session_id = 0u32;
        let mut len = 0u32;
        win32!(GetTokenInformation(
            self.0,
            TokenSessionId,
            Some(ptr::from_mut(&mut session_id).cast()),
            mem::size_of::<u32>() as u32,
            &raw mut len
        ))?;
        Ok(session_id)
    }

    /// Explicitly assign a Windows Session ID to this token.
    pub fn set_session_id(&self, session_id: u32) -> Result<(), ElevateError> {
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
    pub fn with_impersonation<F, R>(&self, f: F) -> Result<R, ElevateError>
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
    pub fn user_sid(&self) -> Result<String, ElevateError> {
        let buf = self.query_info_buffer(TokenUser)?;
        let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
        Sid::string_from_raw(user.User.Sid)
    }

    /// Check whether this token holds membership in the specified string SID.
    pub fn has_sid(&self, target_sid: PCWSTR) -> Result<bool, ElevateError> {
        let target = Sid::parse(target_sid)?;
        let buf = self.query_info_buffer(TokenGroups)?;
        let base = buf.as_ptr().cast::<TOKEN_GROUPS>();
        let count = unsafe { (*base).GroupCount as usize };
        if count == 0 {
            return Ok(false);
        }

        let groups_offset = mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_ptr = unsafe { base.byte_add(groups_offset).cast::<SID_AND_ATTRIBUTES>() };
        let slice = unsafe { slice::from_raw_parts(groups_ptr, count) };

        Ok(slice.iter().any(|g| Sid::equal(g.Sid, target.as_raw())))
    }

    /// Query raw token information into a pointer-aligned buffer.
    fn query_info_buffer(
        &self,
        class: TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, ElevateError> {
        let mut len = 0u32;
        let _ = unsafe { GetTokenInformation(self.0, class, None, 0, &raw mut len) };
        if len == 0 {
            return Err(ElevateError::InvalidTokenBuffer);
        }

        let count = (len as usize).div_ceil(mem::size_of::<usize>());
        let mut buf: Vec<usize> = vec![0; count];

        win32!(GetTokenInformation(
            self.0,
            class,
            Some(buf.as_mut_ptr().cast()),
            len,
            &raw mut len
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
    static_assertions::assert_not_impl_any!(ImpersonationGuard: Send, Sync);
}
