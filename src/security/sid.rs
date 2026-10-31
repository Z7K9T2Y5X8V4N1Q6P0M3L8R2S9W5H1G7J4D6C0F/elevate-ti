//! Strongly-typed Windows Security Identifier (SID) wrapper.

use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            GetLengthSid, IsValidSid, PSID,
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::{guard::LocalFreeGuard, win32};
use crate::error::ElevateError;

/// Safe RAII wrapper around a native Windows Security Identifier (SID).
pub(crate) struct Sid(PSID);

impl Drop for Sid {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.0.0));
            }
        }
    }
}

impl Sid {
    /// Parse a security identifier from a wide string format (e.g. `S-1-5-18`).
    pub(crate) fn parse(sid: PCWSTR) -> Result<Self, ElevateError> {
        let mut psid = PSID::default();
        win32!(ConvertStringSidToSidW(sid, &raw mut psid))?;
        Ok(Self(psid))
    }

    /// Access the underlying raw `PSID`.
    pub(crate) const fn as_raw(&self) -> PSID {
        self.0
    }

    /// Check if two raw binary `PSID` handles represent the identical security principal.
    ///
    /// # Safety
    ///
    /// Both `lhs` and `rhs` must point to valid, readable memory representing SID structures,
    /// and must remain valid and unmodified for the duration of this call (no concurrent writes).
    ///
    /// Note: Passing arbitrary invalid or dangling pointers will cause undefined behavior
    /// (access violation), as [`IsValidSid`] cannot protect against unmapped memory.
    ///
    /// # Errors
    ///
    /// Returns [`ElevateError::InvalidSid`] if either pointer is null or fails
    /// structural validation via [`IsValidSid`].
    pub(crate) unsafe fn equal(lhs: PSID, rhs: PSID) -> Result<bool, ElevateError> {
        if lhs.0.is_null() || rhs.0.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        // Structural integrity validation: ensures SID revision and sub-authority counts are sane.
        if !unsafe { IsValidSid(lhs) }.as_bool() || !unsafe { IsValidSid(rhs) }.as_bool() {
            return Err(ElevateError::InvalidSid);
        }

        let len_lhs = unsafe { GetLengthSid(lhs) };
        let len_rhs = unsafe { GetLengthSid(rhs) };

        if len_lhs != len_rhs {
            return Ok(false);
        }

        // Binary comparison: valid SIDs of identical length are identical iff their raw bytes match.
        // This avoids legacy Win32 GetLastError ambiguity inherent to EqualSid.
        let bytes_lhs = unsafe { std::slice::from_raw_parts(lhs.0.cast::<u8>(), len_lhs as usize) };
        let bytes_rhs = unsafe { std::slice::from_raw_parts(rhs.0.cast::<u8>(), len_rhs as usize) };

        Ok(bytes_lhs == bytes_rhs)
    }

    /// Convert a raw `PSID` into its standard textual format string.
    pub(crate) fn string_from_raw(psid: PSID) -> Result<String, ElevateError> {
        let mut pwstr = PWSTR::null();
        win32!(ConvertSidToStringSidW(psid, &raw mut pwstr))?;

        // Immediately wrap the returned buffer into an RAII guard to guarantee deallocation
        // even if UTF-16 conversion fails or panics occur.
        let _guard = LocalFreeGuard(HLOCAL(pwstr.0.cast()));

        unsafe { pwstr.to_string() }.map_err(|_| ElevateError::InvalidTokenBuffer)
    }
}
