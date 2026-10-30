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

use super::win32;
use crate::error::ElevateError;

/// RAII guard ensuring any buffer allocated by Win32 APIs returning `HLOCAL` is safely freed.
struct LocalFreeGuard(HLOCAL);

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

/// Safe RAII wrapper around a native Windows Security Identifier (SID).
pub struct Sid(PSID);

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
    pub fn parse(s: PCWSTR) -> Result<Self, ElevateError> {
        let mut psid = PSID::default();
        win32!(ConvertStringSidToSidW(s, &raw mut psid))?;
        Ok(Self(psid))
    }

    /// Access the underlying raw `PSID`.
    pub const fn as_raw(&self) -> PSID {
        self.0
    }

    /// Check if two raw binary `PSID` handles represent the identical security principal.
    ///
    /// # Safety
    ///
    /// Both `a` and `b` must point to valid, readable memory representing SID structures,
    /// and must remain valid and unmodified for the duration of this call (no concurrent writes).
    ///
    /// Note: Passing arbitrary invalid or dangling pointers will cause undefined behavior
    /// (access violation), as [`IsValidSid`] cannot protect against unmapped memory.
    ///
    /// # Errors
    ///
    /// Returns [`ElevateError::InvalidTokenBuffer`] if either pointer is null or fails
    /// structural validation via [`IsValidSid`].
    pub unsafe fn equal(a: PSID, b: PSID) -> Result<bool, ElevateError> {
        if a.0.is_null() || b.0.is_null() {
            return Err(ElevateError::InvalidSid);
        }

        // Structural integrity validation: ensures SID revision and sub-authority counts are sane.
        if !unsafe { IsValidSid(a) }.as_bool() || !unsafe { IsValidSid(b) }.as_bool() {
            return Err(ElevateError::InvalidSid);
        }

        let len_a = unsafe { GetLengthSid(a) };
        let len_b = unsafe { GetLengthSid(b) };

        if len_a != len_b {
            return Ok(false);
        }

        // Binary comparison: valid SIDs of identical length are identical iff their raw bytes match.
        // This avoids legacy Win32 GetLastError ambiguity inherent to EqualSid.
        let a = unsafe { std::slice::from_raw_parts(a.0.cast::<u8>(), len_a as usize) };
        let b = unsafe { std::slice::from_raw_parts(b.0.cast::<u8>(), len_b as usize) };

        Ok(a == b)
    }

    /// Convert a raw `PSID` into its standard textual format string.
    pub fn string_from_raw(psid: PSID) -> Result<String, ElevateError> {
        let mut pwstr = PWSTR::null();
        win32!(ConvertSidToStringSidW(psid, &raw mut pwstr))?;

        // Immediately wrap the returned buffer into an RAII guard to guarantee deallocation
        // even if UTF-16 conversion fails or panics occur.
        let _guard = LocalFreeGuard(HLOCAL(pwstr.0.cast()));

        unsafe { pwstr.to_string() }.map_err(|_| ElevateError::InvalidTokenBuffer)
    }
}
