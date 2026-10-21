//! Strongly-typed Windows Security Identifier (SID) wrapper.

use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            EqualSid, PSID,
        },
    },
    core::{PCWSTR, PWSTR},
};

use super::win32;
use crate::error::ElevateError;

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
    pub fn equal(a: PSID, b: PSID) -> bool {
        unsafe { EqualSid(a, b).is_ok() }
    }

    /// Convert a raw `PSID` into its standard textual format string.
    pub fn string_from_raw(psid: PSID) -> Result<String, ElevateError> {
        let mut pwstr = PWSTR::null();
        win32!(ConvertSidToStringSidW(psid, &raw mut pwstr))?;

        let res = unsafe { pwstr.to_string() }.map_err(|_| ElevateError::InvalidTokenBuffer);
        unsafe {
            let _ = LocalFree(HLOCAL(pwstr.0.cast()));
        }
        res
    }
}
