//! Idiomatic, safe Win32 security primitives.

pub mod command;
pub(crate) mod privilege;
pub(crate) mod service;
pub(crate) mod sid;
pub(crate) mod snapshot;
pub(crate) mod token;

use std::ffi::c_void;

pub use command::{Command, ExecutionContext, InteractiveDesktop};
pub use service::{Service, ServiceManager};
pub use snapshot::ProcessSnapshot;
pub use token::Token;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree},
    System::{Environment::DestroyEnvironmentBlock, RemoteDesktop::WTSFreeMemory},
};

/// Internal RAII guard ensuring any raw Win32 [`HANDLE`] is safely closed on drop.
#[repr(transparent)]
pub(crate) struct HandleGuard(pub(crate) HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII guard ensuring any buffer allocated by Terminal Services (WTS) is safely freed via [`WTSFreeMemory`].
pub(crate) struct WtsMemoryGuard(pub(crate) *mut c_void);
impl Drop for WtsMemoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                WTSFreeMemory(self.0);
            }
        }
    }
}

/// RAII guard ensuring any user environment block is safely destroyed via [`DestroyEnvironmentBlock`].
pub(crate) struct EnvBlockGuard(pub(crate) *mut c_void);
impl Drop for EnvBlockGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

/// RAII guard ensuring any buffer allocated by Win32 APIs returning `HLOCAL` is safely freed via [`LocalFree`].
pub(crate) struct LocalFreeGuard(pub(crate) HLOCAL);
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

/// Internal helper macro to eliminate repetitive Win32 result mapping boilerplate.
macro_rules! win32 {
    ($func:ident ( $($arg:tt)* )) => {
        unsafe { $func($($arg)*) }.map_err(|source| $crate::error::ElevateError::Win32 {
            operation: stringify!($func),
            source,
        })
    };
}
pub(crate) use win32;
