//! Idiomatic, safe Win32 security primitives.

pub mod command;
pub mod privilege;
pub mod service;
pub mod sid;
pub mod snapshot;
pub mod token;

pub use command::TokenCommand;
pub use privilege::Privilege;
pub use service::{Service, ServiceManager};
pub use sid::Sid;
pub use snapshot::ProcessSnapshot;
pub use token::{ImpersonationGuard, Token, TokenType};

use windows::Win32::Foundation::{CloseHandle, HANDLE};

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
