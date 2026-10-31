use std::ffi::c_void;

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
