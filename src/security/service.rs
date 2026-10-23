//! Windows Service Control Manager connection and service polling.

use std::{
    mem, slice,
    thread::sleep,
    time::{Duration, Instant},
};

use windows::{
    Win32::{
        Foundation::ERROR_SERVICE_ALREADY_RUNNING,
        System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
            SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
            SERVICE_STOPPED, StartServiceW,
        },
    },
    core::PCWSTR,
};

use super::win32;
use crate::error::ElevateError;

/// Number of status queries tolerated where the state remains `SERVICE_STOPPED`
/// immediately after `try_start()` returns successfully.
const STOPPED_GRACE_TICKS: u32 = 3;

/// Safe RAII wrapper for Service Control Manager connection.
pub struct ServiceManager(SC_HANDLE);

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

impl ServiceManager {
    /// Open a connection to the local Service Control Manager.
    pub fn open() -> Result<Self, ElevateError> {
        let handle = win32!(OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT
        ))?;
        Ok(Self(handle))
    }

    /// Open an individual service with query and start rights.
    pub fn service(&self, name: PCWSTR) -> Result<Service, ElevateError> {
        let handle = win32!(OpenServiceW(
            self.0,
            name,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
        ))?;
        Ok(Service(handle))
    }
}

/// Safe RAII handle for an individual Windows service.
pub struct Service(SC_HANDLE);

impl Drop for Service {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

impl Service {
    /// Ensure the service is running and wait until it enters `SERVICE_RUNNING`, returning its PID.
    pub fn start_and_wait(&self, name: &str, timeout: Duration) -> Result<u32, ElevateError> {
        let mut deadline = Instant::now() + timeout;
        let mut start_attempted = false;
        let mut stopped_grace = 0u32;
        let mut last_checkpoint = 0u32;

        loop {
            if Instant::now() > deadline {
                return Err(ElevateError::ServiceTimeout {
                    name: name.to_string(),
                    seconds: timeout.as_secs(),
                });
            }

            let mut status = SERVICE_STATUS_PROCESS::default();
            let mut bytes_needed = 0u32;

            // SAFETY: SERVICE_STATUS_PROCESS is a plain-old-data (POD) struct composed entirely of DWORDs.
            // Any byte pattern is valid, and casting it to a contiguous mutable byte slice covering its
            // exact memory size is sound for the Windows API to populate.
            let status_bytes = unsafe {
                slice::from_raw_parts_mut(
                    (&raw mut status).cast(),
                    mem::size_of::<SERVICE_STATUS_PROCESS>(),
                )
            };

            win32!(QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                Some(status_bytes),
                &raw mut bytes_needed,
            ))?;

            match status.dwCurrentState {
                SERVICE_RUNNING => return Ok(status.dwProcessId),
                SERVICE_STOPPED => {
                    if !start_attempted {
                        self.try_start()?;
                        start_attempted = true;
                        // Allow brief grace period for SCM to transition out of stopped state.
                        stopped_grace = STOPPED_GRACE_TICKS;
                    } else if stopped_grace > 0 {
                        // Consume grace ticks while waiting for SCM state synchronization.
                        stopped_grace -= 1;
                    } else {
                        // Service remains stopped after grace period expires; consider it failed.
                        return Err(ElevateError::ServiceFailed {
                            name: name.to_string(),
                        });
                    }
                }
                SERVICE_START_PENDING => {
                    // SCM acknowledged startup; clear stopped grace counter.
                    stopped_grace = 0;

                    // If checkpoint advances, the service is actively initializing; extend deadline.
                    if status.dwCheckPoint > 0 && status.dwCheckPoint > last_checkpoint {
                        last_checkpoint = status.dwCheckPoint;
                        deadline = Instant::now() + timeout;
                    }
                }
                // Intermediate states (e.g., STOP_PENDING): keep polling until timeout expires.
                _ => {}
            }

            // Derive poll interval from wait hint per MSDN guidelines, clamped to reasonable bounds.
            let wait_ms = (status.dwWaitHint / 10).clamp(1000, 3000);
            sleep(Duration::from_millis(wait_ms as u64));
        }
    }

    fn try_start(&self) -> Result<(), ElevateError> {
        let res = win32!(StartServiceW(self.0, None));
        match res {
            Ok(()) => Ok(()),
            Err(ElevateError::Win32 { ref source, .. })
                if source.code() == ERROR_SERVICE_ALREADY_RUNNING.to_hresult() =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
