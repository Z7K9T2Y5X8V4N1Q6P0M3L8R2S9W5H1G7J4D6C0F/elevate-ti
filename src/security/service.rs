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

/// Maximum duration tolerated for SCM to remain in `SERVICE_STOPPED`
/// immediately after `try_start()` returns successfully.
const STOPPED_GRACE: Duration = Duration::from_millis(1500);

/// Polling interval during the initial startup grace period.
const GRACE_POLL: Duration = Duration::from_millis(250);

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

        let service_name =
            unsafe { name.to_string() }.map_err(|_| ElevateError::InvalidTokenBuffer)?;

        Ok(Service {
            handle,
            name: service_name,
        })
    }
}

/// Safe RAII handle for an individual Windows service.
pub struct Service {
    handle: SC_HANDLE,
    name: String,
}

impl Drop for Service {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

impl Service {
    /// Ensure the service is running and wait until it enters `SERVICE_RUNNING`, returning its PID.
    pub fn start_and_wait(&self, timeout: Duration) -> Result<u32, ElevateError> {
        let mut deadline = Instant::now() + timeout;
        let mut start_attempted = false;
        let mut stopped_since: Option<Instant> = None;
        let mut last_checkpoint = 0u32;

        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(ElevateError::ServiceTimeout {
                    name: self.name.clone(),
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
                self.handle,
                SC_STATUS_PROCESS_INFO,
                Some(status_bytes),
                &raw mut bytes_needed,
            ))?;

            match status.dwCurrentState {
                SERVICE_RUNNING => return Ok(status.dwProcessId),
                SERVICE_STOPPED => match stopped_since {
                    // Initial stopped state: trigger start and mark the beginning of the grace period.
                    None if !start_attempted => {
                        self.try_start()?;
                        start_attempted = true;
                        stopped_since = Some(Instant::now());
                    }
                    // Within grace period: SCM may still be transitioning state. Keep checking.
                    Some(start_time) if start_time.elapsed() < STOPPED_GRACE => {}
                    // Grace period expired or service stopped again after transitioning: failure confirmed.
                    _ => {
                        return Err(ElevateError::ServiceFailed {
                            name: self.name.clone(),
                            exit_code: status.dwWin32ExitCode,
                            service_exit_code: status.dwServiceSpecificExitCode,
                        });
                    }
                },
                SERVICE_START_PENDING => {
                    // SCM acknowledged startup; clear the stopped grace tracking.
                    stopped_since = None;

                    // If checkpoint advances, the service is actively initializing; extend deadline.
                    if status.dwCheckPoint > 0 && status.dwCheckPoint > last_checkpoint {
                        last_checkpoint = status.dwCheckPoint;
                        deadline = Instant::now() + timeout;
                    }
                }

                // Intermediate states (e.g., STOP_PENDING): keep polling until timeout expires.
                _ => {}
            }

            // Polling interval:
            // - During SCM state transition grace period: fast 250ms polling for prompt response.
            // - During normal pending/running transition: MSDN-guided wait hint (1~3s).
            let target_interval = if stopped_since.is_some() {
                GRACE_POLL
            } else {
                Duration::from_millis((status.dwWaitHint / 10).clamp(1000, 3000) as u64)
            };

            // Ensure sleep interval never overshoots the overall deadline.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            sleep(target_interval.min(remaining));
        }
    }

    fn try_start(&self) -> Result<(), ElevateError> {
        let result = win32!(StartServiceW(self.handle, None));
        match result {
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
