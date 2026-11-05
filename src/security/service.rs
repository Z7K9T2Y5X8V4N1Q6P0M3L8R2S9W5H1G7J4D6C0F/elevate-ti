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
    core::{HSTRING, PCWSTR},
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
    pub fn service(&self, name: &str) -> Result<Service, ElevateError> {
        let handle = win32!(OpenServiceW(
            self.0,
            PCWSTR(HSTRING::from(name).as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
        ))?;

        Ok(Service {
            handle,
            name: name.to_string(),
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
                    None if !start_attempted => {
                        self.try_start()?;
                        start_attempted = true;
                        stopped_since = Some(Instant::now());
                    }
                    Some(start_time) if start_time.elapsed() < STOPPED_GRACE => {}
                    _ => {
                        return Err(ElevateError::ServiceFailed {
                            name: self.name.clone(),
                            exit_code: status.dwWin32ExitCode,
                            service_exit_code: status.dwServiceSpecificExitCode,
                        });
                    }
                },
                SERVICE_START_PENDING => {
                    stopped_since = None;
                    // The service is making progress, so reset the wait hint.
                    // REF: https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service
                    if status.dwCheckPoint > 0 && status.dwCheckPoint > last_checkpoint {
                        last_checkpoint = status.dwCheckPoint;
                        deadline = Instant::now() + timeout;
                    }
                }

                _ => {}
            }

            let target_interval = if stopped_since.is_some() {
                GRACE_POLL
            } else {
                // "A good interval is one-tenth the wait hint, but no less than 1 second and no more than 10 seconds."
                // NOTE: Upper bound is capped at 3s instead of 10s for faster responsiveness.
                // REF: https://learn.microsoft.com/en-us/windows/win32/services/starting-a-service
                Duration::from_millis((status.dwWaitHint / 10).clamp(1000, 3000) as u64)
            };

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                continue;
            }
            sleep(target_interval.min(remaining));
        }
    }

    /// Send a start control request to the service, tolerating if it is already running.
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
