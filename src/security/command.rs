//! Command-style process launcher with bound security tokens.

use std::{
    env,
    ffi::c_void,
    mem,
    path::{Path, PathBuf},
    ptr,
};

use windows::{
    Win32::{
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Threading::{
                CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW,
                PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::SW_SHOWNORMAL,
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::{HandleGuard, token::Token, win32};
use crate::error::ElevateError;

/// RAII guard for destroying the Win32 user environment block.
struct EnvBlockGuard(*mut c_void);

impl Drop for EnvBlockGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

/// Builder for launching processes under a specified primary security token.
#[must_use = "commands do nothing unless spawned"]
pub struct TokenCommand<'a> {
    token: &'a Token,
    exe: Option<PathBuf>,
    args: Option<String>,
    desktop: HSTRING,
}

impl<'a> TokenCommand<'a> {
    /// Create a new command builder bound to an elevated primary token.
    pub fn new(token: &'a Token) -> Self {
        Self {
            token,
            exe: None,
            args: None,
            desktop: HSTRING::from("WinSta0\\Default"),
        }
    }

    /// Set the target executable to the path of the current binary.
    pub fn current_exe(mut self) -> Result<Self, ElevateError> {
        self.exe = Some(env::current_exe()?);
        Ok(self)
    }

    /// Set a custom target executable path.
    pub fn exe(mut self, path: impl AsRef<Path>) -> Self {
        self.exe = Some(path.as_ref().to_path_buf());
        self
    }

    /// Pass a raw command-line string to the process.
    pub fn args(mut self, args: impl Into<String>) -> Self {
        self.args = Some(args.into());
        self
    }

    /// Set a custom desktop window station (defaults to `WinSta0\Default`).
    pub fn desktop(mut self, station: &str) -> Self {
        self.desktop = HSTRING::from(station);
        self
    }

    /// Spawn the process under the configured token context.
    pub fn spawn(self) -> Result<(), ElevateError> {
        let cmd = match (self.args, self.exe) {
            (Some(args), _) => args,
            (None, Some(exe)) => format!("\"{}\"", exe.display()),
            (None, None) => return Err(ElevateError::MissingExePath),
        };

        let mut cmd_utf16: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        // Generate a tailored environment block for this token.
        let mut raw_env_block: *mut c_void = ptr::null_mut();
        win32!(CreateEnvironmentBlock(
            &raw mut raw_env_block,
            self.token.as_raw(),
            false
        ))?;
        let _env_guard = EnvBlockGuard(raw_env_block);

        let cwd = env::current_dir()?;
        let cwd_hstr = HSTRING::from(cwd.as_os_str());

        let si = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(self.desktop.as_ptr().cast_mut()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let spawn_res = win32!(CreateProcessWithTokenW(
            self.token.as_raw(),
            CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR::null(),
            PWSTR(cmd_utf16.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            Some(raw_env_block),
            &cwd_hstr,
            &raw const si,
            &raw mut pi,
        ));

        // Immediately transfer process and thread handles to RAII guards regardless of spawn outcome.
        let _process_guard = HandleGuard(pi.hProcess);
        let _thread_guard = HandleGuard(pi.hThread);

        spawn_res?;
        Ok(())
    }
}
