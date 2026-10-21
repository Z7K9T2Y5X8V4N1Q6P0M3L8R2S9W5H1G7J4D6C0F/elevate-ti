//! Command-style process launcher with bound security tokens.

use std::{
    env,
    ffi::{OsString, c_void},
    mem,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};

use windows::{
    Win32::{
        System::{
            Environment::{
                CreateEnvironmentBlock, DestroyEnvironmentBlock, ExpandEnvironmentStringsW,
            },
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

/// Target interactive desktop window station.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum InteractiveDesktop {
    /// The standard interactive user desktop (`WinSta0\Default`).
    #[default]
    Default,

    /// The secure desktop (`WinSta0\Winlogon`), active during UAC prompts and lock screens.
    Winlogon,

    /// The screensaver desktop (`WinSta0\Screen-Saver`).
    Screensaver,

    /// A custom Window Station and Desktop object path (e.g. "`MyStation\\MyDesktop`").
    Custom(String),
}

impl InteractiveDesktop {
    /// Create a custom window station and desktop target path.
    pub fn custom(station_and_desktop: impl Into<String>) -> Self {
        Self::Custom(station_and_desktop.into())
    }

    pub(crate) fn as_station_str(&self) -> &str {
        match self {
            Self::Default => "WinSta0\\Default",
            Self::Winlogon => "WinSta0\\Winlogon",
            Self::Screensaver => "WinSta0\\Screen-Saver",
            Self::Custom(station) => station.as_str(),
        }
    }
}

/// Process host environment context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionContext {
    /// Run interactively attached to a specific desktop.
    Interactive(InteractiveDesktop),

    /// Run as a headless Session 0 process with no window station or desktop attached.
    Headless,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::Interactive(InteractiveDesktop::default())
    }
}

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
pub struct TokenCommand {
    token: Token,
    exe: Option<PathBuf>,
    args: Option<String>,
    desktop_str: Option<HSTRING>,
}

impl TokenCommand {
    /// Create a new command builder bound to an elevated token and its target desktop context.
    pub fn new(token: Token, desktop: Option<InteractiveDesktop>) -> Self {
        let desktop_str = desktop.map(|d| HSTRING::from(d.as_station_str()));
        Self {
            token,
            exe: None,
            args: None,
            desktop_str,
        }
    }

    /// Set the target executable to the path of the current binary.
    pub fn current_exe(mut self) -> Result<Self, ElevateError> {
        self.exe = Some(env::current_exe()?);
        Ok(self)
    }

    /// Set a custom target executable path. Supports environment variables like `%SystemRoot%`.
    pub fn exe(mut self, path: impl AsRef<Path>) -> Self {
        self.exe = Some(expand_env_path(path.as_ref()));
        self
    }

    /// Pass a raw command-line string to the process.
    pub fn args(mut self, args: impl Into<String>) -> Self {
        self.args = Some(args.into());
        self
    }

    /// Spawn the process under the configured token context.
    pub fn spawn(self) -> Result<(), ElevateError> {
        let exe_hstr = self.exe.as_ref().map(|p| HSTRING::from(p.as_os_str()));

        let cmd = match (&self.args, &self.exe) {
            (Some(args), _) => args.clone(),
            (None, Some(exe)) => format!("\"{}\"", exe.display()),
            (None, None) => return Err(ElevateError::MissingExePath),
        };

        let mut cmd_utf16: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        let mut raw_env_block: *mut c_void = ptr::null_mut();
        win32!(CreateEnvironmentBlock(
            &raw mut raw_env_block,
            self.token.as_raw(),
            false
        ))?;
        let _env_guard = EnvBlockGuard(raw_env_block);

        let cwd = env::current_dir()?;
        let cwd_hstr = HSTRING::from(cwd.as_os_str());

        let lp_desktop = match &self.desktop_str {
            Some(d) => PWSTR(d.as_ptr().cast_mut()),
            None => PWSTR::null(),
        };

        let si = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: lp_desktop,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let app_name = match &exe_hstr {
            Some(h) => PCWSTR(h.as_ptr()),
            None => PCWSTR::null(),
        };

        let spawn_res = win32!(CreateProcessWithTokenW(
            self.token.as_raw(),
            CREATE_PROCESS_LOGON_FLAGS(0),
            app_name,
            PWSTR(cmd_utf16.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            Some(raw_env_block),
            &cwd_hstr,
            &raw const si,
            &raw mut pi,
        ));

        let _process_guard = HandleGuard(pi.hProcess);
        let _thread_guard = HandleGuard(pi.hThread);

        spawn_res?;
        Ok(())
    }
}

fn expand_env_path(path: &Path) -> PathBuf {
    let input = HSTRING::from(path.as_os_str());

    let needed = unsafe { ExpandEnvironmentStringsW(&input, None) };
    if needed == 0 {
        return path.to_path_buf();
    }

    let mut buf: Vec<u16> = vec![0; needed as usize];
    let written = unsafe { ExpandEnvironmentStringsW(&input, Some(&mut buf)) };
    if written == 0 || written as usize > buf.len() {
        return path.to_path_buf();
    }

    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    PathBuf::from(OsString::from_wide(&buf[..len]))
}
