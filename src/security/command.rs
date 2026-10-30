//! Command-style process launcher with bound security tokens.

use std::{
    env,
    ffi::{OsString, c_void},
    mem,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
    time::Duration,
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
use crate::{
    error::ElevateError,
    strategy::{ElevationStrategy, TrustedInstallerStrategy},
};

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
    /// A custom Window Station and Desktop object path (e.g. `CustomStation\\CustomDesktop`).
    Custom(String),
}

impl InteractiveDesktop {
    /// Create a custom window station and desktop target path (e.g. `CustomStation\\CustomDesktop`).
    pub fn custom(station_and_desktop: impl Into<String>) -> Self {
        Self::Custom(station_and_desktop.into())
    }

    pub(crate) fn as_str(&self) -> &str {
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

/// A process builder for executing commands with `TrustedInstaller` privileges.
#[must_use = "commands do nothing unless spawned"]
pub struct Command {
    token: Token,
    program: Option<PathBuf>,
    args: Option<String>,
    desktop_str: Option<HSTRING>,
}

impl Command {
    /// Create a new elevated command targeting the default interactive desktop (`WinSta0\Default`).
    pub fn new(program: impl AsRef<Path>) -> Result<Self, ElevateError> {
        Self::on_desktop(&InteractiveDesktop::Default, program)
    }

    /// Create an elevated command strictly for Session 0 headless background execution.
    pub fn headless(program: impl AsRef<Path>) -> Result<Self, ElevateError> {
        let strategy =
            TrustedInstallerStrategy::new(Duration::from_secs(30), ExecutionContext::Headless);
        let token = strategy.acquire_primary_token()?;
        Ok(Self {
            token,
            program: Some(expand_env_path(program.as_ref())),
            args: None,
            desktop_str: None,
        })
    }

    /// Create an elevated command targeting a specific interactive desktop.
    pub fn on_desktop(
        desktop: &InteractiveDesktop,
        program: impl AsRef<Path>,
    ) -> Result<Self, ElevateError> {
        let strategy = TrustedInstallerStrategy::new(
            Duration::from_secs(30),
            ExecutionContext::Interactive(desktop.clone()),
        );
        let token = strategy.acquire_primary_token()?;
        let desktop_str = Some(HSTRING::from(desktop.as_str()));
        Ok(Self {
            token,
            program: Some(expand_env_path(program.as_ref())),
            args: None,
            desktop_str,
        })
    }

    /// Relaunch the current running binary with `TrustedInstaller` privileges.
    pub fn relaunch() -> Result<(), ElevateError> {
        let current = env::current_exe()?;
        Self::new(current)?.spawn()
    }

    /// Pass a raw command-line string to the process.
    ///
    /// This string is passed directly as the `lpCommandLine` parameter to Windows `CreateProcess`.
    /// If not specified, the command line defaults to the executable path itself.
    pub fn args(mut self, args: impl Into<String>) -> Self {
        self.args = Some(args.into());
        self
    }

    /// Spawn the elevated process.
    pub fn spawn(self) -> Result<(), ElevateError> {
        let cmd_line = match (&self.program, &self.args) {
            (_program, Some(args)) => args.clone(),
            (Some(program), None) => format!("\"{}\"", program.display()),
            (None, None) => return Err(ElevateError::MissingExePath),
        };
        let mut cmd_line: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

        let mut raw_env_block: *mut c_void = ptr::null_mut();
        win32!(CreateEnvironmentBlock(
            &raw mut raw_env_block,
            self.token.as_raw(),
            false
        ))?;
        let _env_guard = EnvBlockGuard(raw_env_block);

        let cwd = env::current_dir()?;
        let cwd = HSTRING::from(cwd.as_os_str());

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

        let program = self.program.as_ref().map(|p| HSTRING::from(p.as_os_str()));
        let app_name = match &program {
            Some(h) => PCWSTR(h.as_ptr()),
            None => PCWSTR::null(),
        };

        let spawn_result = win32!(CreateProcessWithTokenW(
            self.token.as_raw(),
            CREATE_PROCESS_LOGON_FLAGS(0),
            app_name,
            PWSTR(cmd_line.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            Some(raw_env_block),
            &cwd,
            &raw const si,
            &raw mut pi,
        ));

        let _process_guard = HandleGuard(pi.hProcess);
        let _thread_guard = HandleGuard(pi.hThread);

        spawn_result?;
        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_default_station_str() {
        assert_eq!(InteractiveDesktop::Default.as_str(), "WinSta0\\Default");
    }

    #[test]
    fn desktop_winlogon_station_str() {
        assert_eq!(InteractiveDesktop::Winlogon.as_str(), "WinSta0\\Winlogon");
    }

    #[test]
    fn desktop_screensaver_station_str() {
        assert_eq!(
            InteractiveDesktop::Screensaver.as_str(),
            "WinSta0\\Screen-Saver"
        );
    }

    #[test]
    fn desktop_custom_station_str() {
        assert_eq!(
            InteractiveDesktop::custom("CustomStation\\CustomDesktop").as_str(),
            "CustomStation\\CustomDesktop"
        );
    }

    #[test]
    fn desktop_custom_empty_string() {
        assert_eq!(InteractiveDesktop::custom("").as_str(), "");
    }

    #[test]
    fn execution_context_default_is_interactive_default() {
        assert_eq!(
            ExecutionContext::default(),
            ExecutionContext::Interactive(InteractiveDesktop::Default)
        );
    }

    #[test]
    fn expand_env_path_without_variables_returns_unchanged() {
        let cases = [
            "C:\\Windows\\System32\\cmd.exe",
            "relative\\path\\to\\file.txt",
            "plain_filename.exe",
        ];

        for case in cases {
            let input = Path::new(case);
            assert_eq!(expand_env_path(input), input, "Failed on: {case}");
        }
    }

    #[test]
    fn expand_env_path_with_systemroot() {
        let input = Path::new("%SystemRoot%\\System32\\cmd.exe");
        let result = expand_env_path(input);
        let result_str = result.to_string_lossy();
        assert!(
            !result_str.contains('%'),
            "Environment variable should have been expanded, got: {result_str}"
        );
        assert!(
            result_str.ends_with("\\System32\\cmd.exe"),
            "Suffix must be preserved, got: {result_str}"
        );
    }
}
