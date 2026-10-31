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
            Environment::{CreateEnvironmentBlock, ExpandEnvironmentStringsW},
            Threading::{
                CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW,
                PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::SW_SHOWNORMAL,
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::{
    guard::{EnvBlockGuard, HandleGuard},
    token::Token,
    win32,
};
use crate::{Elevator, error::ElevateError};

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
    pub fn custom(path: impl Into<String>) -> Self {
        Self::Custom(path.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Default => "WinSta0\\Default",
            Self::Winlogon => "WinSta0\\Winlogon",
            Self::Screensaver => "WinSta0\\Screen-Saver",
            Self::Custom(path) => path.as_str(),
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
    desktop: Option<HSTRING>,
}

impl Command {
    /// Create a new elevated command targeting the default interactive desktop (`WinSta0\Default`).
    pub fn new(program: impl AsRef<Path>) -> Result<Self, ElevateError> {
        Self::on_desktop(&InteractiveDesktop::Default, program)
    }

    /// Create an elevated command strictly for Session 0 headless background execution.
    pub fn headless(program: impl AsRef<Path>) -> Result<Self, ElevateError> {
        let elevator = Elevator::new(ExecutionContext::Headless);
        let token = elevator.acquire_primary_token()?;
        Ok(Self {
            token,
            program: Some(expand_env_path(program.as_ref())),
            args: None,
            desktop: None,
        })
    }

    /// Create an elevated command targeting a specific interactive desktop.
    pub fn on_desktop(
        desktop: &InteractiveDesktop,
        program: impl AsRef<Path>,
    ) -> Result<Self, ElevateError> {
        let elevator = Elevator::new(ExecutionContext::Interactive(desktop.clone()));
        let token = elevator.acquire_primary_token()?;
        let desktop = Some(HSTRING::from(desktop.as_str()));
        Ok(Self {
            token,
            program: Some(expand_env_path(program.as_ref())),
            args: None,
            desktop,
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

        let mut env_block: *mut c_void = ptr::null_mut();
        win32!(CreateEnvironmentBlock(
            &raw mut env_block,
            self.token.as_raw(),
            false
        ))?;
        let _guard = EnvBlockGuard(env_block);

        let cwd = env::current_dir()?;
        let cwd = HSTRING::from(cwd.as_os_str());

        let desktop = match &self.desktop {
            Some(desktop) => PWSTR(desktop.as_ptr().cast_mut()),
            None => PWSTR::null(),
        };

        let startup_info = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: desktop,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();

        let program = self
            .program
            .as_ref()
            .map(|path| HSTRING::from(path.as_os_str()));
        let program_path = match &program {
            Some(program_path) => PCWSTR(program_path.as_ptr()),
            None => PCWSTR::null(),
        };

        let spawn_result = win32!(CreateProcessWithTokenW(
            self.token.as_raw(),
            CREATE_PROCESS_LOGON_FLAGS(0),
            program_path,
            PWSTR(cmd_line.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            Some(env_block),
            &cwd,
            &raw const startup_info,
            &raw mut process_info,
        ));

        let _process_guard = HandleGuard(process_info.hProcess);
        let _thread_guard = HandleGuard(process_info.hThread);

        spawn_result?;
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

#[cfg(test)]
mod tests {
    use super::*;

    // Verify each desktop variant outputs the exact station/desktop string required by Windows.
    #[test]
    fn interactive_desktop_as_str_maps_to_expected_paths() {
        let cases = [
            (InteractiveDesktop::Default, "WinSta0\\Default"),
            (InteractiveDesktop::Winlogon, "WinSta0\\Winlogon"),
            (InteractiveDesktop::Screensaver, "WinSta0\\Screen-Saver"),
            (
                InteractiveDesktop::custom("CustomStation\\CustomDesktop"),
                "CustomStation\\CustomDesktop",
            ),
            (InteractiveDesktop::custom(""), ""), // Ensure empty path is safely handled without panic
        ];

        for (desktop, expected) in cases {
            assert_eq!(desktop.as_str(), expected);
        }
    }

    // Ensure new commands target the interactive user desktop by default so the window is visible.
    #[test]
    fn execution_context_default_is_interactive_desktop() {
        assert_eq!(
            ExecutionContext::default(),
            ExecutionContext::Interactive(InteractiveDesktop::Default)
        );
    }

    // Ensure regular file paths without environment variables are returned completely unchanged.
    #[test]
    fn expand_env_path_without_vars_returns_unchanged_path() {
        let test_cases = [
            "C:\\Windows\\System32\\cmd.exe",
            "relative\\path\\to\\file.txt",
            "plain_filename.exe",
        ];

        for path in test_cases {
            let input = Path::new(path);
            assert_eq!(
                expand_env_path(input),
                input,
                "Regular path got unexpectedly changed: {path}"
            );
        }
    }

    // Ensure environment variables like %SystemRoot% are properly expanded to real disk paths.
    #[test]
    fn expand_env_path_with_systemroot_expands_variable() {
        let input = Path::new("%SystemRoot%\\System32\\cmd.exe");
        let result = expand_env_path(input);
        let result_str = result.to_string_lossy();

        assert!(
            !result_str.contains('%'),
            "Environment variable wasn't expanded, '%' is still there: {result_str}"
        );
        assert!(
            result_str.to_lowercase().ends_with("\\system32\\cmd.exe"),
            "Expected path to end with '\\System32\\cmd.exe', but got: {result_str}"
        );
    }
}
