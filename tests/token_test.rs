//! End-to-end integration tests for elevate-ti privilege acquisition.

use std::{env, time::Duration};

use elevate_ti::{
    ElevationStatus, ElevationStrategy, Privilege, SessionTarget, Token, TokenCommand,
    TrustedInstallerStrategy, status,
};

const PROBE_ARG_HEADLESS: &str = "--ti-probe-headless";
const PROBE_ARG_INTERACTIVE: &str = "--ti-probe-interactive";

/// Shared fast-fail helper for tests requiring administrative privileges.
fn can_run_elevated_tests() -> bool {
    let Ok(current_token) = Token::current() else {
        return false;
    };
    current_token.enable_privileges(&[Privilege::Debug]).is_ok()
}

/// Scenario 1: Headless / Session 0 Context (Task Scheduler, Background Services, CI).
#[test]
fn test_trusted_installer_session_zero_headless() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == PROBE_ARG_HEADLESS) {
        let child_status = status().expect("Subprocess must query status");
        assert_eq!(
            child_status,
            ElevationStatus::Elevated,
            "Session 0 child must possess genuine TrustedInstaller privileges"
        );
        std::process::exit(0);
    }

    if !can_run_elevated_tests() {
        eprintln!("[SKIP] Non-Admin context. Skipping Session 0 test.");
        return;
    }

    // Explicitly testing NoSession (Session 0)
    let strategy = TrustedInstallerStrategy::new(Duration::from_secs(30), SessionTarget::NoSession);
    let ti_token = strategy
        .acquire_primary_token()
        .expect("Must acquire TrustedInstaller token in Session 0");

    let current_exe = env::current_exe().expect("Must locate current test binary");
    let cmd_line = format!("\"{}\" {}", current_exe.display(), PROBE_ARG_HEADLESS);

    TokenCommand::new(ti_token)
        .exe(&current_exe)
        .args(cmd_line)
        .spawn()
        .expect("Must successfully spawn child process in Session 0");
}

/// Scenario 2: Interactive Desktop Context (Caller Session / GUI / `WinSta0\\Default`).
#[test]
fn test_trusted_installer_interactive_session() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == PROBE_ARG_INTERACTIVE) {
        let child_status = status().expect("Subprocess must query status");
        assert_eq!(
            child_status,
            ElevationStatus::Elevated,
            "Interactive child must possess genuine TrustedInstaller privileges"
        );
        std::process::exit(0);
    }

    if !can_run_elevated_tests() {
        eprintln!("[SKIP] Non-Admin context. Skipping interactive session test.");
        return;
    }

    // Default strategy uses CallerSession (breaks through to current user desktop)
    let strategy = TrustedInstallerStrategy::default();
    let ti_token = match strategy.acquire_primary_token() {
        Ok(token) => token,
        Err(elevate_ti::ElevateError::SessionZeroNotSupported) => {
            eprintln!(
                "[SKIP] Running inside Session 0 (CI runner/headless); skipping interactive desktop test."
            );
            return;
        }
        Err(e) => panic!("Unexpected failure acquiring token for caller session: {e}"),
    };

    let current_exe = env::current_exe().expect("Must locate current test binary");
    let cmd_line = format!("\"{}\" {}", current_exe.display(), PROBE_ARG_INTERACTIVE);

    TokenCommand::new(ti_token)
        .exe(&current_exe)
        .args(cmd_line)
        .spawn()
        .expect("Must successfully spawn child process onto interactive desktop");
}
