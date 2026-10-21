//! End-to-end integration tests for elevate-ti privilege acquisition.

use std::time::Duration;

use elevate_ti::{
    ElevationStatus, ElevationStrategy, ExecutionContext, Privilege, Token,
    TrustedInstallerStrategy, headless_command, status,
};
use windows::core::w;

const TRUSTED_INSTALLER_SID: windows::core::PCWSTR =
    w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

fn assert_elevated_context() {
    let current_token = Token::current().expect("Failed to open current process security token");

    current_token.enable_privileges(&[Privilege::Debug]).expect(
        "Test execution requires an elevated Administrator context with SeDebugPrivilege enabled. \
         Please run 'cargo test' from an Administrator PowerShell/CMD prompt.",
    );
}

#[test]
fn test_status_query_does_not_panic() {
    let result = status();
    assert!(result.is_ok(), "Querying elevation status must not fail");
    let current_status = result.unwrap();
    assert!(
        matches!(
            current_status,
            ElevationStatus::RequiresElevation | ElevationStatus::Elevated
        ),
        "Status must return a valid elevation state variant"
    );
}

#[test]
fn test_acquire_primary_token_session_zero() {
    assert_elevated_context();

    let strategy =
        TrustedInstallerStrategy::new(Duration::from_secs(30), ExecutionContext::Headless);
    let token = strategy
        .acquire_primary_token()
        .expect("Must acquire TrustedInstaller token in Session 0");

    assert!(
        token
            .has_sid(TRUSTED_INSTALLER_SID)
            .expect("Must query SID membership"),
        "Acquired token must possess genuine TrustedInstaller SID"
    );

    let session_id = token.session_id().expect("Must read session ID");
    assert_eq!(
        session_id, 0,
        "Headless execution context must strictly bind to Session 0"
    );
}

#[test]
fn test_acquire_primary_token_caller_session() {
    assert_elevated_context();

    let strategy = TrustedInstallerStrategy::default();
    match strategy.acquire_primary_token() {
        Ok(token) => {
            assert!(
                token
                    .has_sid(TRUSTED_INSTALLER_SID)
                    .expect("Must query SID membership"),
                "Acquired token must possess genuine TrustedInstaller SID"
            );

            let caller_session = Token::current().unwrap().session_id().unwrap();
            assert_eq!(
                token.session_id().unwrap(),
                caller_session,
                "Token must match the caller's active interactive session ID"
            );
        }
        Err(elevate_ti::ElevateError::SessionZeroNotSupported) => {
            eprintln!("[INFO] Running inside Session 0 (CI runner/headless); fast-fail verified.");
        }
        Err(e) => panic!("Unexpected failure acquiring token for caller session: {e}"),
    }
}

#[test]
fn test_spawn_headless_child_execution() {
    assert_elevated_context();

    let cmd = headless_command()
        .expect("Must create headless command")
        .exe("%SystemRoot%\\System32\\cmd.exe")
        .args("cmd.exe /c exit 0");

    assert!(
        cmd.spawn().is_ok(),
        "Must spawn process in headless mode without DACL or environment block failure"
    );
}
