//! End-to-end integration tests for elevate-ti privilege acquisition.
//!
//! Tests requiring Administrator elevation and interaction with the `TrustedInstaller`
//! service are marked `#[ignore = "..."]` so standard CI environments (e.g. GitHub Actions)
//! can pass without privilege errors. Run full elevated tests locally with:
//!
//! ```text
//! cargo test -- --ignored
//! ```

use std::time::Duration;

use elevate_ti::{
    ElevateError, ElevationStrategy, ExecutionContext, Privilege, Token, TrustedInstallerStrategy,
    headless_command, status,
};
use windows::core::w;

const TRUSTED_INSTALLER_SID: windows::core::PCWSTR =
    w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

fn assert_elevated_context() {
    let token = Token::current().expect("Failed to open current process security token");

    assert!(
        token.is_elevated_admin().unwrap_or(false),
        "Test execution requires an elevated Administrator context. \
         Please run from an Administrator prompt."
    );

    token.enable_privileges(&[Privilege::Debug]).expect(
        "Administrator context lacks SeDebugPrivilege! \
         Your system policy (secpol.msc) or EDR may have stripped this privilege.",
    );
}

// =======================================================================
// Non-elevated tests — safe to run in standard / CI environments
// =======================================================================

#[test]
fn test_status_query_does_not_panic() {
    let result = status();
    assert!(result.is_ok(), "Querying elevation status must not fail");
}

#[test]
fn test_current_token_opens_successfully() {
    let token = Token::current();
    assert!(
        token.is_ok(),
        "Opening the current process token should always succeed"
    );
}

#[test]
fn test_current_token_session_id_is_valid() {
    let token = Token::current().unwrap();
    let session = token.session_id();
    assert!(session.is_ok(), "Reading session ID must not fail");
}

#[test]
fn test_current_token_user_sid_is_nonempty() {
    let token = Token::current().unwrap();
    let sid = token.user_sid().unwrap();
    assert!(
        sid.starts_with("S-1-"),
        "User SID must be a valid SID string, got: {sid}"
    );
}

#[test]
fn test_is_elevated_admin_matches_integrity_level() {
    let token = Token::current().unwrap();

    let is_admin = token.is_elevated_admin().unwrap();
    let integrity_level = token.integrity_level().unwrap();

    if is_admin {
        assert!(
            integrity_level >= 0x3000,
            "Elevated admin must possess High/System integrity level (>= 0x3000), got: 0x{integrity_level:04X}"
        );
    } else {
        assert!(
            integrity_level < 0x3000,
            "Non-elevated user must possess Medium or lower integrity level (< 0x3000), got: 0x{integrity_level:04X}"
        );
    }
}

#[test]
fn test_current_token_is_not_restricted() {
    let token = Token::current().unwrap();

    let is_restricted = token.is_restricted().unwrap();
    assert!(
        !is_restricted,
        "Current development/test process should not be a restricted token"
    );
}

#[test]
fn test_has_sid_with_bogus_sid_returns_false() {
    let token = Token::current().unwrap();
    let has = token.has_sid(w!("S-1-5-80-0-0-0-0-999999")).unwrap();
    assert!(!has, "Token should not have a fabricated SID");
}

#[test]
fn test_core_privileges_presence_matches_admin_status() {
    let token = Token::current().unwrap();
    let is_admin = token.is_elevated_admin().unwrap();

    let has_debug = token.has_privilege_present(Privilege::Debug).unwrap();
    let has_impersonate = token.has_privilege_present(Privilege::Impersonate).unwrap();

    if is_admin {
        assert!(
            has_debug,
            "Elevated administrator token must hold SeDebugPrivilege in its privilege table"
        );
        assert!(
            has_impersonate,
            "Elevated administrator token must hold SeImpersonatePrivilege in its privilege table"
        );
    }
}

// =======================================================================
// Elevated tests — require Administrator + SeDebugPrivilege + SCM access
// =======================================================================

#[test]
#[ignore = "requires elevated Administrator privileges"]
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
#[ignore = "requires elevated Administrator privileges and an active desktop session"]
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
        Err(ElevateError::SessionZeroNotSupported) => {
            eprintln!("[INFO] Running inside Session 0 (CI runner/headless); fast-fail verified.");
        }
        Err(e) => panic!("Unexpected failure acquiring token for caller session: {e}"),
    }
}

#[test]
#[ignore = "requires elevated Administrator privileges to spawn child processes with token"]
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

#[test]
#[ignore = "requires elevated Administrator privileges"]
fn test_acquired_token_session_id_readback() {
    assert_elevated_context();

    let strategy =
        TrustedInstallerStrategy::new(Duration::from_secs(30), ExecutionContext::Headless);
    let token = strategy.acquire_primary_token().unwrap();

    let session_id = token.session_id().expect("Must query session ID");
    assert_eq!(
        session_id, 0,
        "Headless token must be strictly confined to Session 0"
    );
}
