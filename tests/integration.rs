//! End-to-end integration tests for elevate-ti public APIs.
//!
//! Note: Tests that actually perform elevation require an elevated Administrator
//! command prompt. You can run all ignored tests using:
//! ```text
//! cargo test -- --ignored
//! ```

use elevate_ti::{Command, status};

// Ensure checking the elevation status works reliably from a normal, unprivileged process.
// It should return an Ok status without failing or panicking.
#[test]
fn status_query_returns_ok_in_unprivileged_context() {
    let result = status();
    assert!(result.is_ok(), "Querying elevation status must not fail");
}

// Full end-to-end test: start TrustedInstaller, steal the SYSTEM token, duplicate it,
// and spawn a real background process in Session 0 without opening any visible windows.
#[test]
#[ignore = "requires elevated Administrator privileges to spawn child processes with token"]
fn spawn_headless_child_process_with_trustedinstaller_token() {
    // We run "cmd.exe /c exit 0" as a quick smoke test that exits immediately.
    let cmd = Command::headless("%SystemRoot%\\System32\\cmd.exe")
        .expect("Failed to initialize headless command builder")
        .args("/c exit 0");

    assert!(
        cmd.spawn().is_ok(),
        "Failed to spawn the headless child process with TrustedInstaller privileges"
    );
}
