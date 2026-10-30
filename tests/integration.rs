//! End-to-end integration tests for elevate-ti public APIs.
//!
//! Run ignored tests with:
//! ```text
//! cargo test -- --ignored
//! ```

use elevate_ti::{Command, status};

#[test]
fn test_status_query_does_not_panic() {
    let result = status();
    assert!(result.is_ok(), "Querying elevation status must not fail");
}

#[test]
#[ignore = "requires elevated Administrator privileges to spawn child processes with token"]
fn test_spawn_headless_child_execution() {
    let cmd = Command::headless("%SystemRoot%\\System32\\cmd.exe")
        .expect("Must create headless command")
        .args("cmd.exe /c exit 0");

    assert!(
        cmd.spawn().is_ok(),
        "Must spawn process in headless mode without DACL or environment block failure"
    );
}
