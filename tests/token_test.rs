//! End-to-end integration tests for elevate-ti public APIs.

use elevate_ti::{ElevationStatus, Sid, Token, status};
use windows::core::w;

#[test]
fn test_public_sid_parsing() {
    let system_sid = w!("S-1-5-18");
    let sid = Sid::parse(system_sid).expect("System SID parsing should never fail");
    assert!(!sid.as_raw().is_invalid());
}

#[test]
fn test_current_process_token_query() {
    let token = Token::current().expect("Must be able to query current process token");
    let session_id = token
        .session_id()
        .expect("Current process must have a session ID");
    // Interactive Windows user sessions are >= 0
    assert!(session_id < 65535);
}

#[test]
fn test_status_query_does_not_panic() {
    // Verifies that query executes safely without memory violations
    let current_status = status().expect("Status query must succeed on Windows");
    match current_status {
        ElevationStatus::Elevated => println!("Running elevated"),
        ElevationStatus::RequiresElevation => println!("Running non-elevated"),
    }
}
