//! A safe, idiomatic Rust library to obtain Windows `TrustedInstaller` privileges.

pub mod elevation;
pub mod error;
pub mod security;
pub mod session;

pub use elevation::{Elevator, SessionTarget};
pub use error::{ElevateError, ProcessAccessFailure, ProcessDiagnostic, SessionDiagnostic};
pub use security::{Command, ExecutionContext, InteractiveDesktop};
pub use session::{ElevationStatus, relaunch, status};
