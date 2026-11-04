//! Idiomatic, safe Win32 security primitives.

pub mod command;
pub(crate) mod guard;
pub(crate) mod privilege;
pub(crate) mod service;
pub(crate) mod sid;
pub(crate) mod snapshot;
pub(crate) mod token;

pub use command::{Command, ExecutionContext, InteractiveDesktop};
pub(crate) use service::ServiceManager;
pub(crate) use snapshot::ProcessSnapshot;
pub(crate) use token::Token;

macro_rules! win32 {
    ($func:ident ( $($arg:tt)* )) => {
        unsafe { $func($($arg)*) }.map_err(|source| $crate::error::ElevateError::Win32 {
            operation: stringify!($func),
            source,
        })
    };
}
pub(crate) use win32;
