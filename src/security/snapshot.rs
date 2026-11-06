//! Lightweight native Windows process snapshot iterator using `ToolHelp32`.

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
};

use super::win32;
use crate::error::ElevateError;

/// Lightweight, zero-allocation borrowed view of a process entry in a snapshot.
#[derive(Debug)]
pub struct ProcessEntry<'a> {
    /// Process ID (PID).
    pub pid: u32,
    raw_name: &'a [u16],
}

impl ProcessEntry<'_> {
    /// Performs a zero-allocation, case-insensitive comparison against an ASCII string.
    #[inline]
    #[must_use]
    pub fn eq_ignore_ascii_case(&self, ascii: &str) -> bool {
        if self.raw_name.len() != ascii.len() {
            return false;
        }

        // Compare native UTF-16 code units (`u`) directly against ASCII bytes (`b`).
        // If `u <= 0x7F`, it is guaranteed to be a pure ASCII character with its high byte as 0x00,
        // making the truncation `u as u8` safe and allowing zero-allocation case folding.
        self.raw_name
            .iter()
            .zip(ascii.as_bytes())
            .all(|(&u, &b)| u <= 0x7F && (u as u8).eq_ignore_ascii_case(&b))
    }

    /// Converts the UTF-16 image name to a standard Rust [`String`].
    ///
    /// This performs heap allocation and UTF-16 decoding lazily only when requested.
    #[inline]
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf16_lossy(self.raw_name)
    }
}

/// Lightweight RAII cursor over active system processes.
#[derive(Debug)]
pub struct ProcessSnapshot {
    handle: HANDLE,
    entry: PROCESSENTRY32W,
    started: bool,
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl ProcessSnapshot {
    /// Capture a new process snapshot of the current system state.
    pub fn new() -> Result<Self, ElevateError> {
        let handle = win32!(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;
        let entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        Ok(Self {
            handle,
            entry,
            started: false,
        })
    }

    /// Advances the snapshot cursor and yields a zero-allocation borrowed [`ProcessEntry`].
    pub fn next_entry(&mut self) -> Option<ProcessEntry<'_>> {
        let ok = if self.started {
            unsafe { Process32NextW(self.handle, &raw mut self.entry).is_ok() }
        } else {
            self.started = true;
            unsafe { Process32FirstW(self.handle, &raw mut self.entry).is_ok() }
        };

        if !ok {
            return None;
        }

        let len = self
            .entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.entry.szExeFile.len());

        Some(ProcessEntry {
            pid: self.entry.th32ProcessID,
            raw_name: &self.entry.szExeFile[..len],
        })
    }
}
