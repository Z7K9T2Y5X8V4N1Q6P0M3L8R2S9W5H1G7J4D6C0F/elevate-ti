<div align="center">

# Elevate-TI

**A safe, idiomatic Rust library to obtain Windows TrustedInstaller privileges.**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://microsoft.com)
[![Rust](https://img.shields.io/badge/Language-Rust_2024-dea584?style=flat-square&logo=rust)](https://rust-lang.org)

</div>

## Overview

`elevate-ti` is an ergonomic Windows systems library designed to elevate privileges to `NT SERVICE\TrustedInstaller`. It isolates Session 0 services, acquires primary tokens via chained impersonation, and spawns processes directly onto the active user's interactive desktop (`WinSta0\Default`).

## Architecture Flow

```text
Caller (Admin)
  │
  ├─> 1. Enable SeDebugPrivilege & SeImpersonatePrivilege
  ├─> 2. Ensure TrustedInstaller service is running (SCM)
  ├─> 3. Locate winlogon.exe in caller session & impersonate SYSTEM
  │     └─> Duplicate TrustedInstaller Primary Token
  │     └─> Bind Token to caller Session ID
  │
  └─> 4. Spawn target process onto active desktop (WinSta0\Default)
```

## Quickstart

Add `elevate-ti` to your `Cargo.toml`:

```toml
[dependencies]
elevate-ti = { git = "https://github.com/Z7K9T2Y5X8V4N1Q6P0M3L8R2S9W5H1G7J4D6C0F/elevate-ti.git", branch = "main" }
```

### Automatic Self-Relaunch

```rust
use elevate_ti::{status, relaunch, ElevationStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if status()? == ElevationStatus::RequiresElevation {
        relaunch()?;
        return Ok(());
    }

    println!("Running with TrustedInstaller privileges!");
    Ok(())
}
```

### Spawning an Elevated Child Process

```rust
use elevate_ti::elevated_command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    elevated_command()?
        .exe("%SystemRoot%\\System32\\cmd.exe")
        .args("cmd.exe /k whoami /groups")
        .spawn()?;

    Ok(())
}
```

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).
