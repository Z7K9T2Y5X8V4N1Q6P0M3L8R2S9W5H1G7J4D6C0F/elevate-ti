# Elevate-TI

[![Crates.io](https://img.shields.io/crates/v/elevate-ti?style=flat-square)](https://crates.io/crates/elevate-ti)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE-MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://microsoft.com)
[![Rust](https://img.shields.io/badge/Language-Rust_2024-dea584?style=flat-square&logo=rust)](https://rust-lang.org)

**A safe, idiomatic Rust library to obtain Windows TrustedInstaller privileges.**

## Overview

`elevate-ti` is an ergonomic Windows systems library designed to elevate privileges to `NT SERVICE\TrustedInstaller`. It acquires primary tokens via chained impersonation, navigates Session 0 isolation, and supports launching processes either onto an active interactive desktop (`WinSta0\Default`) or within headless background sessions (CI, services, and tasks).

## Architecture Flow

```text
Caller (Admin with SeDebugPrivilege)
  │
  ├─> 1. Ensure "TrustedInstaller" Service is Running (SCM polling)
  │
  ├─> 2. Pivot to Session 0 SYSTEM Token (Bypassing RunAs-PPL/WinTCB)
  │     ├─> Primary: services.exe (System32 path validated)
  │     └─> Fallback: Dynamic Session 0 scan & token verification
  │
  ├─> 3. Impersonate SYSTEM (Acquires SeTcbPrivilege)
  │     │
  │     └─> Duplicate TrustedInstaller Token (TokenPrimary)
  │           ├─> Headless: Bind strictly to Session 0 (No desktop station)
  │           └─> Interactive: Reassign TokenSessionId + Readback Verification
  │
  └─> 4. CreateProcessWithTokenW (Target Desktop or Headless Context)
```

## Usage

Add `elevate-ti` to your `Cargo.toml` by running:

```bash
cargo add elevate-ti
```

## Examples

For complete and runnable scenarios, check the [`examples`](examples) directory:

- [`relaunch.rs`](examples/relaunch.rs): Automatic self-elevation and privilege verification.
- [`spawn_cmd.rs`](examples/spawn_cmd.rs): Spawning interactive processes onto user or secure desktops.
- [`headless_cmd.rs`](examples/headless_cmd.rs): Non-interactive background execution in Session 0.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
