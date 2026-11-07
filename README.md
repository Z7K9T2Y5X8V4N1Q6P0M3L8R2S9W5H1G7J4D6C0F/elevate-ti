# Elevate-TI

[![Crates.io](https://img.shields.io/crates/v/elevate-ti?style=flat-square)](https://crates.io/crates/elevate-ti)
[![Docs.rs](https://img.shields.io/docsrs/elevate-ti?style=flat-square)](https://docs.rs/elevate-ti)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](LICENSE-APACHE)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE-MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=flat-square&logo=windows)](https://microsoft.com)

**Spawn processes with `NT SERVICE\TrustedInstaller` privileges from Rust.**

Navigates Session 0 isolation via token impersonation, allowing execution either interactively on the active desktop (`WinSta0\Default`) or headlessly in background sessions (CI, services).

## How It Works

```text
Caller (Admin + SeDebugPrivilege)
  │
  ├── 1. Ensure TrustedInstaller service is running (SCM)
  │
  ├── 2. Steal Session 0 SYSTEM Token (services.exe or scan fallback)
  │      └─> Impersonate to acquire SeTcbPrivilege
  │
  ├── 3. Duplicate TrustedInstaller Token
  │      ├── Interactive ──> Assign to active TokenSessionId
  │      └── Headless    ──> Keep in Session 0
  │
  └── 4. Spawn Process (CreateProcessWithTokenW)
```

## Installation

Add `elevate-ti` to your `Cargo.toml` by running:

```bash
cargo add elevate-ti
```

## Quick Start

```rust
use elevate_ti::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn an interactive TrustedInstaller process on the active desktop
    Command::new("cmd.exe")
        .args("/k whoami /groups")
        .spawn()?;

    Ok(())
}
```

## Examples

For complete and runnable scenarios, check the [`examples`](examples) directory:

- [`relaunch.rs`](examples/relaunch.rs): Automatic self-elevation and privilege verification.
- [`spawn.rs`](examples/spawn.rs): Spawning interactive processes onto user or secure desktops.
- [`headless.rs`](examples/headless.rs): Non-interactive background execution in Session 0.
- [`audit.rs`](examples/audit.rs): In-process token acquisition and kernel audit provenance reporting.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
