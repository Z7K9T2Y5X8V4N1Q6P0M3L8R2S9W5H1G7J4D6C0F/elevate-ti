//! Example demonstrating headless `TrustedInstaller` execution.
//!
//! Ideal for background services, automated maintenance, CI/CD pipelines,
//! and environments without an active GUI/desktop session (Session 0).

use elevate_ti::headless_command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Spawning headless background maintenance command...");

    // `headless_command()` automatically binds to a Session 0 TrustedInstaller token
    // with no desktop station attached, preventing any Session 0 DACL or access violations.
    headless_command()?
        .exe("%SystemRoot%\\System32\\cmd.exe")
        .args("cmd.exe /k whoami /groups")
        .spawn()?;

    println!("Headless process spawned successfully in Session 0.");
    Ok(())
}
