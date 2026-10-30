//! Example demonstrating headless `TrustedInstaller` execution.
//!
//! Ideal for background services, automated maintenance, CI/CD pipelines,
//! and environments without an active GUI/desktop session (Session 0).

use elevate_ti::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Spawning headless background maintenance command...");

    Command::headless("%SystemRoot%\\System32\\cmd.exe")?
        .args("/k whoami /groups")
        .spawn()?;

    println!("Headless process spawned successfully in Session 0.");
    Ok(())
}
