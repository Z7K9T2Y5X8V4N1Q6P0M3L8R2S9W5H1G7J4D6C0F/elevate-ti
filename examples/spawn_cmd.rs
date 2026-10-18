//! Example demonstrating spawning a custom process (e.g. cmd.exe)
//! directly with elevated `TrustedInstaller` privileges.

use elevate_ti::elevated_command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Spawning an elevated Command Prompt...");

    elevated_command()?
        .exe("%SystemRoot%\\System32\\cmd.exe")
        .args("cmd.exe /k whoami /groups")
        .spawn()?;

    println!("Elevated Command Prompt spawned successfully.");
    Ok(())
}
