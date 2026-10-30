//! Example demonstrating spawning a custom process (e.g. cmd.exe)
//! directly with elevated `TrustedInstaller` privileges in the user's interactive desktop.

use elevate_ti::Command;
// Advanced usage:
// use elevate_ti::InteractiveDesktop;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Spawning an elevated Command Prompt...");

    // Standard interactive desktop:
    Command::new("%SystemRoot%\\System32\\cmd.exe")?
        .args("/k whoami /groups")
        .spawn()?;

    // Tip: To target specific desktops (like the lock screen or a custom sandbox),
    // you can use `Command::on_desktop`:
    //
    // Command::on_desktop(&InteractiveDesktop::Winlogon, "%SystemRoot%\\System32\\cmd.exe")?.spawn()?;
    // Command::on_desktop(&InteractiveDesktop::custom("CustomStation\\CustomDesktop"), "%SystemRoot%\\System32\\cmd.exe")?.spawn()?;

    println!("Elevated Command Prompt spawned successfully.");
    Ok(())
}
