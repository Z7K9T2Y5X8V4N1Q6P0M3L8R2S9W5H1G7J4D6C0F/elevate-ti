//! Example demonstrating spawning a custom process (e.g. cmd.exe)
//! directly with elevated `TrustedInstaller` privileges in the user's interactive desktop.

use elevate_ti::elevated_command;
// Advanced usage:
// use elevate_ti::{elevated_command_on, InteractiveDesktop};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Spawning an elevated Command Prompt...");

    // Standard interactive desktop:
    elevated_command()?
        .exe("%SystemRoot%\\System32\\cmd.exe")
        .args("cmd.exe /k whoami /groups")
        .spawn()?;

    // Tip: To target specific desktops (like the lock screen or a custom sandbox),
    // you can use `elevated_command_on`:
    //
    // elevated_command_on(InteractiveDesktop::Winlogon)?.exe(...).spawn()?;
    // elevated_command_on(InteractiveDesktop::custom("CustomStation\\CustomDesktop"))?.exe(...).spawn()?;

    println!("Elevated Command Prompt spawned successfully.");
    Ok(())
}
