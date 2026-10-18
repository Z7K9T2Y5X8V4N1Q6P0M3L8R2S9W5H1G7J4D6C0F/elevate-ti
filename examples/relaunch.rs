//! Example demonstrating how a process can verify its privileges
//! and automatically relaunch itself as `TrustedInstaller`.

use elevate_ti::{ElevationStatus, relaunch, status};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking elevation status...");

    if status()? == ElevationStatus::RequiresElevation {
        println!("Currently running as standard user/admin. Relaunching as TrustedInstaller...");
        relaunch()?;
        return Ok(());
    }

    println!("Success! Process is now running with TrustedInstaller privileges.");
    println!("Press Enter to exit...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}
