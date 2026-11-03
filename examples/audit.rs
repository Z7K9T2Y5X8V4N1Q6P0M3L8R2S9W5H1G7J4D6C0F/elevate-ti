//! Example demonstrating standalone token acquisition and elevation audit provenance reporting.
//!
//! Ideal for security tooling, audit logging pipelines, and infrastructure services
//! that operate in-process without spawning external child processes.

use elevate_ti::Elevator;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting elevated TrustedInstaller primary token...");

    // Acquire primary token with attached execution provenance metadata
    let token = Elevator::default().acquire_primary_token()?;

    // Read and print the verified kernel-level audit report
    if let Some(report) = token.report() {
        println!("\n================ Elevation Audit Report ================");
        println!(
            "* TrustedInstaller Service PID : {}",
            report.trusted_installer_pid
        );
        println!(
            "* SYSTEM Pivot Process         : {} (PID: {})",
            report.pivot_process_name, report.pivot_pid
        );
        println!("* Target Bound Session ID      : {}", report.target_session);
        println!("========================================================\n");
    }

    println!("Token successfully acquired with verified audit provenance.");
    Ok(())
}
