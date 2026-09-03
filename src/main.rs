use airgap_verify::{inspect_evidence, verify_artifact};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "airgap-verify",
    version,
    about = "Verify a Sigstore bundle without network access"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify one regular .tar.gz artifact against local evidence.
    Verify {
        artifact: PathBuf,
        evidence: PathBuf,
    },
    /// Inspect local evidence structure without verifying an artifact.
    Inspect { evidence: PathBuf },
    /// Print the program version.
    Version,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { artifact, evidence } => {
            let report = verify_artifact(&artifact, &evidence);
            print_json(&report);
            if report.verdict == "pass" {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Inspect { evidence } => {
            let report = inspect_evidence(&evidence);
            print_json(&report);
            if report.verdict == "pass" {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Command::Version => {
            println!("airgap-verify {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("could not serialize report: {error}");
        }
    }
}
