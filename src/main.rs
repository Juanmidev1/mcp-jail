use std::error::Error;
use std::process::ExitCode;

use clap::Parser;

use mcp_jail::cli::{Cli, Subcommands};
use mcp_jail::policy::Policy;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mcp-jail: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    // TODO: dispatch to the sandbox, tail, report and profile runtimes in later phases
    if let Some(Subcommands::Profile(run)) = &cli.subcommand {
        Policy::load(&run.sandbox)?;
    } else if cli.subcommand.is_none() {
        Policy::load(&cli.run.sandbox)?;
    }
    Err("this subcommand is not implemented yet".into())
}
