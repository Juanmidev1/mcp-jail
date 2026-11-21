use std::error::Error;
use std::process::ExitCode;

use clap::Parser;

use mcp_jail::cli::{Cli, RunArgs};
use mcp_jail::policy::Policy;
use mcp_jail::sandbox;

const FAILURE_EXIT_CODE: u8 = 1;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("mcp-jail: {error}");
            ExitCode::from(FAILURE_EXIT_CODE)
        }
    }
}

fn run(cli: Cli) -> Result<u8, Box<dyn Error>> {
    match cli.subcommand {
        None => run_sandbox(&cli.run),
        // TODO: implement profile, tail and report in the views phase
        Some(_) => Err("this subcommand is not implemented yet".into()),
    }
}

fn run_sandbox(run: &RunArgs) -> Result<u8, Box<dyn Error>> {
    let policy = Policy::load(&run.sandbox)?;
    let exit_code = sandbox::run(&run.command, policy)?;
    Ok(u8::try_from(exit_code).unwrap_or(FAILURE_EXIT_CODE))
}
