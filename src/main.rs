use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use mcp_jail::cli::{Cli, RunArgs, Subcommands};
use mcp_jail::policy::{Policy, default_trace_path, home_dir};
use mcp_jail::{profile, report, sandbox, tail};

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
        Some(Subcommands::Profile(run)) => profile::run(&run).map(to_exit_code),
        Some(Subcommands::Tail { file }) => tail::run(&trace_file(file)).map(|()| 0),
        Some(Subcommands::Report { file }) => report::run(&trace_file(file)).map(|()| 0),
    }
}

fn run_sandbox(run: &RunArgs) -> Result<u8, Box<dyn Error>> {
    let policy = Policy::load(&run.sandbox)?;
    sandbox::run(&run.command, policy).map(to_exit_code)
}

fn trace_file(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(|| default_trace_path(home_dir().as_deref()))
}

fn to_exit_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(FAILURE_EXIT_CODE)
}
