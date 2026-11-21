use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "mcp-jail",
    version,
    about = "Rootless Linux kernel sandbox and syscall auditor for MCP servers",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommands>,

    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    /// Observe a session in audit-only mode and generate a minimal mcp-jail.toml
    Profile(RunArgs),
    /// Follow a .jsonl trace live
    Tail {
        /// Trace file (default: ~/.cache/mcp-jail/latest.jsonl)
        file: Option<PathBuf>,
    },
    /// Summarize a .jsonl trace
    Report {
        /// Trace file (default: ~/.cache/mcp-jail/latest.jsonl)
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// MCP server command to run inside the sandbox
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Debug, Default, Clone, Args)]
pub struct SandboxArgs {
    /// TOML policy file (default: ./mcp-jail.toml if present)
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Add a read-only path (repeatable)
    #[arg(long, value_name = "PATH")]
    pub ro: Vec<PathBuf>,

    /// Add a read-write path (repeatable)
    #[arg(long, value_name = "PATH")]
    pub rw: Vec<PathBuf>,

    /// Allow reading .env and .env.* files inside allowed directories
    #[arg(long)]
    pub allow_env: bool,

    /// Block all non-loopback outbound connections
    #[arg(long)]
    pub deny_net: bool,

    /// Allow outbound connections only to these IPs (repeatable)
    #[arg(long, value_name = "IP")]
    pub allow_net: Vec<IpAddr>,

    /// Block spawning new executables after the MCP server starts
    #[arg(long)]
    pub deny_exec: bool,

    /// Record policy violations without blocking syscalls
    #[arg(long)]
    pub audit_only: bool,

    /// Trace .jsonl path (default: ~/.cache/mcp-jail/latest.jsonl)
    #[arg(short, long, value_name = "FILE")]
    pub log: Option<PathBuf>,

    /// Suppress live block alerts on stderr
    #[arg(long)]
    pub quiet: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn parses_default_run_with_flags() {
        let cli = parse(&[
            "mcp-jail",
            "--deny-net",
            "--ro",
            "/opt",
            "--",
            "npx",
            "-y",
            "srv",
        ]);
        assert!(cli.subcommand.is_none());
        assert!(cli.run.sandbox.deny_net);
        assert_eq!(cli.run.sandbox.ro, vec![PathBuf::from("/opt")]);
        assert_eq!(cli.run.command, vec!["npx", "-y", "srv"]);
    }

    #[test]
    fn parses_profile_subcommand() {
        let cli = parse(&["mcp-jail", "profile", "--quiet", "--", "uvx", "srv"]);
        let Some(Subcommands::Profile(run)) = cli.subcommand else {
            panic!("expected profile subcommand");
        };
        assert!(run.sandbox.quiet);
        assert_eq!(run.command, vec!["uvx", "srv"]);
    }

    #[test]
    fn parses_tail_and_report_without_command() {
        assert!(matches!(
            parse(&["mcp-jail", "tail"]).subcommand,
            Some(Subcommands::Tail { file: None })
        ));
        assert!(matches!(
            parse(&["mcp-jail", "report", "x.jsonl"]).subcommand,
            Some(Subcommands::Report { file: Some(_) })
        ));
    }

    #[test]
    fn rejects_run_without_command() {
        assert!(Cli::try_parse_from(["mcp-jail", "--deny-net"]).is_err());
    }

    #[test]
    fn rejects_invalid_allow_net_ip() {
        assert!(Cli::try_parse_from(["mcp-jail", "--allow-net", "nope", "--", "x"]).is_err());
    }
}
