mod lifecycle;

use std::env;
use std::error::Error;
use std::io::{self, IsTerminal};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use crate::landlock;
use crate::policy::{Policy, home_dir};
use crate::rpc::RpcTracker;
use crate::seccomp::{self, ChildSetup};
use crate::supervisor::{self, SupervisorContext};
use crate::trace::{EventKind, Tracer};

const EXECUTABLE_MODE_BITS: u32 = 0o111;

/// Runs `command` inside the sandbox and returns its exit code
pub fn run(command: &[String], mut policy: Policy) -> Result<i32, Box<dyn Error>> {
    colored::control::set_override(io::stderr().is_terminal());
    restrict_to_concrete_paths(&mut policy)?;
    let policy = Arc::new(policy);
    let tracer = Arc::new(Tracer::create(&policy.log_path)?);
    let audit_only = policy.audit_only;
    tracer.emit(EventKind::SessionStart {
        command: command.to_vec(),
        audit_only,
    });
    let tracker = RpcTracker::default();
    let stop = Arc::new(AtomicBool::new(false));
    let context = SupervisorContext {
        policy: Arc::clone(&policy),
        tracker: tracker.clone(),
        tracer: Arc::clone(&tracer),
        stop: Arc::clone(&stop),
    };
    lifecycle::install_signal_handlers();
    let (supervisor, sender) = start_supervisor(context)?;
    let outcome = spawn_child(command, &policy, sender)
        .and_then(|child| lifecycle::supervise(child, &tracker, &tracer));
    stop.store(true, Ordering::Relaxed);
    if supervisor.join().is_err() {
        eprintln!("mcp-jail: supervisor thread panicked");
    }
    let exit_code = outcome?;
    tracer.emit(EventKind::SessionEnd { exit_code });
    Ok(exit_code)
}

fn restrict_to_concrete_paths(policy: &mut Policy) -> io::Result<()> {
    policy.resolve_paths(&env::current_dir()?);
    for dropped in policy.drop_broad_grants(home_dir().as_deref()) {
        eprintln!(
            "mcp-jail: warning: refusing to grant {} wholesale (is the server started from / or \
             $HOME?); pass --rw <project dir> or set cwd explicitly",
            dropped.display()
        );
    }
    Ok(())
}

/// Must run before spawn(): the child's execve blocks until the supervisor answers it.
/// Returns the supervisor thread and the socket end the child sends its listener over
fn start_supervisor(context: SupervisorContext) -> io::Result<(JoinHandle<()>, OwnedFd)> {
    let (receiver, sender) = seccomp::socket_pair()?;
    let supervisor = thread::spawn(move || receive_and_supervise(&receiver, &context));
    Ok((supervisor, sender))
}

fn receive_and_supervise(receiver: &OwnedFd, context: &SupervisorContext) {
    match seccomp::receive_fd(receiver) {
        Ok(Some(notify_fd)) => supervisor::run(notify_fd, context),
        // The child failed before installing the filter; spawn() reports why
        Ok(None) => {}
        Err(error) => eprintln!("mcp-jail: cannot receive seccomp listener: {error}"),
    }
}

/// `sender` moves into the pre_exec closure, so the parent's copy closes when the
/// Command is dropped and the receiver thread never waits forever on a failed spawn
fn spawn_child(
    command: &[String],
    policy: &Policy,
    sender: OwnedFd,
) -> Result<Child, Box<dyn Error>> {
    let (program, args) = command.split_first().ok_or("missing MCP server command")?;
    let program = resolve_program(program)?;
    let ruleset = if policy.audit_only {
        None
    } else {
        warn_if_landlock_missing();
        Some(landlock::prepare_ruleset(policy)?)
    };
    let mut setup = ChildSetup::new(seccomp::build_filter(), ruleset, sender);
    let mut child_command = Command::new(&program);
    child_command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    unsafe { child_command.pre_exec(move || setup.apply()) };
    child_command
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", program.display()).into())
}

/// PATH lookup happens here so the child performs exactly one execve, which the
/// supervisor recognizes as the server's own startup
fn resolve_program(program: &str) -> Result<PathBuf, Box<dyn Error>> {
    if program.contains('/') {
        return Ok(PathBuf::from(program));
    }
    let search_path = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&search_path)
        .map(|directory| directory.join(program))
        .find(|candidate| is_executable_file(candidate))
        .ok_or_else(|| format!("command not found in PATH: {program}").into())
}

fn is_executable_file(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & EXECUTABLE_MODE_BITS != 0)
}

fn warn_if_landlock_missing() {
    if !landlock::is_supported() {
        eprintln!(
            "mcp-jail: warning: this kernel does not support Landlock (Linux 5.13+); \
             filesystem isolation relies on seccomp checks only"
        );
    }
}
