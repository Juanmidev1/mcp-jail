use std::error::Error;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::proxy;
use crate::rpc::RpcTracker;
use crate::trace::Tracer;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const WAIT_INTERVAL: Duration = Duration::from_millis(20);
const SIGNAL_EXIT_BASE: i32 = 128;

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn request_shutdown(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

pub fn supervise(
    mut child: Child,
    tracker: &RpcTracker,
    tracer: &Arc<Tracer>,
) -> Result<i32, Box<dyn Error>> {
    // process_group(0) makes the child the leader of a group whose id is its pid
    let group = libc::pid_t::try_from(child.id())?;
    let proxy = match proxy::spawn(&mut child, tracker, tracer) {
        Ok(proxy) => proxy,
        Err(error) => {
            kill_group(group, libc::SIGKILL);
            child.wait()?;
            return Err(error);
        }
    };
    let status = wait_for_exit(&mut child, group, &proxy.stdin);
    // Reap helpers that npx/uvx leave behind once the server itself is gone
    kill_group(group, libc::SIGKILL);
    finish_forwarding("stdout", proxy.stdout);
    finish_forwarding("stderr", proxy.stderr);
    Ok(exit_code(status?))
}

/// Shutdown starts on SIGINT/SIGTERM or when the client closes stdin; the group gets
/// SHUTDOWN_GRACE to exit on its own before SIGKILL
fn wait_for_exit(
    child: &mut Child,
    group: libc::pid_t,
    stdin_forwarder: &JoinHandle<io::Result<()>>,
) -> io::Result<ExitStatus> {
    let mut kill_deadline: Option<Instant> = None;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let is_signaled = SHUTDOWN_REQUESTED.load(Ordering::Relaxed);
        if kill_deadline.is_none() && (is_signaled || stdin_forwarder.is_finished()) {
            if is_signaled {
                kill_group(group, libc::SIGTERM);
            }
            kill_deadline = Some(Instant::now() + SHUTDOWN_GRACE);
        }
        if kill_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            kill_group(group, libc::SIGKILL);
        }
        thread::sleep(WAIT_INTERVAL);
    }
}

/// Installed before spawn so an early Ctrl-C cannot orphan the server's process group
pub fn install_signal_handlers() {
    let handler = request_shutdown as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// ESRCH just means the group is already gone
fn kill_group(group: libc::pid_t, signal: libc::c_int) {
    unsafe { libc::kill(-group, signal) };
}

fn finish_forwarding(stream: &str, handle: JoinHandle<io::Result<()>>) {
    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {}
        Ok(Err(error)) => eprintln!("mcp-jail: {stream} forwarding failed: {error}"),
        Err(_) => eprintln!("mcp-jail: {stream} forwarding thread panicked"),
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| SIGNAL_EXIT_BASE + status.signal().unwrap_or(0))
}
