use std::error::Error;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
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
// Bounds how quickly signals and client EOF are noticed; child exit wakes immediately
const WAIT_INTERVAL_MS: libc::c_int = 20;
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
    let pidfd = open_pidfd(group);
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
        wait_interval(pidfd.as_ref());
    }
}

/// Opened before the child is reaped, so the pid cannot be recycled underneath it;
/// `None` on kernels older than 5.3
fn open_pidfd(pid: libc::pid_t) -> Option<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = RawFd::try_from(fd).ok().filter(|&fd| fd >= 0)?;
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Returns as soon as the child exits, or after WAIT_INTERVAL_MS otherwise
fn wait_interval(pidfd: Option<&OwnedFd>) {
    let Some(pidfd) = pidfd else {
        thread::sleep(Duration::from_millis(WAIT_INTERVAL_MS as u64));
        return;
    };
    let mut poll_fd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut poll_fd, 1, WAIT_INTERVAL_MS) };
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
