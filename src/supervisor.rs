mod inspect;
mod paths;
mod remote;

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::alert::format_syscall_event;
use crate::policy::Policy;
use crate::rpc::RpcTracker;
use crate::trace::{Action, Category, EventKind, Tracer};
pub use inspect::{Inspector, Verdict, parse_socket_address};

const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const IOC_DIRECTION_SHIFT: u64 = 30;
const IOC_SIZE_SHIFT: u64 = 16;
const IOC_TYPE_SHIFT: u64 = 8;
const SECCOMP_IOC_MAGIC: u64 = b'!' as u64;
const SECCOMP_NOTIF_SIZE: u64 = 80;
const SECCOMP_NOTIF_RESP_SIZE: u64 = 24;
const SECCOMP_NOTIF_ID_SIZE: u64 = 8;

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = ioc(IOC_READ | IOC_WRITE, 0, SECCOMP_NOTIF_SIZE);
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = ioc(IOC_READ | IOC_WRITE, 1, SECCOMP_NOTIF_RESP_SIZE);
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = ioc(IOC_WRITE, 2, SECCOMP_NOTIF_ID_SIZE);
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Bounds how long the loop takes to notice the stop flag once the session ends
const POLL_TIMEOUT_MS: libc::c_int = 100;

const fn ioc(direction: u64, number: u64, size: u64) -> u64 {
    (direction << IOC_DIRECTION_SHIFT)
        | (size << IOC_SIZE_SHIFT)
        | (SECCOMP_IOC_MAGIC << IOC_TYPE_SHIFT)
        | number
}

pub struct SupervisorContext {
    pub policy: Arc<Policy>,
    pub tracker: RpcTracker,
    pub tracer: Arc<Tracer>,
    pub stop: Arc<AtomicBool>,
}

enum Readiness {
    Ready,
    Idle,
    Closed,
}

pub fn run(notify_fd: OwnedFd, context: &SupervisorContext) {
    let fd = notify_fd.as_raw_fd();
    let mut inspector = Inspector::new(Arc::clone(&context.policy));
    while !context.stop.load(Ordering::Relaxed) {
        match wait_for_notification(fd) {
            Readiness::Ready => {}
            Readiness::Idle => continue,
            Readiness::Closed => return,
        }
        if let Some(request) = receive_notification(fd) {
            handle(fd, &request, &mut inspector, context);
        }
    }
}

/// RECV blocks forever once every filtered task is gone, so readiness comes from poll,
/// which reports POLLHUP in that case
fn wait_for_notification(fd: RawFd) -> Readiness {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll_fd, 1, POLL_TIMEOUT_MS) } < 0 {
        let is_interrupted = std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR);
        return if is_interrupted {
            Readiness::Idle
        } else {
            Readiness::Closed
        };
    }
    if poll_fd.revents & libc::POLLIN != 0 {
        Readiness::Ready
    } else if poll_fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        Readiness::Closed
    } else {
        Readiness::Idle
    }
}

/// `None` when the target died between poll and RECV (ENOENT) or on EINTR
fn receive_notification(fd: RawFd) -> Option<libc::seccomp_notif> {
    // The kernel rejects RECV with EINVAL unless the buffer is zeroed
    let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut request) };
    (result == 0).then_some(request)
}

fn handle(
    fd: RawFd,
    request: &libc::seccomp_notif,
    inspector: &mut Inspector,
    context: &SupervisorContext,
) {
    let Some(verdict) = inspector.evaluate(request) else {
        respond(fd, request.id, false);
        return;
    };
    // Memory read from the target is only trustworthy while the request is still pending;
    // a dead request needs no reply
    if !is_request_valid(fd, request.id) {
        return;
    }
    let action = match (verdict.is_violation, context.policy.audit_only) {
        (false, _) => Action::Allowed,
        (true, true) => Action::Audited,
        (true, false) => Action::Blocked,
    };
    respond(fd, request.id, action == Action::Blocked);
    report(&verdict, action, request.pid, context);
}

fn is_request_valid(fd: RawFd, id: u64) -> bool {
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID as _, &id) == 0 }
}

/// A failed SEND only means the target already died, so there is nothing to recover
fn respond(fd: RawFd, id: u64, is_blocked: bool) {
    let mut response = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    if is_blocked {
        response.error = -libc::EACCES;
        response.flags = 0;
    }
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &mut response) };
}

/// Allowed file opens are only recorded in audit mode, where `profile` needs them
fn report(verdict: &Verdict, action: Action, pid: u32, context: &SupervisorContext) {
    let policy = &context.policy;
    if action == Action::Allowed && verdict.category == Category::Fs && !policy.audit_only {
        return;
    }
    let mcp_context = context.tracker.current_context();
    if action != Action::Allowed && !policy.quiet {
        let (syscall, target) = (verdict.syscall, verdict.target.as_str());
        let line = format_syscall_event(action, verdict.category, syscall, target, &mcp_context);
        eprintln!("{line}");
    }
    context.tracer.emit(EventKind::SyscallEvent {
        action,
        category: verdict.category,
        syscall: verdict.syscall.to_string(),
        target: verdict.target.clone(),
        pid: i32::try_from(pid).unwrap_or(i32::MAX),
        mcp_context,
    });
}

#[cfg(test)]
mod tests;
