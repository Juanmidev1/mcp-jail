use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use super::{paths, remote};
use crate::policy::Policy;
use crate::trace::Category;

// Unreadable pointers fail closed: the kernel would reject them with EFAULT anyway, so
// legitimate programs never notice, while a racing writer cannot slip past the checks
const UNREADABLE_TARGET: &str = "<unreadable>";
const SOCKADDR_IN6_SIZE: usize = size_of::<libc::sockaddr_in6>();
#[cfg(target_arch = "x86_64")]
const CREAT_FLAGS: u64 = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub category: Category,
    pub syscall: &'static str,
    pub target: String,
    pub is_violation: bool,
}

pub struct Inspector {
    policy: Arc<Policy>,
    is_initial_exec_seen: bool,
}

impl Inspector {
    pub fn new(policy: Arc<Policy>) -> Self {
        Self {
            policy,
            is_initial_exec_seen: false,
        }
    }

    /// `None` means the syscall continues unrecorded (loopback, unix sockets, or the
    /// server's own startup execve)
    pub fn evaluate(&mut self, request: &libc::seccomp_notif) -> Option<Verdict> {
        let (pid, args) = (request.pid, request.data.args);
        let dirfd = args[0] as i32;
        match libc::c_long::from(request.data.nr) {
            libc::SYS_openat => self.open_verdict("openat", pid, dirfd, args[1], args[2]),
            libc::SYS_openat2 => {
                let flags = remote::read_u64(pid, args[2])?;
                self.open_verdict("openat2", pid, dirfd, args[1], flags)
            }
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open => self.open_verdict("open", pid, libc::AT_FDCWD, args[0], args[1]),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_creat => {
                self.open_verdict("creat", pid, libc::AT_FDCWD, args[0], CREAT_FLAGS)
            }
            libc::SYS_connect => self.connect_verdict(pid, args[1], args[2]),
            libc::SYS_execve => self.exec_verdict("execve", pid, libc::AT_FDCWD, args[0]),
            libc::SYS_execveat => self.exec_verdict("execveat", pid, dirfd, args[1]),
            _ => None,
        }
    }

    fn open_verdict(
        &self,
        syscall: &'static str,
        pid: u32,
        dirfd: i32,
        address: u64,
        flags: u64,
    ) -> Option<Verdict> {
        let Some(path) = read_target_path(pid, dirfd, address) else {
            return Some(unreadable_verdict(Category::Fs, syscall, true));
        };
        let canonical = paths::canonicalize_lenient(&path);
        // The kernel answers ENOENT before Landlock is consulted; returning EACCES instead
        // would change how runtimes treat optional config files such as /etc/gai.conf
        if !paths::is_create(flags) && !canonical.exists() {
            return None;
        }
        let is_denied = self.policy.is_denied_path(&path) || self.policy.is_denied_path(&canonical);
        let is_outside = !paths::is_path_only(flags)
            && !self
                .policy
                .is_path_allowed(&canonical, paths::is_write_intent(flags));
        Some(Verdict {
            category: Category::Fs,
            syscall,
            target: path.display().to_string(),
            is_violation: is_denied || is_outside,
        })
    }

    fn connect_verdict(&self, pid: u32, address: u64, length: u64) -> Option<Verdict> {
        let length = usize::try_from(length).ok()?.min(SOCKADDR_IN6_SIZE);
        let Some(bytes) = remote::read_bytes(pid, address, length) else {
            let restricts_network = self.policy.deny_net || !self.policy.allow_ips.is_empty();
            return Some(unreadable_verdict(
                Category::Net,
                "connect",
                restricts_network,
            ));
        };
        let socket_address = parse_socket_address(&bytes)?;
        if socket_address.ip().to_canonical().is_loopback() {
            return None;
        }
        Some(Verdict {
            category: Category::Net,
            syscall: "connect",
            target: socket_address.to_string(),
            is_violation: !self.policy.is_ip_allowed(socket_address.ip()),
        })
    }

    /// The first execve is the server binary itself: it is the only process that exists
    /// when the filter is installed, so its notification always arrives first
    fn exec_verdict(
        &mut self,
        syscall: &'static str,
        pid: u32,
        dirfd: i32,
        address: u64,
    ) -> Option<Verdict> {
        if !self.is_initial_exec_seen {
            self.is_initial_exec_seen = true;
            return None;
        }
        let Some(path) = read_target_path(pid, dirfd, address) else {
            return Some(unreadable_verdict(
                Category::Process,
                syscall,
                self.policy.deny_exec,
            ));
        };
        Some(Verdict {
            category: Category::Process,
            syscall,
            target: path.display().to_string(),
            is_violation: self.policy.deny_exec,
        })
    }
}

fn unreadable_verdict(category: Category, syscall: &'static str, is_violation: bool) -> Verdict {
    Verdict {
        category,
        syscall,
        target: UNREADABLE_TARGET.to_string(),
        is_violation,
    }
}

fn read_target_path(pid: u32, dirfd: i32, address: u64) -> Option<PathBuf> {
    let raw = PathBuf::from(remote::read_c_string(pid, address)?);
    let base = if raw.is_absolute() {
        PathBuf::from("/")
    } else {
        remote::directory_path(pid, dirfd)?
    };
    Some(paths::resolve(&raw, &base, pid))
}

/// Parses `sockaddr_in` / `sockaddr_in6`; other families (AF_UNIX, netlink) return `None`
pub fn parse_socket_address(bytes: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(bytes.get(0..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(bytes.get(2..4)?.try_into().ok()?);
    match libc::c_int::from(family) {
        libc::AF_INET => {
            let octets: [u8; 4] = bytes.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::from((Ipv4Addr::from(octets), port)))
        }
        libc::AF_INET6 => {
            let octets: [u8; 16] = bytes.get(8..24)?.try_into().ok()?;
            Some(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        _ => None,
    }
}
