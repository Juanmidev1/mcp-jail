mod fd_transfer;

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use ::landlock::RulesetCreated;

pub use fd_transfer::{receive_fd, socket_pair};

const BPF_LOAD_WORD_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const BPF_JUMP_EQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const BPF_RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 8;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("mcp-jail supports only x86_64 and aarch64");

// x32 syscalls share the x86_64 audit arch but set this bit, so they would bypass nr matching
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Legacy open/creat exist only on x86_64 and would otherwise bypass openat interception
#[cfg(target_arch = "x86_64")]
pub const MONITORED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_connect,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_open,
    libc::SYS_creat,
];
#[cfg(target_arch = "aarch64")]
pub const MONITORED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_connect,
    libc::SYS_execve,
    libc::SYS_execveat,
];

pub fn build_filter() -> Vec<libc::sock_filter> {
    let mut program = vec![
        statement(BPF_LOAD_WORD_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump_if_equal(AUDIT_ARCH, 1, 0),
        statement(BPF_RETURN, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LOAD_WORD_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    #[cfg(target_arch = "x86_64")]
    program.extend([
        jump(
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
            X32_SYSCALL_BIT,
            0,
            1,
        ),
        statement(BPF_RETURN, SECCOMP_RET_KILL_PROCESS),
    ]);
    for &syscall_nr in MONITORED_SYSCALLS {
        program.push(jump_if_equal(syscall_nr as u32, 0, 1));
        program.push(statement(BPF_RETURN, SECCOMP_RET_USER_NOTIF));
    }
    program.push(statement(BPF_RETURN, SECCOMP_RET_ALLOW));
    program
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump_if_equal(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JUMP_EQ,
        jt,
        jf,
        k,
    }
}

#[cfg(target_arch = "x86_64")]
fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

/// Everything the forked child needs, built in the parent so `apply` never allocates
pub struct ChildSetup {
    filter: Vec<libc::sock_filter>,
    ruleset: Option<RulesetCreated>,
    sender: OwnedFd,
}

impl ChildSetup {
    pub fn new(
        filter: Vec<libc::sock_filter>,
        ruleset: Option<RulesetCreated>,
        sender: OwnedFd,
    ) -> Self {
        Self {
            filter,
            ruleset,
            sender,
        }
    }

    /// Runs inside `pre_exec`: only async-signal-safe syscalls, no heap allocation
    pub fn apply(&mut self) -> io::Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if let Some(ruleset) = self.ruleset.take() {
            crate::landlock::enforce(ruleset)
                .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?;
        }
        let listener = self.install_filter()?;
        let sent = fd_transfer::send_fd(self.sender.as_raw_fd(), listener);
        // The child must never keep the listener, or it could answer its own notifications
        unsafe {
            libc::close(listener);
            libc::close(self.sender.as_raw_fd());
        }
        sent
    }

    fn install_filter(&self) -> io::Result<libc::c_int> {
        let program = libc::sock_fprog {
            len: self.filter.len() as libc::c_ushort,
            filter: self.filter.as_ptr().cast_mut(),
        };
        let listener = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &program as *const libc::sock_fprog,
            )
        };
        if listener < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(listener as libc::c_int)
    }
}

#[cfg(test)]
mod tests;
