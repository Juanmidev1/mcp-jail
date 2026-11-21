use std::os::fd::{AsRawFd, FromRawFd};

use super::*;

#[test]
fn filter_checks_arch_then_notifies_monitored_syscalls() {
    let filter = build_filter();
    assert_eq!(filter[0].k, SECCOMP_DATA_ARCH_OFFSET);
    assert_eq!(filter[1].k, AUDIT_ARCH);
    assert_eq!(filter[2].k, SECCOMP_RET_KILL_PROCESS);
    let notified: Vec<u32> = filter
        .windows(2)
        .filter(|pair| pair[1].k == SECCOMP_RET_USER_NOTIF && pair[0].code == BPF_JUMP_EQ)
        .map(|pair| pair[0].k)
        .collect();
    let expected: Vec<u32> = MONITORED_SYSCALLS.iter().map(|&nr| nr as u32).collect();
    assert_eq!(notified, expected);
    assert_eq!(filter.last().unwrap().k, SECCOMP_RET_ALLOW);
}

#[test]
fn transfers_descriptor_over_socket_pair() {
    let (receiver, sender) = socket_pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    fd_transfer::send_fd(sender.as_raw_fd(), file.as_raw_fd()).unwrap();
    let received = receive_fd(&receiver).unwrap().unwrap();
    assert_ne!(received.as_raw_fd(), file.as_raw_fd());
    let received =
        unsafe { std::fs::File::from_raw_fd(std::os::fd::IntoRawFd::into_raw_fd(received)) };
    assert!(received.metadata().is_ok());
}

#[test]
fn receive_returns_none_when_sender_closes() {
    let (receiver, sender) = socket_pair().unwrap();
    drop(sender);
    assert!(receive_fd(&receiver).unwrap().is_none());
}
