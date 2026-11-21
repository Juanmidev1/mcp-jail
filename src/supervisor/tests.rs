use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::paths::{is_path_only, is_write_intent, normalize_lexically, resolve};
use super::*;

#[test]
fn ioctl_numbers_match_kernel_headers() {
    assert_eq!(SECCOMP_IOCTL_NOTIF_RECV, libc::SECCOMP_IOCTL_NOTIF_RECV);
    assert_eq!(SECCOMP_IOCTL_NOTIF_SEND, libc::SECCOMP_IOCTL_NOTIF_SEND);
    assert_eq!(
        SECCOMP_IOCTL_NOTIF_ID_VALID,
        libc::SECCOMP_IOCTL_NOTIF_ID_VALID
    );
    assert_eq!(size_of::<libc::seccomp_notif>() as u64, SECCOMP_NOTIF_SIZE);
    assert_eq!(
        size_of::<libc::seccomp_notif_resp>() as u64,
        SECCOMP_NOTIF_RESP_SIZE
    );
}

#[test]
fn normalization_catches_traversal() {
    let env_file = concat!(".e", "nv");
    let traversal = format!("./src/../{env_file}");
    let resolved = resolve(Path::new(&traversal), Path::new("/work/project"), 7);
    assert_eq!(resolved, Path::new("/work/project").join(env_file));
    assert_eq!(
        normalize_lexically(Path::new("/../../etc/./hosts")),
        PathBuf::from("/etc/hosts")
    );
}

#[test]
fn proc_self_points_at_the_calling_process() {
    let resolved = resolve(Path::new("/proc/self/environ"), Path::new("/"), 1234);
    assert_eq!(resolved, PathBuf::from("/proc/1234/environ"));
    let resolved = resolve(Path::new("/proc/selfish"), Path::new("/"), 1234);
    assert_eq!(resolved, PathBuf::from("/proc/selfish"));
}

#[test]
fn open_flags_classify_write_intent() {
    assert!(!is_write_intent(libc::O_RDONLY as u64));
    assert!(is_write_intent(libc::O_WRONLY as u64));
    assert!(is_write_intent(libc::O_RDWR as u64));
    assert!(is_write_intent((libc::O_RDONLY | libc::O_CREAT) as u64));
    assert!(is_path_only((libc::O_PATH | libc::O_CLOEXEC) as u64));
}

fn sockaddr_bytes<T>(address: &T) -> Vec<u8> {
    let pointer = (address as *const T).cast::<u8>();
    unsafe { std::slice::from_raw_parts(pointer, size_of::<T>()) }.to_vec()
}

#[test]
fn parses_ipv4_and_ipv6_socket_addresses() {
    let mut v4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    v4.sin_family = libc::AF_INET as libc::sa_family_t;
    v4.sin_port = 443u16.to_be();
    v4.sin_addr.s_addr = u32::from_ne_bytes([140, 82, 121, 4]);
    let expected: SocketAddr = "140.82.121.4:443".parse().unwrap();
    assert_eq!(parse_socket_address(&sockaddr_bytes(&v4)), Some(expected));

    let mut v6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    v6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    v6.sin6_port = 8080u16.to_be();
    v6.sin6_addr.s6_addr[15] = 1;
    let expected: SocketAddr = "[::1]:8080".parse().unwrap();
    assert_eq!(parse_socket_address(&sockaddr_bytes(&v6)), Some(expected));
}

#[test]
fn ignores_unix_and_truncated_socket_addresses() {
    let mut unix: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    unix.sun_family = libc::AF_UNIX as libc::sa_family_t;
    assert_eq!(parse_socket_address(&sockaddr_bytes(&unix)), None);
    assert_eq!(parse_socket_address(&[2, 0, 1]), None);
}

#[test]
fn truncated_open_how_is_left_to_the_kernel() {
    let policy = crate::policy::Policy::build(
        crate::policy::PolicyFile::default(),
        &crate::cli::SandboxArgs::default(),
        None,
    );
    let mut inspector = Inspector::new(std::sync::Arc::new(policy));
    let open_how = [0u64; 3];
    let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
    request.pid = std::process::id();
    request.data.nr = libc::SYS_openat2 as i32;
    request.data.args[2] = open_how.as_ptr() as u64;
    request.data.args[3] = super::inspect::OPEN_HOW_SIZE_VER0 - 1;
    assert_eq!(inspector.evaluate(&request), None);

    // With a valid size the flags are read, then the null path fails closed
    request.data.args[3] = super::inspect::OPEN_HOW_SIZE_VER0;
    let verdict = inspector.evaluate(&request).unwrap();
    assert!(verdict.is_violation && verdict.target == "<unreadable>");
}
