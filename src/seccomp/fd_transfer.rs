use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

/// Large enough and aligned for one SCM_RIGHTS control message carrying a single fd
#[repr(C, align(8))]
struct ControlBuffer([u8; 64]);

const FD_SIZE: libc::c_uint = mem::size_of::<libc::c_int>() as libc::c_uint;

/// Returns `(supervisor_end, child_end)`, both close-on-exec
pub fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [-1; 2];
    let kind = libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC;
    if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Async-signal-safe: uses only stack memory and a single `sendmsg`
pub fn send_fd(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = ControlBuffer([0; 64]);
    let mut message = message_header(&mut iov, &mut control);
    unsafe {
        // CMSG_FIRSTHDR returns null unless msg_controllen already covers one header
        message.msg_controllen = libc::CMSG_SPACE(FD_SIZE) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(FD_SIZE) as _;
        ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
        if libc::sendmsg(socket, &message, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Returns `Ok(None)` when the child closed its end without sending a descriptor
pub fn receive_fd(socket: &OwnedFd) -> io::Result<Option<OwnedFd>> {
    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = ControlBuffer([0; 64]);
    let mut message = message_header(&mut iov, &mut control);
    message.msg_controllen = mem::size_of::<ControlBuffer>() as _;
    let received = receive_retrying(socket, &mut message)?;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if received == 0 || header.is_null() || (*header).cmsg_type != libc::SCM_RIGHTS {
            return Ok(None);
        }
        let fd = ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>());
        Ok(Some(OwnedFd::from_raw_fd(fd)))
    }
}

/// Giving up on EINTR would leave the child's execve waiting forever for a supervisor
fn receive_retrying(socket: &OwnedFd, message: &mut libc::msghdr) -> io::Result<isize> {
    loop {
        let received =
            unsafe { libc::recvmsg(socket.as_raw_fd(), message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            return Ok(received);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn message_header(iov: &mut libc::iovec, control: &mut ControlBuffer) -> libc::msghdr {
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast();
    message
}
