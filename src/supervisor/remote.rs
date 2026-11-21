use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

const MAX_PATH_BYTES: usize = libc::PATH_MAX as usize;
const FALLBACK_PAGE_SIZE: usize = 4096;

/// Reads exactly `length` bytes from the target process, or nothing
pub fn read_bytes(pid: u32, address: u64, length: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; length];
    let read = read_into(pid, address, &mut buffer)?;
    (read == length).then_some(buffer)
}

pub fn read_u64(pid: u32, address: u64) -> Option<u64> {
    let bytes = read_bytes(pid, address, size_of::<u64>())?;
    Some(u64::from_ne_bytes(bytes.try_into().ok()?))
}

/// process_vm_readv never splits a remote iovec, so a string ending just before an
/// unmapped page would fail as a whole unless reads stop at page boundaries
pub fn read_c_string(pid: u32, address: u64) -> Option<OsString> {
    let page_size = page_size();
    let mut bytes = Vec::new();
    let mut cursor = address;
    while bytes.len() < MAX_PATH_BYTES {
        let page_offset = usize::try_from(cursor % page_size as u64).ok()?;
        let chunk_length = (page_size - page_offset).min(MAX_PATH_BYTES - bytes.len());
        let mut chunk = vec![0u8; chunk_length];
        let read = read_into(pid, cursor, &mut chunk).filter(|&read| read > 0)?;
        if let Some(end) = chunk[..read].iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Some(OsString::from_vec(bytes));
        }
        bytes.extend_from_slice(&chunk[..read]);
        cursor = cursor.checked_add(read as u64)?;
    }
    None
}

/// Directory a relative path is resolved against: the cwd for AT_FDCWD, else `dirfd`
pub fn directory_path(pid: u32, dirfd: i32) -> Option<PathBuf> {
    let link = if dirfd == libc::AT_FDCWD {
        format!("/proc/{pid}/cwd")
    } else {
        format!("/proc/{pid}/fd/{dirfd}")
    };
    std::fs::read_link(link).ok()
}

fn read_into(pid: u32, address: u64, buffer: &mut [u8]) -> Option<usize> {
    let local = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let pid = libc::pid_t::try_from(pid).ok()?;
    let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    usize::try_from(read).ok()
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|&size| size > 0)
        .unwrap_or(FALLBACK_PAGE_SIZE)
}
