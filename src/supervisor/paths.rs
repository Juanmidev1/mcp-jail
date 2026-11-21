use std::path::{Component, Path, PathBuf};

/// Joins `raw` onto `base`, folds `.`/`..` lexically and points /proc/self at the caller
pub fn resolve(raw: &Path, base: &Path, pid: u32) -> PathBuf {
    let normalized = normalize_lexically(&base.join(raw));
    let caller_proc = PathBuf::from(format!("/proc/{pid}"));
    for alias in ["/proc/self", "/proc/thread-self"] {
        if let Ok(rest) = normalized.strip_prefix(alias) {
            return caller_proc.join(rest);
        }
    }
    normalized
}

/// `path` must be absolute; `..` above the root stays at the root, as the kernel does
pub fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    normalized
}

/// Follows symlinks of the path, or of its parent when the file does not exist yet
pub fn canonicalize_lenient(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map_or_else(|_| path.to_path_buf(), |parent| parent.join(name)),
        _ => path.to_path_buf(),
    }
}

pub fn is_write_intent(flags: u64) -> bool {
    let flags = flags as libc::c_int;
    flags & libc::O_ACCMODE != libc::O_RDONLY || flags & (libc::O_CREAT | libc::O_TRUNC) != 0
}

pub fn is_create(flags: u64) -> bool {
    (flags as libc::c_int) & libc::O_CREAT != 0
}

/// Landlock does not check O_PATH opens, so they are only matched against deny patterns
pub fn is_path_only(flags: u64) -> bool {
    (flags as libc::c_int) & libc::O_PATH != 0
}
