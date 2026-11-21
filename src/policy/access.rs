use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::Policy;

impl Policy {
    /// Makes `ro`/`rw` absolute and canonical, dropping paths missing on disk exactly like
    /// the Landlock ruleset does, so userspace checks see the same allowed set
    pub fn resolve_paths(&mut self, cwd: &Path) {
        self.ro = canonical_existing(&self.ro, cwd);
        self.rw = canonical_existing(&self.rw, cwd);
    }

    /// MCP clients often start servers with cwd set to `/` or `$HOME`, which would turn the
    /// default `.` grant into access to the whole system or home; such grants are removed
    /// and returned so the caller can warn. Call after `resolve_paths`
    pub fn drop_broad_grants(&mut self, home: Option<&Path>) -> Vec<PathBuf> {
        let home = home.and_then(|home| home.canonicalize().ok());
        let is_broad = |path: &PathBuf| path == Path::new("/") || home.as_ref() == Some(path);
        let dropped: Vec<PathBuf> = self
            .ro
            .iter()
            .chain(&self.rw)
            .filter(|p| is_broad(p))
            .cloned()
            .collect();
        self.ro.retain(|path| !is_broad(path));
        self.rw.retain(|path| !is_broad(path));
        dropped
    }

    /// `path` must be absolute and canonical; mirrors the Landlock read/write split
    pub fn is_path_allowed(&self, path: &Path, is_write: bool) -> bool {
        let is_under = |roots: &[PathBuf]| roots.iter().any(|root| path.starts_with(root));
        is_under(&self.rw) || (!is_write && is_under(&self.ro))
    }

    /// `path` must be absolute and already normalized
    pub fn is_denied_path(&self, path: &Path) -> bool {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        self.deny_patterns.iter().any(|pattern| {
            if pattern.starts_with('/') {
                path.starts_with(pattern)
            } else {
                matches_glob(pattern, file_name)
            }
        })
    }

    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        if ip.is_loopback() {
            return true;
        }
        if !self.deny_net && self.allow_ips.is_empty() {
            return true;
        }
        self.allow_ips
            .iter()
            .any(|allowed| allowed.to_canonical() == ip)
    }
}

fn canonical_existing(paths: &[PathBuf], cwd: &Path) -> Vec<PathBuf> {
    let mut resolved: Vec<PathBuf> = Vec::new();
    for path in paths {
        if let Ok(canonical) = cwd.join(path).canonicalize()
            && !resolved.contains(&canonical)
        {
            resolved.push(canonical);
        }
    }
    resolved
}

/// Minimal glob supporting `*` wildcards, matched against a file name
pub fn matches_glob(pattern: &str, name: &str) -> bool {
    let Some((prefix, rest)) = pattern.split_once('*') else {
        return pattern == name;
    };
    let Some(tail) = name.strip_prefix(prefix) else {
        return false;
    };
    (0..=tail.len())
        .filter(|&index| tail.is_char_boundary(index))
        .any(|index| matches_glob(rest, &tail[index..]))
}
