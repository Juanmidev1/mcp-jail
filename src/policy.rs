mod access;
mod file;

use std::error::Error;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::cli::SandboxArgs;
pub use access::matches_glob;
use file::load_policy_file;
pub use file::{
    DEFAULT_CONFIG_FILE, FilesystemSection, NetworkSection, PolicyFile, ProcessSection,
};

const DEFAULT_TRACE_FILE: &str = ".cache/mcp-jail/latest.jsonl";

// /proc/self would resolve to the supervisor's own pid when opened before fork, so the
// whole /proc tree is granted read-only instead; node also probes cpu and cgroup info
pub const SYSTEM_RO_PATHS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ssl",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/nsswitch.conf",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/etc/locale.alias",
    "/proc",
    "/sys/devices/system/cpu",
    "/sys/fs/cgroup",
    "/dev/urandom",
];

// /dev/null is opened O_RDWR by most runtimes, so it cannot be read-only
pub const SYSTEM_RW_PATHS: &[&str] = &[".", "/tmp", "/dev/null"];

// npx and uvx write into their caches on first run, so they need read-write access
pub const HOME_CACHE_DIRS: &[&str] = &[
    ".npm",
    ".nvm",
    ".local/share/uv",
    ".cache/uv",
    ".cargo",
    ".rustup",
    ".pyenv",
];

pub const SECRET_FILE_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    // Package manager and network credential stores that usually hold auth tokens
    ".npmrc",
    ".pypirc",
    ".netrc",
];
const ENV_FILE_PATTERNS: &[&str] = &[".env", ".env.*"];
const HOME_SECRET_DIRS: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".docker"];

#[derive(Debug, Clone)]
pub struct Policy {
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub deny_patterns: Vec<String>,
    pub deny_net: bool,
    pub allow_ips: Vec<IpAddr>,
    pub deny_exec: bool,
    pub audit_only: bool,
    /// Keeps deny_patterns blocking in audit mode; `profile` sets it so secrets are
    /// never exposed while the session is observed
    pub enforce_deny_patterns: bool,
    pub quiet: bool,
    pub log_path: PathBuf,
}

impl Policy {
    pub fn load(args: &SandboxArgs) -> Result<Self, Box<dyn Error>> {
        let file = load_policy_file(args.config.as_deref())?;
        let home = home_dir();
        Ok(Self::build(file, args, home.as_deref()))
    }

    // Path lists are additive (defaults + TOML + CLI) because a generated profile only
    // lists paths outside the defaults; scalar flags from the CLI can only tighten
    pub fn build(file: PolicyFile, args: &SandboxArgs, home: Option<&Path>) -> Self {
        let allow_env = args.allow_env || file.filesystem.allow_env;
        let mut allow_ips = file.network.allow_ips;
        allow_ips.extend(&args.allow_net);
        Self {
            ro: merge_paths(default_ro_paths(), &file.filesystem.ro, &args.ro),
            rw: merge_paths(default_rw_paths(home), &file.filesystem.rw, &args.rw),
            deny_patterns: build_deny_patterns(file.filesystem.deny_patterns, home, allow_env),
            deny_net: args.deny_net || file.network.deny,
            allow_ips,
            deny_exec: args.deny_exec || file.process.deny_exec,
            audit_only: args.audit_only,
            enforce_deny_patterns: false,
            quiet: args.quiet,
            log_path: args.log.clone().unwrap_or_else(|| default_trace_path(home)),
        }
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub fn default_trace_path(home: Option<&Path>) -> PathBuf {
    home.map_or_else(std::env::temp_dir, Path::to_path_buf)
        .join(DEFAULT_TRACE_FILE)
}

// glibc reads locale data from LOCPATH when set (VS Code snap terminals export it), so
// those public directories are granted read-only to avoid spurious locale alerts
fn default_ro_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = SYSTEM_RO_PATHS.iter().map(PathBuf::from).collect();
    if let Some(locale_path) = std::env::var_os("LOCPATH") {
        paths.extend(std::env::split_paths(&locale_path).filter(|dir| dir.is_absolute()));
    }
    paths
}

fn default_rw_paths(home: Option<&Path>) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = SYSTEM_RW_PATHS.iter().map(PathBuf::from).collect();
    if let Some(home) = home {
        let caches = HOME_CACHE_DIRS.iter().map(|dir| home.join(dir));
        paths.extend(caches.filter(|dir| dir.exists()));
    }
    paths
}

fn merge_paths(
    defaults: Vec<PathBuf>,
    from_file: &[PathBuf],
    from_cli: &[PathBuf],
) -> Vec<PathBuf> {
    let mut merged = defaults;
    for path in from_file.iter().chain(from_cli) {
        if !merged.contains(path) {
            merged.push(path.clone());
        }
    }
    merged
}

// Home secret directories are always denied, even when the TOML overrides the file patterns
fn build_deny_patterns(
    custom: Option<Vec<String>>,
    home: Option<&Path>,
    allow_env: bool,
) -> Vec<String> {
    let file_patterns =
        custom.unwrap_or_else(|| SECRET_FILE_PATTERNS.iter().map(|p| p.to_string()).collect());
    let mut patterns: Vec<String> = file_patterns
        .into_iter()
        .filter(|pattern| !(allow_env && ENV_FILE_PATTERNS.contains(&pattern.as_str())))
        .collect();
    if let Some(home) = home {
        let dirs = HOME_SECRET_DIRS.iter().map(|dir| home.join(dir));
        patterns.extend(dirs.map(|dir| dir.to_string_lossy().into_owned()));
    }
    patterns
}

#[cfg(test)]
mod tests;
