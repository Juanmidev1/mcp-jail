#[cfg(not(target_os = "linux"))]
compile_error!("mcp-jail requires Linux (Landlock LSM + seccomp-unotify)");

pub mod cli;
pub mod policy;
pub mod trace;
