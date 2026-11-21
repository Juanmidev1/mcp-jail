#[cfg(not(target_os = "linux"))]
compile_error!("mcp-jail requires Linux (Landlock LSM + seccomp-unotify)");

pub mod alert;
pub mod cli;
pub mod landlock;
pub mod policy;
pub mod proxy;
pub mod rpc;
pub mod sandbox;
pub mod seccomp;
pub mod supervisor;
pub mod trace;
