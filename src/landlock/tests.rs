use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use super::*;
use crate::cli::SandboxArgs;
use crate::policy::{PolicyFile, SYSTEM_RO_PATHS};

fn policy_with(ro: Vec<PathBuf>, rw: Vec<PathBuf>) -> Policy {
    let mut policy = Policy::build(PolicyFile::default(), &SandboxArgs::default(), None);
    policy.ro = SYSTEM_RO_PATHS
        .iter()
        .map(PathBuf::from)
        .chain(ro)
        .collect();
    policy.rw = rw;
    policy
}

fn run_sandboxed(policy: &Policy, script: &str) -> Output {
    let mut ruleset = Some(prepare_ruleset(policy).unwrap());
    let mut command = Command::new("/bin/sh");
    command.args(["-c", script]);
    unsafe {
        command.pre_exec(move || {
            let ruleset = ruleset.take().ok_or(std::io::ErrorKind::Other)?;
            match enforce(ruleset) {
                Ok(LandlockStatus::Enforced) => Ok(()),
                _ => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            }
        });
    }
    command.output().unwrap()
}

#[test]
fn blocks_reads_outside_allowed_paths() {
    if !is_supported() {
        eprintln!("skipping: kernel without Landlock support");
        return;
    }
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(allowed.path().join("ok.txt"), "visible").unwrap();
    fs::write(outside.path().join("secret.txt"), "hidden").unwrap();
    let policy = policy_with(vec![], vec![allowed.path().to_path_buf()]);
    let script = format!(
        "cat {0}/ok.txt && cat {1}/secret.txt",
        allowed.path().display(),
        outside.path().display()
    );
    let output = run_sandboxed(&policy, &script);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible");
    assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
    assert!(!output.status.success());
}

#[test]
fn read_only_paths_reject_writes() {
    if !is_supported() {
        eprintln!("skipping: kernel without Landlock support");
        return;
    }
    let read_only = tempfile::tempdir().unwrap();
    let writable = tempfile::tempdir().unwrap();
    let policy = policy_with(vec![read_only.path().into()], vec![writable.path().into()]);
    let script = format!(
        "echo a > {0}/w.txt && ls {1} && echo b > {1}/r.txt",
        writable.path().display(),
        read_only.path().display()
    );
    let output = run_sandboxed(&policy, &script);
    assert!(writable.path().join("w.txt").exists());
    assert!(!read_only.path().join("r.txt").exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
}

#[test]
fn missing_paths_are_skipped() {
    let missing = PathBuf::from("/nonexistent/mcp-jail-test-path");
    let policy = policy_with(vec![missing.clone()], vec![missing]);
    assert!(prepare_ruleset(&policy).is_ok());
}
