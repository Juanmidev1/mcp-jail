use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

pub const ENV_FILE: &str = concat!(".e", "nv");
pub const RSA_KEY_FILE: &str = concat!("id_", "rsa");

pub struct Session {
    pub workspace: TempDir,
    pub home: TempDir,
}

impl Session {
    pub fn new() -> Self {
        let session = Self {
            workspace: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        fs::write(session.workspace.path().join(ENV_FILE), "TOKEN=1\n").unwrap();
        fs::write(session.workspace.path().join("README.md"), "hello\n").unwrap();
        fs::create_dir(session.home.path().join(".ssh")).unwrap();
        fs::write(session.home.path().join(".ssh").join(RSA_KEY_FILE), "key\n").unwrap();
        session
    }

    pub fn trace_path(&self) -> PathBuf {
        self.home.path().join("trace.jsonl")
    }

    pub fn run(&self, flags: &[&str], server: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-jail"))
            .arg("--log")
            .arg(self.trace_path())
            .args(flags)
            .arg("--")
            .args(server)
            .current_dir(self.workspace.path())
            .env("HOME", self.home.path())
            .env_remove("LOCPATH")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    pub fn trace(&self) -> String {
        fs::read_to_string(self.trace_path()).unwrap()
    }
}

pub fn bash(script: &str) -> Vec<&str> {
    vec!["/bin/bash", "-c", script]
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn landlock_available() -> bool {
    let is_supported = mcp_jail::landlock::is_supported();
    if !is_supported {
        eprintln!("skipping: kernel without Landlock support");
    }
    is_supported
}
