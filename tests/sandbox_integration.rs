mod common;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use common::{ENV_FILE, RSA_KEY_FILE, Session, bash, landlock_available, stderr};

const TOOL_CALL: &str =
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_secrets"}}"#;

#[test]
fn blocks_secrets_and_tags_them_with_the_active_tool_call() {
    let session = Session::new();
    let script = format!(
        "read -r request; cat README.md; cat ./src/../{ENV_FILE} || echo env-denied; \
         cat ~/.ssh/{RSA_KEY_FILE} || echo key-denied; echo '{{\"id\":1,\"result\":{{}}}}'"
    );
    let output = session.run(&[], &bash(&script), &format!("{TOOL_CALL}\n"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("hello\n"), "stdout: {stdout}");
    assert!(stdout.contains("env-denied") && stdout.contains("key-denied"));
    assert!(stdout.ends_with("{\"id\":1,\"result\":{}}\n"));
    let alerts = stderr(&output);
    assert!(
        alerts.contains("[tools/call: read_secrets] BLOCKED openat("),
        "{alerts}"
    );
    let trace = session.trace();
    assert!(trace.contains(r#""type":"mcp_call","method":"tools/call","target":"read_secrets""#));
    assert!(trace.contains(&format!("/{ENV_FILE}\",")));
    assert!(trace.contains(r#""mcp_context":"tools/call:read_secrets""#));
    assert!(trace.contains(r#""type":"session_end","exit_code":0"#));
}

#[test]
fn allow_env_lets_env_files_through() {
    let session = Session::new();
    let output = session.run(&["--allow-env"], &bash(&format!("cat {ENV_FILE}")), "");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "TOKEN=1\n");
}

#[test]
fn landlock_blocks_paths_outside_the_policy() {
    if !landlock_available() {
        return;
    }
    let outside = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let secret = outside.path().join("notes.txt");
    fs::write(&secret, "private").unwrap();
    let session = Session::new();
    let script = format!("cat {} || echo denied", secret.display());
    let output = session.run(&["--quiet"], &bash(&script), "");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "denied\n");
    assert!(
        !stderr(&output).contains("BLOCKED"),
        "--quiet must silence alerts"
    );
    assert!(session.trace().contains(r#""action":"blocked""#));
}

#[test]
fn missing_files_outside_the_policy_fail_with_enoent_and_no_alert() {
    let outside = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let existing = outside.path().join("present.conf");
    fs::write(&existing, "x").unwrap();
    let session = Session::new();
    let script = format!(
        "cat {0}/absent.conf; cat {1}",
        outside.path().display(),
        existing.display()
    );
    let alerts = stderr(&session.run(&[], &bash(&script), ""));
    assert!(
        alerts.contains("absent.conf: No such file or directory"),
        "{alerts}"
    );
    assert!(!alerts.contains("absent.conf\") -> EACCES"), "{alerts}");
    assert!(
        alerts.contains("present.conf: Permission denied"),
        "{alerts}"
    );
    assert!(alerts.contains("present.conf\") -> EACCES"), "{alerts}");
}

#[test]
fn deny_net_blocks_external_connections_but_not_loopback() {
    let session = Session::new();
    let script = "exec 3<>/dev/tcp/192.0.2.1/80 || echo net-denied; \
                  (exec 3<>/dev/tcp/127.0.0.1/9) 2>/dev/null; echo done";
    let output = session.run(&["--deny-net"], &bash(script), "");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("net-denied") && stdout.contains("done"),
        "{stdout}"
    );
    assert!(stderr(&output).contains("BLOCKED connect(192.0.2.1:80) -> EACCES"));
    let trace = session.trace();
    let mut syscall_events = trace.lines().filter(|line| line.contains("syscall_event"));
    assert!(!syscall_events.any(|line| line.contains("127.0.0.1")));
}

#[test]
fn allow_net_permits_only_listed_ips() {
    let session = Session::new();
    let script = "exec 3<>/dev/tcp/192.0.2.2/80 || echo second-denied";
    let output = session.run(&["--allow-net", "192.0.2.1"], &bash(script), "");
    assert!(String::from_utf8_lossy(&output.stdout).contains("second-denied"));
}

#[test]
fn deny_exec_blocks_child_processes_after_startup() {
    let session = Session::new();
    let output = session.run(&["--deny-exec"], &bash("/bin/true || echo exec-denied"), "");
    assert!(String::from_utf8_lossy(&output.stdout).contains("exec-denied"));
    assert!(stderr(&output).contains("BLOCKED execve(\"/bin/true\") -> EACCES"));
}

#[test]
fn audit_only_records_violations_without_blocking() {
    let session = Session::new();
    let output = session.run(&["--audit-only"], &bash(&format!("cat {ENV_FILE}")), "");
    assert_eq!(String::from_utf8_lossy(&output.stdout), "TOKEN=1\n");
    assert!(stderr(&output).contains("AUDIT openat("));
    let trace = session.trace();
    assert!(trace.contains(r#""audit_only":true"#) && trace.contains(r#""action":"audited""#));
}

#[test]
fn propagates_the_server_exit_code() {
    let session = Session::new();
    let output = session.run(&[], &bash("exit 7"), "");
    assert_eq!(output.status.code(), Some(7));
    assert!(session.trace().contains(r#""exit_code":7"#));
}

#[test]
fn stdin_eof_kills_servers_that_ignore_it_after_the_grace_period() {
    let session = Session::new();
    let started = Instant::now();
    let output = session.run(&[], &bash("sleep 30 & trap '' TERM; sleep 30"), "");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(10),
        "{elapsed:?}"
    );
    assert_eq!(output.status.code(), Some(128 + 9));
}

#[test]
fn missing_command_fails_cleanly() {
    let session = Session::new();
    let output = session.run(&[], &["mcp-jail-no-such-binary"], "");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("command not found in PATH"));
    assert!(Path::new(&session.trace_path()).exists());
}
