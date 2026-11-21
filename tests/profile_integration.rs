mod common;

use std::fs;

use common::{Session, bash, stderr};

/// Uses only bash builtins so the observed session performs no child exec
const SERVER_SCRIPT: &str = "read -r settings < ~/.config/tool/settings.json && echo saved > ~/.cache/tool/state && echo ok";

fn prepare_tool_dirs(session: &Session) {
    let home = session.home.path();
    fs::create_dir_all(home.join(".config/tool")).unwrap();
    fs::write(home.join(".config/tool/settings.json"), "{}\n").unwrap();
    fs::create_dir_all(home.join(".cache/tool")).unwrap();
}

fn assert_generated_policy(session: &Session) {
    let policy = fs::read_to_string(session.workspace.path().join("mcp-jail.toml")).unwrap();
    let home = session.home.path().canonicalize().unwrap();
    assert!(
        policy.contains(&format!("{}/.config/tool", home.display())),
        "{policy}"
    );
    assert!(
        policy.contains(&format!("{}/.cache/tool", home.display())),
        "{policy}"
    );
    assert!(
        policy.contains("deny = true") && policy.contains("deny_exec = true"),
        "{policy}"
    );
}

#[test]
fn generated_profile_runs_cleanly_under_strict_enforcement() {
    let session = Session::new();
    prepare_tool_dirs(&session);

    let strict = session.run(&[], &bash(SERVER_SCRIPT), "");
    assert!(
        !String::from_utf8_lossy(&strict.stdout).contains("ok"),
        "home must be blocked first"
    );

    let profiled = session.run_subcommand("profile", &bash(SERVER_SCRIPT));
    assert!(String::from_utf8_lossy(&profiled.stdout).contains("ok"));
    assert!(stderr(&profiled).contains("wrote"), "{}", stderr(&profiled));
    assert_generated_policy(&session);

    let enforced = session.run(&[], &bash(SERVER_SCRIPT), "");
    assert_eq!(String::from_utf8_lossy(&enforced.stdout), "ok\n");
    assert!(
        !stderr(&enforced).contains("BLOCKED"),
        "{}",
        stderr(&enforced)
    );
}

#[test]
fn profile_keeps_secrets_blocked_while_auditing_the_rest() {
    let session = Session::new();
    let script = concat!(
        "cat .e",
        "nv || echo secret-denied; cat ~/.ssh/known_hosts 2>&1 || true"
    );
    let output = session.run_subcommand("profile", &bash(script));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("secret-denied") && !stdout.contains("TOKEN"),
        "{stdout}"
    );
    assert!(
        stderr(&output).contains("BLOCKED openat("),
        "{}",
        stderr(&output)
    );
}

#[test]
fn report_summarizes_the_last_session() {
    let session = Session::new();
    let script = concat!("cat .e", "nv; exit 4");
    session.run(&[], &bash(script), "");
    let output = session.run_subcommand("report", &[]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("(exit 4)"), "{text}");
    assert!(text.contains("Denied file access ("), "{text}");
    assert!(text.contains(concat!("/.e", "nv\n")), "{text}");
    assert!(text.contains("CONTEXT"), "{text}");
}
