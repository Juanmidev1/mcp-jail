use std::path::Path;

use super::*;
use crate::trace::parse_line;

fn syscall(action: &str, category: &str, target: &str, context: &str) -> TraceEvent {
    parse_line(&format!(
        r#"{{"ts_ms":1,"type":"syscall_event","action":"{action}","category":"{category}","syscall":"x","target":"{target}","pid":1,"mcp_context":"{context}"}}"#
    ))
    .unwrap()
}

fn session() -> Vec<TraceEvent> {
    let env_path = concat!("/w/.e", "nv");
    vec![
        parse_line(
            r#"{"ts_ms":0,"type":"session_start","command":["npx","srv"],"audit_only":false}"#,
        )
        .unwrap(),
        parse_line(r#"{"ts_ms":1,"type":"mcp_call","method":"tools/call","target":"read"}"#)
            .unwrap(),
        syscall("blocked", "fs", env_path, "tools/call:read"),
        syscall("blocked", "fs", env_path, "tools/call:read"),
        syscall("allowed", "net", "1.2.3.4:443", "tools/call:read"),
        syscall("blocked", "net", "5.6.7.8:80", "idle"),
        syscall("allowed", "net", "5.6.7.8:80", "idle"),
        syscall("allowed", "process", "/usr/bin/git", "idle"),
        parse_line(r#"{"ts_ms":2,"type":"session_end","exit_code":3}"#).unwrap(),
    ]
}

#[test]
fn summarizes_counts_and_targets() {
    let report = summarize(&session());
    assert_eq!(report.command, vec!["npx", "srv"]);
    assert_eq!(report.exit_code, Some(3));
    assert_eq!(report.mcp_calls, 1);
    assert_eq!(
        report.totals,
        ActionCounts {
            blocked: 3,
            audited: 0,
            allowed: 3
        }
    );
    assert_eq!(report.denied_files.len(), 1);
    assert_eq!(report.network.get("5.6.7.8:80"), Some(&Action::Blocked));
    assert_eq!(report.network.get("1.2.3.4:443"), Some(&Action::Allowed));
    assert_eq!(report.processes.len(), 1);
    let read_counts = report.contexts["tools/call:read"];
    assert_eq!(
        read_counts,
        ActionCounts {
            blocked: 2,
            audited: 0,
            allowed: 1
        }
    );
}

#[test]
fn renders_sections_and_context_table() {
    let text = render(&summarize(&session()), Path::new("t.jsonl"));
    assert!(text.contains("Session:   npx srv (exit 3)"));
    assert!(text.contains("Syscalls:  3 blocked, 0 audited, 3 allowed"));
    assert!(text.contains("Denied file access (1):"));
    assert!(text.contains("Network destinations (2):"));
    assert!(
        text.lines()
            .any(|line| line.trim_start().starts_with("tools/call:read"))
    );
}

#[test]
fn empty_trace_renders_without_panicking() {
    let text = render(&summarize(&[]), Path::new("t.jsonl"));
    assert!(text.contains("running or crashed"));
}
