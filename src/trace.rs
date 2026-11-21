use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allowed,
    Blocked,
    /// Would have been blocked, but the session runs in audit-only mode
    Audited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Fs,
    Net,
    Process,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    SessionStart {
        command: Vec<String>,
        audit_only: bool,
    },
    McpCall {
        method: String,
        target: String,
    },
    SyscallEvent {
        action: Action,
        category: Category,
        syscall: String,
        target: String,
        pid: i32,
        mcp_context: String,
    },
    SessionEnd {
        exit_code: i32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub ts_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Thread-safe `.jsonl` writer; every event is flushed immediately so `tail` sees it live
pub struct Tracer {
    file: Mutex<File>,
}

impl Tracer {
    /// Truncates `path` so each session starts a fresh trace
    pub fn create(path: &Path) -> Result<Self, Box<dyn Error>> {
        if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create trace directory {}: {e}", parent.display()))?;
        }
        let file = File::create(path)
            .map_err(|e| format!("cannot create trace file {}: {e}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn record(&self, kind: EventKind) -> io::Result<()> {
        let event = TraceEvent {
            ts_ms: now_ms(),
            kind,
        };
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("trace writer lock poisoned"))?;
        file.write_all(line.as_bytes())
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

pub fn parse_line(line: &str) -> Option<TraceEvent> {
    serde_json::from_str(line).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_syscall_event_with_spec_schema() {
        let event = TraceEvent {
            ts_ms: 7,
            kind: EventKind::SyscallEvent {
                action: Action::Blocked,
                category: Category::Fs,
                syscall: "openat".into(),
                target: "/w/secret".into(),
                pid: 42,
                mcp_context: "tools/call:read_file".into(),
            },
        };
        let json: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "syscall_event");
        assert_eq!(json["action"], "blocked");
        assert_eq!(json["category"], "fs");
        assert_eq!(json["ts_ms"], 7);
    }

    #[test]
    fn tracer_writes_parseable_lines_and_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/trace.jsonl");
        let tracer = Tracer::create(&path).unwrap();
        tracer
            .record(EventKind::SessionEnd { exit_code: 3 })
            .unwrap();
        tracer
            .record(EventKind::SessionEnd { exit_code: 4 })
            .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        let events: Vec<_> = text.lines().filter_map(parse_line).collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].kind, EventKind::SessionEnd { exit_code: 4 });

        Tracer::create(&path).unwrap();
        assert!(fs::read_to_string(&path).unwrap().is_empty());
    }
}
