use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Seek, SeekFrom};
use std::path::Path;
use std::thread;
use std::time::Duration;

use colored::Colorize;

use crate::alert::format_syscall_event;
use crate::trace::{Action, Category, EventKind, TraceEvent, parse_line};

const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MS_PER_SECOND: u64 = 1000;

/// Incremental reader that restarts when a new session truncates the trace
#[derive(Debug, Default)]
pub struct TraceFollower {
    offset: u64,
    partial_line: String,
    session_header: String,
}

impl TraceFollower {
    /// Returns events appended since the last poll; a missing file yields nothing yet
    pub fn poll(&mut self, path: &Path) -> io::Result<Vec<TraceEvent>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        // A new session may outgrow the old offset before the next poll, so its unique
        // session_start line is compared too, not just the file length
        let header = read_first_line(&mut file)?;
        if file.metadata()?.len() < self.offset || header != self.session_header {
            self.offset = 0;
            self.partial_line.clear();
            self.session_header = header;
        }
        file.seek(SeekFrom::Start(self.offset))?;
        let mut appended = String::new();
        self.offset += file.read_to_string(&mut appended)? as u64;
        self.partial_line.push_str(&appended);
        // A line without its newline is still being written; keep it for the next poll
        let complete_length = self.partial_line.rfind('\n').map_or(0, |index| index + 1);
        let complete: String = self.partial_line.drain(..complete_length).collect();
        Ok(complete.lines().filter_map(parse_line).collect())
    }
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    colored::control::set_override(io::stdout().is_terminal());
    eprintln!("mcp-jail: following {} (Ctrl-C to stop)", path.display());
    let mut follower = TraceFollower::default();
    loop {
        for event in follower.poll(path)? {
            if let Some(line) = format_event(&event) {
                println!("{} {line}", format_clock(event.ts_ms).dimmed());
            }
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Allowed file opens are only recorded in audit sessions and would drown the monitor
pub fn format_event(event: &TraceEvent) -> Option<String> {
    let line = match &event.kind {
        EventKind::SessionStart {
            command,
            audit_only,
        } => {
            let mode = if *audit_only { " (audit-only)" } else { "" };
            format!("session started: {}{mode}", command.join(" ")).bold()
        }
        EventKind::McpCall { method, target } => {
            format!("-> {method} {target}").trim_end().dimmed()
        }
        EventKind::SyscallEvent {
            action,
            category,
            syscall,
            target,
            mcp_context,
            ..
        } => {
            let is_routine = *action == Action::Allowed && *category == Category::Fs;
            return (!is_routine)
                .then(|| format_syscall_event(*action, *category, syscall, target, mcp_context));
        }
        EventKind::SessionEnd { exit_code } => format!("session ended (exit {exit_code})").bold(),
    };
    Some(line.to_string())
}

fn read_first_line(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut line = String::new();
    BufReader::new(&mut *file).read_line(&mut line)?;
    Ok(if line.ends_with('\n') {
        line
    } else {
        String::new()
    })
}

/// Local wall-clock time as HH:MM:SS
fn format_clock(ts_ms: u64) -> String {
    let seconds = libc::time_t::try_from(ts_ms / MS_PER_SECOND).unwrap_or_default();
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&seconds, &mut local) }.is_null() {
        return "--:--:--".to_string();
    }
    format!(
        "{:02}:{:02}:{:02}",
        local.tm_hour, local.tm_min, local.tm_sec
    )
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::*;

    const START: &str =
        r#"{"ts_ms":1,"type":"session_start","command":["srv"],"audit_only":false}"#;
    const END: &str = r#"{"ts_ms":2,"type":"session_end","exit_code":0}"#;

    #[test]
    fn follows_appends_partial_lines_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let mut follower = TraceFollower::default();
        assert!(follower.poll(&path).unwrap().is_empty());

        std::fs::write(&path, format!("{START}\n{}", &END[..10])).unwrap();
        assert_eq!(follower.poll(&path).unwrap().len(), 1);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "{}", &END[10..]).unwrap();
        let events = follower.poll(&path).unwrap();
        assert_eq!(events[0].kind, EventKind::SessionEnd { exit_code: 0 });

        let newer_start = START.replace(r#""ts_ms":1"#, r#""ts_ms":9"#);
        std::fs::write(&path, format!("{newer_start}\n{END}\n{END}\n")).unwrap();
        assert_eq!(follower.poll(&path).unwrap().len(), 3);
    }

    #[test]
    fn hides_allowed_file_opens_only() {
        colored::control::set_override(false);
        let event = |action: &str, category: &str| {
            parse_line(&format!(
                r#"{{"ts_ms":1,"type":"syscall_event","action":"{action}","category":"{category}","syscall":"openat","target":"/x","pid":1,"mcp_context":"idle"}}"#
            ))
            .unwrap()
        };
        assert!(format_event(&event("allowed", "fs")).is_none());
        assert!(
            format_event(&event("blocked", "fs"))
                .unwrap()
                .contains("BLOCKED")
        );
        assert!(
            format_event(&event("allowed", "net"))
                .unwrap()
                .contains("ALLOWED")
        );
    }
}
