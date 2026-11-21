use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write;
use std::path::Path;

use crate::trace::{Action, Category, EventKind, TraceEvent, read_events};

const CONTEXT_COLUMN_WIDTH: usize = 40;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ActionCounts {
    pub blocked: usize,
    pub audited: usize,
    pub allowed: usize,
}

impl ActionCounts {
    fn add(&mut self, action: Action) {
        match action {
            Action::Blocked => self.blocked += 1,
            Action::Audited => self.audited += 1,
            Action::Allowed => self.allowed += 1,
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub command: Vec<String>,
    pub is_audit_only: bool,
    pub exit_code: Option<i32>,
    pub mcp_calls: usize,
    pub totals: ActionCounts,
    pub denied_files: BTreeSet<String>,
    /// Destination -> strongest action seen (blocked wins over allowed)
    pub network: BTreeMap<String, Action>,
    pub processes: BTreeMap<String, Action>,
    pub contexts: BTreeMap<String, ActionCounts>,
}

pub fn run(path: &Path) -> Result<(), Box<dyn Error>> {
    print!("{}", render(&summarize(&read_events(path)?), path));
    Ok(())
}

pub fn summarize(events: &[TraceEvent]) -> Report {
    let mut report = Report::default();
    for event in events {
        match &event.kind {
            EventKind::SessionStart {
                command,
                audit_only,
            } => {
                report.command.clone_from(command);
                report.is_audit_only = *audit_only;
            }
            EventKind::McpCall { .. } => report.mcp_calls += 1,
            EventKind::SyscallEvent {
                action,
                category,
                target,
                mcp_context,
                ..
            } => {
                record_syscall(&mut report, *action, *category, target, mcp_context);
            }
            EventKind::SessionEnd { exit_code } => report.exit_code = Some(*exit_code),
        }
    }
    report
}

fn record_syscall(
    report: &mut Report,
    action: Action,
    category: Category,
    target: &str,
    context: &str,
) {
    report.totals.add(action);
    report
        .contexts
        .entry(context.to_string())
        .or_default()
        .add(action);
    match category {
        Category::Fs if action != Action::Allowed => {
            report.denied_files.insert(target.to_string());
        }
        Category::Fs => {}
        Category::Net => record_strongest(&mut report.network, target, action),
        Category::Process => record_strongest(&mut report.processes, target, action),
    }
}

/// A destination that was blocked once stays reported as blocked
fn record_strongest(targets: &mut BTreeMap<String, Action>, target: &str, action: Action) {
    let recorded = targets.entry(target.to_string()).or_insert(action);
    if *recorded != Action::Blocked {
        *recorded = action;
    }
}

/// Writing into a String cannot fail, so the fmt::Result values are discarded
pub fn render(report: &Report, path: &Path) -> String {
    let mut out = String::new();
    render_header(&mut out, report, path);
    render_set(&mut out, "Denied file access", report.denied_files.iter());
    render_map(&mut out, "Network destinations", &report.network);
    render_map(&mut out, "Child processes", &report.processes);
    render_contexts(&mut out, &report.contexts);
    out
}

fn render_header(out: &mut String, report: &Report, path: &Path) {
    let mode = if report.is_audit_only {
        ", audit-only"
    } else {
        ""
    };
    let exit = report.exit_code.map_or_else(
        || "running or crashed".to_string(),
        |code| format!("exit {code}"),
    );
    let totals = report.totals;
    let _ = writeln!(out, "mcp-jail report: {}", path.display());
    let _ = writeln!(
        out,
        "Session:   {} ({exit}{mode})",
        report.command.join(" ")
    );
    let _ = writeln!(out, "MCP calls: {}", report.mcp_calls);
    let _ = writeln!(
        out,
        "Syscalls:  {} blocked, {} audited, {} allowed",
        totals.blocked, totals.audited, totals.allowed
    );
}

fn render_set<'a>(out: &mut String, title: &str, items: impl ExactSizeIterator<Item = &'a String>) {
    let _ = writeln!(out, "\n{title} ({}):", items.len());
    for item in items {
        let _ = writeln!(out, "  {item}");
    }
}

fn render_map(out: &mut String, title: &str, items: &BTreeMap<String, Action>) {
    let _ = writeln!(out, "\n{title} ({}):", items.len());
    for (target, action) in items {
        let _ = writeln!(
            out,
            "  {target:<CONTEXT_COLUMN_WIDTH$} {}",
            action_label(*action)
        );
    }
}

fn render_contexts(out: &mut String, contexts: &BTreeMap<String, ActionCounts>) {
    let _ = writeln!(out, "\nPer MCP context:");
    let _ = writeln!(
        out,
        "  {:<CONTEXT_COLUMN_WIDTH$} {:>8} {:>8} {:>8}",
        "CONTEXT", "BLOCKED", "AUDITED", "ALLOWED"
    );
    for (context, counts) in contexts {
        let _ = writeln!(
            out,
            "  {context:<CONTEXT_COLUMN_WIDTH$} {:>8} {:>8} {:>8}",
            counts.blocked, counts.audited, counts.allowed
        );
    }
}

fn action_label(action: Action) -> &'static str {
    match action {
        Action::Blocked => "blocked",
        Action::Audited => "audited",
        Action::Allowed => "allowed",
    }
}

#[cfg(test)]
mod tests;
