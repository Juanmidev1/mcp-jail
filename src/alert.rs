use colored::Colorize;

use crate::trace::{Action, Category};

/// One-line human-readable rendering of a syscall event, shared by live alerts and `tail`
pub fn format_syscall_event(
    action: Action,
    category: Category,
    syscall: &str,
    target: &str,
    mcp_context: &str,
) -> String {
    let tag = format!("[{}]", mcp_context.replacen(':', ": ", 1)).bold();
    let call = match category {
        Category::Net => format!("{syscall}({target})"),
        Category::Fs | Category::Process => format!("{syscall}({target:?})"),
    };
    match action {
        Action::Blocked => format!("{tag} {} {call} -> EACCES", "BLOCKED".red().bold()),
        Action::Audited => format!("{tag} {} {call} (audit-only)", "AUDIT".yellow().bold()),
        Action::Allowed => {
            let label = match category {
                Category::Process => "ALLOWED".cyan(),
                Category::Net => "ALLOWED".yellow(),
                Category::Fs => "ALLOWED".normal(),
            };
            format!("{tag} {label} {call}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_blocked_file_access_like_the_spec() {
        colored::control::set_override(false);
        let line = format_syscall_event(
            Action::Blocked,
            Category::Fs,
            "openat",
            "/w/secret",
            "tools/call:summarize_readme",
        );
        assert_eq!(
            line,
            r#"[tools/call: summarize_readme] BLOCKED openat("/w/secret") -> EACCES"#
        );
        let line = format_syscall_event(
            Action::Allowed,
            Category::Net,
            "connect",
            "1.2.3.4:443",
            "idle",
        );
        assert_eq!(line, "[idle] ALLOWED connect(1.2.3.4:443)");
    }
}
