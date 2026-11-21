use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::Child;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crate::rpc::RpcTracker;
use crate::trace::{EventKind, Tracer};

const RAW_CHUNK_SIZE: usize = 8192;

pub struct ProxyThreads {
    /// Finishes when the MCP client closes stdin, which the sandbox uses to start shutdown
    pub stdin: JoinHandle<io::Result<()>>,
    pub stdout: JoinHandle<io::Result<()>>,
    pub stderr: JoinHandle<io::Result<()>>,
}

pub fn spawn(
    child: &mut Child,
    tracker: &RpcTracker,
    tracer: &Arc<Tracer>,
) -> Result<ProxyThreads, Box<dyn Error>> {
    let child_stdin = child.stdin.take().ok_or("child stdin is not piped")?;
    let child_stdout = child.stdout.take().ok_or("child stdout is not piped")?;
    let child_stderr = child.stderr.take().ok_or("child stderr is not piped")?;
    let (client_tracker, server_tracker) = (tracker.clone(), tracker.clone());
    let tracer = Arc::clone(tracer);
    // stdout and stderr stay unlocked between writes so supervisor alerts are never starved
    Ok(ProxyThreads {
        stdin: thread::spawn(move || {
            forward_client_frames(io::stdin().lock(), child_stdin, &client_tracker, &tracer)
        }),
        stdout: thread::spawn(move || {
            forward_server_frames(child_stdout, io::stdout(), &server_tracker)
        }),
        stderr: thread::spawn(move || forward_raw(child_stderr, io::stderr())),
    })
}

/// Requests are registered before they reach the server, otherwise a fast server could hit
/// a syscall before its tools/call context exists; parsing one line costs microseconds
pub fn forward_client_frames(
    input: impl Read,
    mut output: impl Write,
    tracker: &RpcTracker,
    tracer: &Tracer,
) -> io::Result<()> {
    forward_lines(input, &mut output, Inspection::BeforeForwarding, |line| {
        for call in tracker.observe_client_line(line) {
            tracer.emit(EventKind::McpCall {
                method: call.method,
                target: call.target,
            });
        }
    })
}

pub fn forward_server_frames(
    input: impl Read,
    mut output: impl Write,
    tracker: &RpcTracker,
) -> io::Result<()> {
    forward_lines(input, &mut output, Inspection::AfterForwarding, |line| {
        tracker.observe_server_line(line);
    })
}

pub fn forward_raw(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    let mut chunk = [0u8; RAW_CHUNK_SIZE];
    loop {
        let read = match input.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        output.write_all(&chunk[..read])?;
        output.flush()?;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Inspection {
    BeforeForwarding,
    AfterForwarding,
}

fn forward_lines(
    input: impl Read,
    output: &mut impl Write,
    inspection: Inspection,
    mut inspect: impl FnMut(&[u8]),
) -> io::Result<()> {
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        if inspection == Inspection::BeforeForwarding {
            inspect(&line);
        }
        output.write_all(&line)?;
        output.flush()?;
        if inspection == Inspection::AfterForwarding {
            inspect(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &[u8] = b"{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"t\"}}\r\n";

    #[test]
    fn client_frames_are_forwarded_byte_for_byte_and_traced() {
        let dir = tempfile::tempdir().unwrap();
        let trace_path = dir.path().join("t.jsonl");
        let tracer = Tracer::create(&trace_path).unwrap();
        let tracker = RpcTracker::default();
        let input = [REQUEST, b"partial without newline"].concat();
        let mut output = Vec::new();
        forward_client_frames(input.as_slice(), &mut output, &tracker, &tracer).unwrap();
        assert_eq!(output, input);
        assert_eq!(tracker.current_context(), "tools/call:t");
        let trace = std::fs::read_to_string(trace_path).unwrap();
        assert!(trace.contains(r#""type":"mcp_call""#));
    }

    #[test]
    fn server_frames_close_requests() {
        let tracker = RpcTracker::default();
        tracker.observe_client_line(REQUEST);
        let input: &[u8] = b"{\"id\":1,\"result\":{}}\n";
        let mut output = Vec::new();
        forward_server_frames(input, &mut output, &tracker).unwrap();
        assert_eq!(output, input);
        assert_eq!(tracker.current_context(), crate::rpc::IDLE_CONTEXT);
    }

    #[test]
    fn raw_forwarding_copies_binary_data() {
        let input: Vec<u8> = (0..=255u8).cycle().take(RAW_CHUNK_SIZE * 2 + 7).collect();
        let mut output = Vec::new();
        forward_raw(input.as_slice(), &mut output).unwrap();
        assert_eq!(output, input);
    }
}
