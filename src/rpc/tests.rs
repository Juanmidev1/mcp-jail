use super::*;

fn tool_call(id: &str, name: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}"}}}}"#)
}

fn response(id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{}}}}"#)
}

#[test]
fn idle_when_nothing_is_in_flight() {
    assert_eq!(RpcTracker::default().current_context(), IDLE_CONTEXT);
}

#[test]
fn tracks_most_recent_call_and_closes_on_response() {
    let tracker = RpcTracker::default();
    let opened = tracker.observe_client_line(tool_call("1", "summarize_readme").as_bytes());
    assert_eq!(opened[0].target, "summarize_readme");
    tracker.observe_client_line(tool_call("2", "read_file").as_bytes());
    assert_eq!(tracker.current_context(), "tools/call:read_file");

    tracker.observe_server_line(response("2").as_bytes());
    assert_eq!(tracker.current_context(), "tools/call:summarize_readme");
    tracker.observe_server_line(response("1").as_bytes());
    assert_eq!(tracker.current_context(), IDLE_CONTEXT);
}

#[test]
fn string_and_numeric_ids_are_distinct() {
    let tracker = RpcTracker::default();
    tracker.observe_client_line(tool_call("1", "a").as_bytes());
    tracker.observe_server_line(response(r#""1""#).as_bytes());
    assert_eq!(tracker.current_context(), "tools/call:a");
}

#[test]
fn labels_resources_prompts_and_plain_methods() {
    let tracker = RpcTracker::default();
    let line = r#"{"id":1,"method":"resources/read","params":{"uri":"file:///a"}}"#;
    tracker.observe_client_line(line.as_bytes());
    assert_eq!(tracker.current_context(), "resources/read:file:///a");
    let line = r#"{"id":2,"method":"prompts/get","params":{"name":"p"}}"#;
    tracker.observe_client_line(line.as_bytes());
    assert_eq!(tracker.current_context(), "prompts/get:p");
    tracker.observe_client_line(br#"{"id":3,"method":"tools/list"}"#);
    assert_eq!(tracker.current_context(), "tools/list");
}

#[test]
fn ignores_notifications_server_requests_and_garbage() {
    let tracker = RpcTracker::default();
    assert!(
        tracker
            .observe_client_line(br#"{"method":"notifications/initialized"}"#)
            .is_empty()
    );
    assert!(tracker.observe_client_line(b"not json").is_empty());
    tracker.observe_client_line(tool_call("5", "a").as_bytes());
    tracker.observe_server_line(br#"{"id":5,"method":"sampling/createMessage"}"#);
    assert_eq!(tracker.current_context(), "tools/call:a");
}

#[test]
fn cancellation_closes_the_request() {
    let tracker = RpcTracker::default();
    tracker.observe_client_line(tool_call("9", "slow").as_bytes());
    let cancel = r#"{"method":"notifications/cancelled","params":{"requestId":9}}"#;
    tracker.observe_client_line(cancel.as_bytes());
    assert_eq!(tracker.current_context(), IDLE_CONTEXT);
}

#[test]
fn handles_batches() {
    let tracker = RpcTracker::default();
    let batch = format!("[{},{}]", tool_call("1", "a"), tool_call("2", "b"));
    assert_eq!(tracker.observe_client_line(batch.as_bytes()).len(), 2);
    tracker.observe_server_line(format!("[{},{}]", response("1"), response("2")).as_bytes());
    assert_eq!(tracker.current_context(), IDLE_CONTEXT);
}
