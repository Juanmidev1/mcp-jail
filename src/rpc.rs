use std::sync::{Arc, Mutex};

use serde_json::Value;

pub const IDLE_CONTEXT: &str = "idle";
const CANCELLED_NOTIFICATION: &str = "notifications/cancelled";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCall {
    pub method: String,
    pub target: String,
}

impl McpCall {
    pub fn context(&self) -> String {
        if self.target.is_empty() {
            self.method.clone()
        } else {
            format!("{}:{}", self.method, self.target)
        }
    }
}

/// In-flight requests in arrival order, keyed by the serialized JSON-RPC id
#[derive(Debug, Default)]
pub struct ActiveCalls {
    calls: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct RpcTracker {
    active: Arc<Mutex<ActiveCalls>>,
}

impl RpcTracker {
    /// Inspects a client -> server line and returns the requests it opened
    pub fn observe_client_line(&self, line: &[u8]) -> Vec<McpCall> {
        let mut opened = Vec::new();
        for message in parse_messages(line) {
            if let Some(cancelled_id) = cancelled_request_id(&message) {
                self.remove(&cancelled_id);
            } else if let (Some(id), Some(call)) = (message_id(&message), request_call(&message)) {
                self.insert(id, call.context());
                opened.push(call);
            }
        }
        opened
    }

    /// Inspects a server -> client line and closes the requests it answers
    pub fn observe_server_line(&self, line: &[u8]) {
        for message in parse_messages(line) {
            let is_response = message.get("method").is_none();
            if let Some(id) = message_id(&message).filter(|_| is_response) {
                self.remove(&id);
            }
        }
    }

    /// Most recent in-flight operation, or `idle` when nothing is pending
    pub fn current_context(&self) -> String {
        self.active
            .lock()
            .ok()
            .and_then(|active| active.calls.last().map(|(_, context)| context.clone()))
            .unwrap_or_else(|| IDLE_CONTEXT.to_string())
    }

    fn insert(&self, id: String, context: String) {
        if let Ok(mut active) = self.active.lock() {
            active.calls.retain(|(existing, _)| *existing != id);
            active.calls.push((id, context));
        }
    }

    fn remove(&self, id: &str) {
        if let Ok(mut active) = self.active.lock() {
            active.calls.retain(|(existing, _)| existing != id);
        }
    }
}

fn parse_messages(line: &[u8]) -> Vec<Value> {
    match serde_json::from_slice(line) {
        Ok(Value::Array(batch)) => batch,
        Ok(message @ Value::Object(_)) => vec![message],
        _ => Vec::new(),
    }
}

fn message_id(message: &Value) -> Option<String> {
    message
        .get("id")
        .filter(|id| !id.is_null())
        .map(Value::to_string)
}

fn cancelled_request_id(message: &Value) -> Option<String> {
    if message.get("method")?.as_str()? != CANCELLED_NOTIFICATION {
        return None;
    }
    message
        .get("params")?
        .get("requestId")
        .map(Value::to_string)
}

fn request_call(message: &Value) -> Option<McpCall> {
    let method = message.get("method")?.as_str()?;
    let params = message.get("params");
    let target_key = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    let target = target_key
        .and_then(|key| params?.get(key)?.as_str())
        .unwrap_or_default();
    Some(McpCall {
        method: method.to_string(),
        target: target.to_string(),
    })
}

#[cfg(test)]
mod tests;
