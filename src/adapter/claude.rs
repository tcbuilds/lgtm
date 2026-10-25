//! The Claude Code adapter.
//!
//! Stateless mapping between Claude's lifecycle JSON and lgtm's neutral request
//! and response types. The envelope bytes here are the sole source of truth for
//! every Claude decision contract; the hook handlers construct a
//! [`HookResponse`] and let this adapter encode it.

use serde_json::{Value, json};

use super::{EncodedResponse, HookAdapter, HookEvent, HookRequest, HookResponse, OutputStream};

/// Adapter for the Claude Code harness.
#[derive(Debug, Clone, Copy, Default)]
pub struct ClaudeAdapter;

impl HookAdapter for ClaudeAdapter {
    fn loads_rules_natively(&self) -> bool {
        true
    }

    fn parse_request(&self, event: HookEvent, stdin_json: &str) -> Result<HookRequest, String> {
        let value = if stdin_json.trim().is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(stdin_json).map_err(|error| format!("parse stdin ({error})"))?
        };
        if !value.is_object() {
            return Err("parse stdin (payload is not a JSON object)".to_string());
        }
        Ok(HookRequest {
            event,
            tool_name: string_field(&value, "tool_name"),
            tool_input: value.get("tool_input").cloned(),
            prompt: string_field(&value, "user_prompt").or_else(|| string_field(&value, "prompt")),
            session_id: string_field(&value, "session_id"),
            cwd: string_field(&value, "cwd"),
            transcript_path: string_field(&value, "transcript_path"),
            source: string_field(&value, "source"),
            agent_id: string_field(&value, "agent_id"),
            agent_type: string_field(&value, "agent_type"),
            stop_hook_active: value.get("stop_hook_active").and_then(Value::as_bool),
        })
    }

    fn encode_response(
        &self,
        event: HookEvent,
        response: HookResponse,
    ) -> Result<EncodedResponse, String> {
        match response {
            HookResponse::Allow => Ok(EncodedResponse {
                body: String::new(),
                stream: OutputStream::Stdout,
                exit_code: 0,
            }),
            HookResponse::InjectContext(text) => match event {
                HookEvent::SessionStart | HookEvent::UserPromptSubmit => {
                    Ok(stdout_line(context_envelope(event, &text)))
                }
                _ => Err(invalid_combination(event, "InjectContext")),
            },
            HookResponse::InjectMessage(_) => Err(invalid_combination(event, "InjectMessage")),
            HookResponse::InjectSystemPrompt(_) => {
                Err(invalid_combination(event, "InjectSystemPrompt"))
            }
            HookResponse::PostToolFeedback { reason } => match event {
                HookEvent::PostToolUse => Ok(stdout_line(context_envelope(event, &reason))),
                _ => Err(invalid_combination(event, "PostToolFeedback")),
            },
            HookResponse::HeuristicNotices(_) => {
                Err(invalid_combination(event, "HeuristicNotices"))
            }
            HookResponse::Summary(summary) => match event {
                HookEvent::Stop => Ok(EncodedResponse {
                    body: summary,
                    stream: OutputStream::Stdout,
                    exit_code: 0,
                }),
                _ => Err(invalid_combination(event, "Summary")),
            },
        }
    }
}

/// The Claude event name for a lifecycle event.
fn event_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::SessionStart => "SessionStart",
        HookEvent::UserPromptSubmit => "UserPromptSubmit",
        HookEvent::BeforeAgentStart => "BeforeAgentStart",
        HookEvent::PreToolUse => "PreToolUse",
        HookEvent::PermissionRequest => "PermissionRequest",
        HookEvent::SubagentStart => "SubagentStart",
        HookEvent::SubagentStop => "SubagentStop",
        HookEvent::PostToolUse => "PostToolUse",
        HookEvent::Stop => "Stop",
    }
}

/// The `additionalContext` envelope for an inject-context outcome.
fn context_envelope(event: HookEvent, context: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": event_name(event),
            "additionalContext": context,
        }
    })
}

/// Reject advisory outcomes that do not belong to this event.
fn invalid_combination(event: HookEvent, response: &str) -> String {
    format!(
        "encode response ({response} is not valid for {})",
        event_name(event)
    )
}

/// A stdout, exit-0 encoded response carrying `value` as its line.
fn stdout_line(value: Value) -> EncodedResponse {
    EncodedResponse {
        body: serialize(&value),
        stream: OutputStream::Stdout,
        exit_code: 0,
    }
}

/// Serialize a controlled JSON value to a compact line. The values here are
/// objects of string fields, so serialization is infallible; the
/// `unwrap_or_default` exists only to keep this total. An impossible failure
/// degrades to an empty body, which [`super::emit`] writes as nothing: the
/// fail-safe outcome (a silent, non-blocking allow) rather than a panic.
fn serialize(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Read an optional string field from a JSON object.
fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}
