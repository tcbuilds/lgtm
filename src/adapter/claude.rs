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
            HookResponse::Deny { reason } => match event {
                HookEvent::PreToolUse => Ok(stdout_line(deny_envelope(&reason))),
                _ => Err(invalid_combination(event, "Deny")),
            },
            HookResponse::BlockStop { reason } => block(event, &reason),
        }
    }
}

/// The Claude event name for a lifecycle event.
fn event_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::SessionStart => "SessionStart",
        HookEvent::UserPromptSubmit => "UserPromptSubmit",
        HookEvent::PreToolUse => "PreToolUse",
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

/// The PreToolUse deny envelope. Deny is a Pre-tool decision, so the event name
/// is fixed to preserve the historical contract.
fn deny_envelope(reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason
    })
}

/// Encode a block outcome. PostToolUse writes the decision to stdout and exits
/// 0; Stop writes it to stderr and exits 2, matching Claude's Stop protocol. A
/// block is only a valid contract for those two events; any other event is an
/// invalid combination and returns an error so the caller fails open.
fn block(event: HookEvent, reason: &str) -> Result<EncodedResponse, String> {
    let value = json!({ "decision": "block", "reason": reason });
    match event {
        HookEvent::PostToolUse => Ok(stdout_line(value)),
        HookEvent::Stop => Ok(EncodedResponse {
            body: serialize(&value),
            stream: OutputStream::Stderr,
            exit_code: 2,
        }),
        _ => Err(invalid_combination(event, "BlockStop")),
    }
}

/// The error message for a response that is not a valid contract for `event`.
/// The adapter refuses to encode plausible-but-wrong bytes (for example a Deny
/// on Stop, or a BlockStop on SessionStart); the caller treats this error as
/// fail-open.
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
