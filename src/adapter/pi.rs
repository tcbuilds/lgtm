//! Thin protocol mapping for verified Pi 0.84.2–0.84.3 extension events.

use serde_json::{Value, json};

use super::{EncodedResponse, HookAdapter, HookEvent, HookRequest, HookResponse, OutputStream};

const MAX_INPUT_BYTES: usize = 1_024 * 1_024;

/// Adapter for the verified Pi extension event contracts.
#[derive(Debug, Clone, Copy, Default)]
pub struct PiAdapter;

impl HookAdapter for PiAdapter {
    fn harness_name(&self) -> &'static str {
        "pi"
    }

    fn loads_rules_natively(&self) -> bool {
        false
    }

    fn fail_open_on_error(&self) -> bool {
        true
    }

    fn parse_request(&self, event: HookEvent, stdin_json: &str) -> Result<HookRequest, String> {
        if stdin_json.len() > MAX_INPUT_BYTES {
            return Err("parse stdin (payload exceeds 1048576 bytes)".to_string());
        }
        let blank = stdin_json.trim().is_empty();
        let value = if blank {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(stdin_json).map_err(|error| format!("parse stdin ({error})"))?
        };
        if !value.is_object() {
            return Err("parse stdin (payload is not a JSON object)".to_string());
        }
        if !blank {
            let payload_type = value
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "parse stdin (type is missing or not a string)".to_string())?;
            if !event_types(event).contains(&payload_type) {
                return Err(format!(
                    "parse stdin (event type does not match {})",
                    event_name(event)
                ));
            }
        }

        let tool_name =
            string_field(&value, "toolName").map(|name| canonical_tool_name(&name).to_string());
        let tool_input = value.get("input").cloned();
        let session_id =
            string_field(&value, "sessionId").or_else(|| string_field(&value, "session_id"));
        let cwd = string_field(&value, "cwd");
        if matches!(event, HookEvent::PreToolUse | HookEvent::PostToolUse)
            && (tool_name.is_none()
                || !tool_input.as_ref().is_some_and(Value::is_object)
                || session_id.as_deref().is_none_or(str::is_empty)
                || cwd.as_deref().is_none_or(str::is_empty))
        {
            return Err(
                "parse stdin (Pi toolName, object input, cwd, and session id are required)"
                    .to_string(),
            );
        }

        // Pi's verified built-ins use lowercase names; shared hooks use the
        // neutral adapter vocabulary.
        Ok(HookRequest {
            event,
            tool_name,
            tool_input,
            prompt: string_field(&value, "prompt"),
            session_id,
            cwd,
            transcript_path: string_field(&value, "transcriptPath")
                .or_else(|| string_field(&value, "transcript_path")),
            source: string_field(&value, "source"),
            agent_id: None,
            agent_type: None,
            stop_hook_active: None,
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
            HookResponse::Deny { reason } => {
                if event != HookEvent::PreToolUse {
                    return Err(invalid_combination(event, "Deny"));
                }
                stdout_json(json!({"block": true, "reason": reason}))
            }
            HookResponse::InjectMessage(content) => {
                if event != HookEvent::BeforeAgentStart {
                    return Err(invalid_combination(event, "InjectMessage"));
                }
                stdout_json(json!({
                    "message": {
                        "customType": "lgtm",
                        "content": content,
                        "display": false,
                    }
                }))
            }
            HookResponse::InjectSystemPrompt(system_prompt) => {
                if event != HookEvent::BeforeAgentStart {
                    return Err(invalid_combination(event, "InjectSystemPrompt"));
                }
                stdout_json(json!({"systemPrompt": system_prompt}))
            }
            HookResponse::PostToolFeedback { reason } => {
                if event != HookEvent::PostToolUse {
                    return Err(invalid_combination(event, "PostToolFeedback"));
                }
                stdout_json(json!({
                    "content": [{"type": "text", "text": reason}],
                }))
            }
            HookResponse::InjectContext(_) => Err(invalid_combination(event, "InjectContext")),
            HookResponse::BlockStop { .. } => Err(invalid_combination(event, "BlockStop")),
            HookResponse::Summary(_) => Err(invalid_combination(event, "Summary")),
        }
    }
}

fn event_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::SessionStart => "session_start",
        HookEvent::UserPromptSubmit => "user_prompt_submit",
        HookEvent::BeforeAgentStart => "before_agent_start",
        HookEvent::PreToolUse => "tool_call",
        HookEvent::PostToolUse => "tool_result",
        HookEvent::Stop => "agent_end or agent_settled",
        HookEvent::PermissionRequest => "permission_request",
        HookEvent::SubagentStart => "subagent_start",
        HookEvent::SubagentStop => "subagent_stop",
    }
}

fn event_types(event: HookEvent) -> &'static [&'static str] {
    match event {
        HookEvent::SessionStart => &["session_start"],
        HookEvent::BeforeAgentStart => &["before_agent_start"],
        HookEvent::PreToolUse => &["tool_call"],
        HookEvent::PostToolUse => &["tool_result"],
        HookEvent::UserPromptSubmit => &[],
        HookEvent::Stop => &["agent_end", "agent_settled"],
        HookEvent::PermissionRequest | HookEvent::SubagentStart | HookEvent::SubagentStop => &[],
    }
}

fn stdout_json(value: Value) -> Result<EncodedResponse, String> {
    let body = serde_json::to_string(&value)
        .map_err(|error| format!("serialize Pi response ({error})"))?;
    Ok(EncodedResponse {
        body,
        stream: OutputStream::Stdout,
        exit_code: 0,
    })
}

fn invalid_combination(event: HookEvent, response: &str) -> String {
    format!(
        "encode response ({response} is not valid for {})",
        event_name(event)
    )
}

fn canonical_tool_name(name: &str) -> &str {
    match name {
        "bash" => "Bash",
        "read" => "Read",
        "edit" => "Edit",
        "write" => "Write",
        other => other,
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(event: HookEvent, response: HookResponse, expected: &str) {
        let encoded = PiAdapter
            .encode_response(event, response)
            .expect("response is event-valid");
        assert_eq!(encoded.body, expected);
        assert_eq!(encoded.stream, OutputStream::Stdout);
        assert_eq!(encoded.exit_code, 0);
    }

    #[test]
    fn encodes_pi_allow_and_tool_denial() {
        exact(HookEvent::PreToolUse, HookResponse::Allow, "");
        exact(
            HookEvent::PreToolUse,
            HookResponse::Deny {
                reason: "blocked by policy".to_string(),
            },
            r#"{"block":true,"reason":"blocked by policy"}"#,
        );
    }

    #[test]
    fn encodes_before_agent_start_message_and_system_prompt() {
        exact(
            HookEvent::BeforeAgentStart,
            HookResponse::InjectMessage("context".to_string()),
            r#"{"message":{"content":"context","customType":"lgtm","display":false}}"#,
        );
        exact(
            HookEvent::BeforeAgentStart,
            HookResponse::InjectSystemPrompt("system".to_string()),
            r#"{"systemPrompt":"system"}"#,
        );
    }

    #[test]
    fn encodes_only_tool_result_content_feedback() {
        exact(
            HookEvent::PostToolUse,
            HookResponse::PostToolFeedback {
                reason: "review this result".to_string(),
            },
            r#"{"content":[{"text":"review this result","type":"text"}]}"#,
        );
    }

    #[test]
    fn parses_verified_tool_fields_and_preserves_input() {
        let request = PiAdapter
            .parse_request(
                HookEvent::PreToolUse,
                r#"{"type":"tool_call","toolName":"read","input":{"path":"src/lib.rs"},"cwd":"/repo","sessionId":"session-1"}"#,
            )
            .expect("Pi tool call parses");
        assert_eq!(request.tool_name.as_deref(), Some("Read"));
        assert_eq!(request.tool_input, Some(json!({"path": "src/lib.rs"})));
        assert_eq!(request.cwd.as_deref(), Some("/repo"));
        assert_eq!(request.session_id.as_deref(), Some("session-1"));
    }

    #[test]
    fn preserves_unknown_tool_names_for_provenance_rejection() {
        let request = PiAdapter
            .parse_request(
                HookEvent::PreToolUse,
                r#"{"type":"tool_call","toolName":"custom","input":{},"cwd":"/repo","sessionId":"session-1"}"#,
            )
            .expect("unknown names remain parseable");
        assert_eq!(request.tool_name.as_deref(), Some("custom"));
    }

    #[test]
    fn rejects_malformed_non_object_oversized_and_mismatched_payloads() {
        for payload in ["{ not json", "null", "[]", "\"text\""] {
            assert!(
                PiAdapter
                    .parse_request(HookEvent::PreToolUse, payload)
                    .is_err()
            );
        }
        assert!(
            PiAdapter
                .parse_request(HookEvent::PreToolUse, r#"{"type":"tool_result"}"#)
                .is_err()
        );
        assert!(
            PiAdapter
                .parse_request(HookEvent::PreToolUse, &"x".repeat(MAX_INPUT_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_response_pairs_and_preserves_tool_result_fields() {
        assert!(
            PiAdapter
                .encode_response(
                    HookEvent::Stop,
                    HookResponse::Deny {
                        reason: "no".to_string(),
                    },
                )
                .is_err()
        );
        let encoded = PiAdapter
            .encode_response(
                HookEvent::PostToolUse,
                HookResponse::PostToolFeedback {
                    reason: "addition".to_string(),
                },
            )
            .expect("tool result feedback is supported");
        assert!(!encoded.body.contains("details"));
        assert!(!encoded.body.contains("isError"));
        assert!(!encoded.body.contains("usage"));
    }
}
