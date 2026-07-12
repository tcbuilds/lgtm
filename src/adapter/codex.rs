//! The Codex CLI adapter.
//!
//! Codex consumes explicit JSON hook decisions and ignores hook exit codes for
//! enforcement. Every non-empty response therefore stays on stdout, exits 0,
//! and uses only fields supported by the selected lifecycle event.

use serde_json::{Value, json};

use super::{EncodedResponse, HookAdapter, HookEvent, HookRequest, HookResponse, OutputStream};

/// Adapter for the Codex CLI hook protocol.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodexAdapter;

impl HookAdapter for CodexAdapter {
    fn parse_request(&self, event: HookEvent, stdin_json: &str) -> Result<HookRequest, String> {
        let value = if stdin_json.trim().is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(stdin_json).map_err(|error| format!("parse stdin ({error})"))?
        };
        if !value.is_object() {
            return Err("parse stdin (payload is not a JSON object)".to_string());
        }
        if let Some(payload_event) = string_field(&value, "hookEventName")
            .or_else(|| string_field(&value, "hook_event_name"))
            && payload_event != event_name(event)
        {
            return Err(format!(
                "parse stdin (hook event {payload_event} does not match {})",
                event_name(event)
            ));
        }
        Ok(HookRequest {
            event,
            tool_name: string_field(&value, "tool_name").map(canonical_tool_name),
            tool_input: value.get("tool_input").cloned(),
            prompt: string_field(&value, "prompt").or_else(|| string_field(&value, "user_prompt")),
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
                HookEvent::SessionStart | HookEvent::UserPromptSubmit | HookEvent::PostToolUse => {
                    stdout_json(json!({
                        "hookSpecificOutput": {
                            "hookEventName": event_name(event),
                            "additionalContext": text,
                        }
                    }))
                }
                // Codex versions with stable hooks do not accept
                // `hookSpecificOutput.additionalContext` on PreToolUse. The
                // top-level system message is the supported fallback.
                HookEvent::PreToolUse => stdout_json(json!({
                    "systemMessage": text,
                })),
                HookEvent::Stop => Err(invalid_combination(event, "InjectContext")),
            },
            HookResponse::Deny { reason } => match event {
                HookEvent::PreToolUse => stdout_json(json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                })),
                _ => Err(invalid_combination(event, "Deny")),
            },
            HookResponse::BlockStop { reason } => match event {
                HookEvent::PostToolUse | HookEvent::Stop => {
                    stdout_json(json!({ "decision": "block", "reason": reason }))
                }
                _ => Err(invalid_combination(event, "BlockStop")),
            },
        }
    }
}

fn event_name(event: HookEvent) -> &'static str {
    match event {
        HookEvent::SessionStart => "SessionStart",
        HookEvent::UserPromptSubmit => "UserPromptSubmit",
        HookEvent::PreToolUse => "PreToolUse",
        HookEvent::PostToolUse => "PostToolUse",
        HookEvent::Stop => "Stop",
    }
}

fn stdout_json(value: Value) -> Result<EncodedResponse, String> {
    let body =
        serde_json::to_string(&value).map_err(|error| format!("serialize response ({error})"))?;
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

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn canonical_tool_name(name: String) -> String {
    match name.as_str() {
        "apply_patch" | "Edit" => "Edit".to_string(),
        "Write" => "Write".to_string(),
        "exec_command" | "unified_exec" | "Bash" => "Bash".to_string(),
        _ => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(event: HookEvent, response: HookResponse, expected: &str) {
        let encoded = CodexAdapter
            .encode_response(event, response)
            .expect("response is event-valid");
        assert_eq!(encoded.body, expected);
        assert_eq!(encoded.stream, OutputStream::Stdout);
        assert_eq!(encoded.exit_code, 0);
    }

    #[test]
    fn deny_uses_codex_pre_tool_use_json() {
        exact(
            HookEvent::PreToolUse,
            HookResponse::Deny {
                reason: "target escapes repository".to_string(),
            },
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"target escapes repository"}}"#,
        );
    }

    #[test]
    fn block_stop_uses_stdout_exit_zero_for_stop_and_post_tool_use() {
        for event in [HookEvent::Stop, HookEvent::PostToolUse] {
            exact(
                event,
                HookResponse::BlockStop {
                    reason: "unresolved MUST violation".to_string(),
                },
                r#"{"decision":"block","reason":"unresolved MUST violation"}"#,
            );
        }
    }

    #[test]
    fn inject_context_uses_event_specific_additional_context() {
        for (event, name) in [
            (HookEvent::SessionStart, "SessionStart"),
            (HookEvent::UserPromptSubmit, "UserPromptSubmit"),
            (HookEvent::PostToolUse, "PostToolUse"),
        ] {
            let expected = format!(
                "{{\"hookSpecificOutput\":{{\"additionalContext\":\"packet\",\"hookEventName\":\"{name}\"}}}}"
            );
            let encoded = CodexAdapter
                .encode_response(event, HookResponse::InjectContext("packet".to_string()))
                .expect("context is event-valid");
            assert_eq!(encoded.body, expected);
            assert_eq!(encoded.stream, OutputStream::Stdout);
            assert_eq!(encoded.exit_code, 0);
        }

        exact(
            HookEvent::PreToolUse,
            HookResponse::InjectContext("packet".to_string()),
            r#"{"systemMessage":"packet"}"#,
        );
    }

    #[test]
    fn allow_is_silent_for_every_event() {
        for event in [
            HookEvent::SessionStart,
            HookEvent::UserPromptSubmit,
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
            HookEvent::Stop,
        ] {
            let encoded = CodexAdapter
                .encode_response(event, HookResponse::Allow)
                .expect("allow is event-valid");
            assert_eq!(encoded.body, "");
            assert_eq!(encoded.stream, OutputStream::Stdout);
            assert_eq!(encoded.exit_code, 0);
        }
    }

    #[test]
    fn unsupported_response_pairs_are_rejected() {
        let invalid = [
            (
                HookEvent::Stop,
                HookResponse::Deny {
                    reason: "reason".to_string(),
                },
            ),
            (
                HookEvent::SessionStart,
                HookResponse::BlockStop {
                    reason: "reason".to_string(),
                },
            ),
            (
                HookEvent::PreToolUse,
                HookResponse::BlockStop {
                    reason: "reason".to_string(),
                },
            ),
            (
                HookEvent::Stop,
                HookResponse::InjectContext("context".to_string()),
            ),
        ];
        for (event, response) in invalid {
            let error = CodexAdapter
                .encode_response(event, response)
                .expect_err("unsupported response pair must be rejected");
            assert!(error.contains("encode response"));
        }
    }

    #[test]
    fn parses_codex_pre_tool_use_fixture_and_normalizes_edit_tool() {
        let request = CodexAdapter
            .parse_request(
                HookEvent::PreToolUse,
                include_str!("../../tests/fixtures/codex/pre_tool_use.json"),
            )
            .expect("Codex fixture parses");
        assert_eq!(request.event, HookEvent::PreToolUse);
        assert_eq!(request.tool_name.as_deref(), Some("Edit"));
        assert_eq!(request.session_id.as_deref(), Some("session-123"));
        assert_eq!(request.cwd.as_deref(), Some("/workspace/repo"));
        assert_eq!(request.transcript_path.as_deref(), Some("/tmp/codex.jsonl"));
        assert_eq!(
            request.tool_input,
            Some(json!({"patch": "*** Begin Patch"}))
        );
    }

    #[test]
    fn normalizes_codex_command_tool_names() {
        for (codex_name, expected) in [
            ("apply_patch", "Edit"),
            ("Edit", "Edit"),
            ("Write", "Write"),
            ("exec_command", "Bash"),
            ("unified_exec", "Bash"),
            ("Bash", "Bash"),
        ] {
            let payload =
                format!("{{\"hookEventName\":\"PostToolUse\",\"tool_name\":\"{codex_name}\"}}");
            let request = CodexAdapter
                .parse_request(HookEvent::PostToolUse, &payload)
                .expect("tool payload parses");
            assert_eq!(request.tool_name.as_deref(), Some(expected));
        }
    }

    #[test]
    fn rejects_malformed_non_object_and_mismatched_event_payloads() {
        for payload in ["{ not json", "null", "[]", "\"text\""] {
            let error = CodexAdapter
                .parse_request(HookEvent::Stop, payload)
                .expect_err("malformed payload must fail");
            assert!(error.contains("parse stdin"));
        }
        let error = CodexAdapter
            .parse_request(HookEvent::Stop, r#"{"hookEventName":"PreToolUse"}"#)
            .expect_err("mismatched event must fail");
        assert!(error.contains("does not match Stop"));
    }
}
