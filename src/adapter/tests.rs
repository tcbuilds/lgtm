//! Unit tests for the adapter core and the Claude adapter.

use serde_json::{Value, json};

use super::{
    ClaudeAdapter, EncodedResponse, HookAdapter, HookEvent, HookResponse, OutputStream, emit,
};

/// Parse the encoded body of an inject/deny/block response as JSON.
fn body_json(encoded: &EncodedResponse) -> Value {
    serde_json::from_str(&encoded.body).expect("encoded body is JSON")
}

#[test]
fn allow_encodes_to_a_silent_stdout_success() {
    let encoded = ClaudeAdapter
        .encode_response(HookEvent::PreToolUse, HookResponse::Allow)
        .expect("allow is valid for any event");
    assert_eq!(
        encoded,
        EncodedResponse {
            body: String::new(),
            stream: OutputStream::Stdout,
            exit_code: 0,
        }
    );
}

#[test]
fn inject_context_uses_the_event_specific_envelope() {
    for (event, name) in [
        (HookEvent::SessionStart, "SessionStart"),
        (HookEvent::UserPromptSubmit, "UserPromptSubmit"),
    ] {
        let encoded = ClaudeAdapter
            .encode_response(event, HookResponse::InjectContext("packet".to_string()))
            .expect("inject context is valid for this event");
        assert_eq!(encoded.stream, OutputStream::Stdout);
        assert_eq!(encoded.exit_code, 0);
        assert_eq!(
            body_json(&encoded),
            json!({
                "hookSpecificOutput": {
                    "hookEventName": name,
                    "additionalContext": "packet",
                }
            })
        );
    }
}

#[test]
fn deny_encodes_the_pre_tool_use_permission_envelope() {
    let encoded = ClaudeAdapter
        .encode_response(
            HookEvent::PreToolUse,
            HookResponse::Deny {
                reason: "target escapes repository".to_string(),
            },
        )
        .expect("deny is valid for PreToolUse");
    assert_eq!(encoded.stream, OutputStream::Stdout);
    assert_eq!(encoded.exit_code, 0);
    assert_eq!(
        body_json(&encoded),
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "target escapes repository",
            },
            "systemMessage": "target escapes repository"
        })
    );
}

#[test]
fn post_tool_use_block_writes_decision_to_stdout_exit_zero() {
    let encoded = ClaudeAdapter
        .encode_response(
            HookEvent::PostToolUse,
            HookResponse::BlockStop {
                reason: "boom".to_string(),
            },
        )
        .expect("block is valid for PostToolUse");
    assert_eq!(encoded.stream, OutputStream::Stdout);
    assert_eq!(encoded.exit_code, 0);
    assert_eq!(
        body_json(&encoded),
        json!({ "decision": "block", "reason": "boom" })
    );
}

#[test]
fn stop_block_writes_decision_to_stderr_exit_two() {
    let encoded = ClaudeAdapter
        .encode_response(
            HookEvent::Stop,
            HookResponse::BlockStop {
                reason: "unresolved".to_string(),
            },
        )
        .expect("block is valid for Stop");
    assert_eq!(encoded.stream, OutputStream::Stderr);
    assert_eq!(encoded.exit_code, 2);
    assert_eq!(
        body_json(&encoded),
        json!({ "decision": "block", "reason": "unresolved" })
    );
}

#[test]
fn every_decision_body_satisfies_the_adapter_schema() {
    let schema: Value = serde_json::from_str(include_str!("../../schemas/adapter.schema.json"))
        .expect("adapter schema");
    let validator = jsonschema::validator_for(&schema).expect("adapter validator");
    let bodies = [
        ClaudeAdapter.encode_response(
            HookEvent::PreToolUse,
            HookResponse::Deny {
                reason: "reason".to_string(),
            },
        ),
        ClaudeAdapter.encode_response(
            HookEvent::PostToolUse,
            HookResponse::BlockStop {
                reason: "reason".to_string(),
            },
        ),
        ClaudeAdapter.encode_response(
            HookEvent::Stop,
            HookResponse::BlockStop {
                reason: "reason".to_string(),
            },
        ),
        ClaudeAdapter.encode_response(
            HookEvent::UserPromptSubmit,
            HookResponse::InjectContext("packet".to_string()),
        ),
    ];
    for encoded in bodies {
        let encoded = encoded.expect("every decision pair is event-valid");
        assert!(validator.is_valid(&body_json(&encoded)));
    }
}

#[test]
fn parse_request_reads_neutral_fields_from_claude_json() {
    let stdin = json!({
        "session_id": "abc",
        "cwd": "/repo",
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/x.py" },
        "transcript_path": "/t.jsonl",
        "source": "startup",
    })
    .to_string();
    let request = ClaudeAdapter
        .parse_request(HookEvent::PreToolUse, &stdin)
        .expect("parses");
    assert_eq!(request.event, HookEvent::PreToolUse);
    assert_eq!(request.tool_name.as_deref(), Some("Edit"));
    assert_eq!(request.session_id.as_deref(), Some("abc"));
    assert_eq!(request.cwd.as_deref(), Some("/repo"));
    assert_eq!(request.transcript_path.as_deref(), Some("/t.jsonl"));
    assert_eq!(request.source.as_deref(), Some("startup"));
    assert_eq!(request.tool_input, Some(json!({ "file_path": "src/x.py" })));
}

#[test]
fn parse_request_prefers_user_prompt_then_prompt() {
    let with_user_prompt = json!({ "user_prompt": "a", "prompt": "b" }).to_string();
    let request = ClaudeAdapter
        .parse_request(HookEvent::UserPromptSubmit, &with_user_prompt)
        .expect("parses");
    assert_eq!(request.prompt.as_deref(), Some("a"));

    let with_prompt_only = json!({ "prompt": "b" }).to_string();
    let request = ClaudeAdapter
        .parse_request(HookEvent::UserPromptSubmit, &with_prompt_only)
        .expect("parses");
    assert_eq!(request.prompt.as_deref(), Some("b"));
}

#[test]
fn parse_request_accepts_blank_stdin_as_empty() {
    let request = ClaudeAdapter
        .parse_request(HookEvent::SessionStart, "   ")
        .expect("blank parses");
    assert_eq!(request.event, HookEvent::SessionStart);
    assert_eq!(request.tool_name, None);
    assert_eq!(request.prompt, None);
}

#[test]
fn parse_request_rejects_malformed_stdin() {
    let error = ClaudeAdapter
        .parse_request(HookEvent::Stop, "{ not json")
        .expect_err("malformed stdin is an error");
    assert!(error.contains("parse stdin"));
}

#[test]
fn parse_request_rejects_non_object_payloads() {
    for payload in ["null", "[1, 2]", "\"text\"", "42", "true"] {
        let error = ClaudeAdapter
            .parse_request(HookEvent::PreToolUse, payload)
            .expect_err("a non-object payload is an error");
        assert!(
            error.contains("parse stdin"),
            "non-object payload {payload:?} must be rejected: {error}"
        );
    }
}

#[test]
fn encode_response_rejects_event_invalid_pairs() {
    let invalid = [
        (
            HookEvent::Stop,
            HookResponse::Deny {
                reason: "r".to_string(),
            },
        ),
        (
            HookEvent::SessionStart,
            HookResponse::BlockStop {
                reason: "r".to_string(),
            },
        ),
        (
            HookEvent::PreToolUse,
            HookResponse::InjectContext("c".to_string()),
        ),
        (
            HookEvent::UserPromptSubmit,
            HookResponse::Deny {
                reason: "r".to_string(),
            },
        ),
    ];
    for (event, response) in invalid {
        let error = ClaudeAdapter
            .encode_response(event, response)
            .expect_err("an event-invalid pair must not encode");
        assert!(
            error.contains("encode response"),
            "invalid pair must report an encode error: {error}"
        );
    }
}

#[test]
fn encode_response_allows_any_event() {
    for event in [
        HookEvent::SessionStart,
        HookEvent::UserPromptSubmit,
        HookEvent::PreToolUse,
        HookEvent::PostToolUse,
        HookEvent::Stop,
    ] {
        let encoded = ClaudeAdapter
            .encode_response(event, HookResponse::Allow)
            .expect("allow is valid for every event");
        assert_eq!(encoded.body, String::new());
    }
}

#[test]
fn emit_writes_a_stdout_response_to_the_stdout_writer_only() {
    let encoded = EncodedResponse {
        body: "{\"decision\":\"block\"}".to_string(),
        stream: OutputStream::Stdout,
        exit_code: 0,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    emit(&mut stdout, &mut stderr, &encoded).expect("emit succeeds");
    assert_eq!(stdout, b"{\"decision\":\"block\"}\n");
    assert!(stderr.is_empty(), "stdout response must not touch stderr");
}

#[test]
fn emit_writes_a_stderr_response_to_the_injected_stderr_writer() {
    let encoded = ClaudeAdapter
        .encode_response(
            HookEvent::Stop,
            HookResponse::BlockStop {
                reason: "unresolved".to_string(),
            },
        )
        .expect("block is valid for Stop");
    assert_eq!(encoded.stream, OutputStream::Stderr);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    emit(&mut stdout, &mut stderr, &encoded).expect("emit succeeds");
    assert!(stdout.is_empty(), "stderr response must not touch stdout");
    assert_eq!(stderr, format!("{}\n", encoded.body).into_bytes());
}

#[test]
fn emit_writes_nothing_for_an_empty_body() {
    let encoded = EncodedResponse {
        body: String::new(),
        stream: OutputStream::Stdout,
        exit_code: 0,
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    emit(&mut stdout, &mut stderr, &encoded).expect("emit succeeds");
    assert!(stdout.is_empty() && stderr.is_empty());
}
