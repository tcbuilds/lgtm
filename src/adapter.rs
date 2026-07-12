//! Harness-neutral hook protocol primitives.
//!
//! Adapters own lifecycle input parsing; policy decisions use these shared
//! response constructors so each harness cannot invent status semantics.

use serde_json::{Value, json};
use std::io::Write;

pub fn pre_tool_deny(reason: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": reason
    })
}

pub fn block(reason: &str) -> Value {
    json!({"decision": "block", "reason": reason})
}

pub fn user_prompt_context(intent: &str, packet: &str) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": format!("Detected task intent: {intent}.\n\n{packet}"),
        }
    })
}

pub fn write_line(output: &mut impl Write, value: &Value) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_claude_decision_contract() {
        let schema: Value = serde_json::from_str(include_str!("../schemas/adapter.schema.json"))
            .expect("adapter schema");
        let validator = jsonschema::validator_for(&schema).expect("adapter validator");
        for response in [
            pre_tool_deny("reason"),
            block("reason"),
            user_prompt_context("intent", "packet"),
        ] {
            assert!(validator.is_valid(&response));
        }
    }
}
