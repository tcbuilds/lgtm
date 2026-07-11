use super::*;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python")
}

fn remove_intent_fixture() {
    let _ = std::fs::remove_file(fixture_root().join(".lgtm/evidence/current-task.intent.json"));
}

#[test]
fn valid_payload_emits_claude_additional_context() {
    let payload = json!({
        "cwd": fixture_root(),
        "user_prompt": "fix src/routes/events.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run(&mut payload.to_string().as_bytes(), &mut output);
    remove_intent_fixture();
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(
        value["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");
    assert!(context.contains("Detected task intent: bug-fix."));
    assert!(context.contains("Applicable engineering constraints:"));
    assert!(context.len() < 8_192);
}

#[test]
fn prompt_alias_is_accepted() {
    let payload = json!({"cwd": fixture_root(), "prompt": "document README.md"});
    let mut output = Vec::new();
    run(&mut payload.to_string().as_bytes(), &mut output);
    remove_intent_fixture();
    assert!(
        String::from_utf8(output)
            .expect("UTF-8")
            .contains("intent: docs")
    );
}

#[test]
fn malformed_and_oversized_payloads_fail_safe_without_output() {
    for payload in ["{".to_string(), "x".repeat(MAX_PAYLOAD_BYTES as usize + 1)] {
        let mut output = Vec::new();
        assert_eq!(run(&mut payload.as_bytes(), &mut output), ExitCode::SUCCESS);
        assert!(output.is_empty());
    }
}
