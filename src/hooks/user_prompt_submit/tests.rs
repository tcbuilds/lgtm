use super::*;
use crate::adapter::CodexAdapter;
use sha2::{Digest, Sha256};
fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python")
}
fn native_fixture_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "lgtm-user-prompt-native-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".claude/rules")).expect("create native rules");
    std::fs::write(
        root.join(".claude/rules/standards.md"),
        include_str!("../../../templates/claude-rules/CLAUDE.md"),
    )
    .expect("write native rules");
    root
}
fn foreign_fixture_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "lgtm-user-prompt-foreign-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".claude/rules")).expect("create foreign rules");
    std::fs::write(
        root.join(".claude/rules/standards.md"),
        "# foreign standards\n",
    )
    .expect("write foreign standards");
    root
}
fn write_org_instruction(root: &Path) {
    write_org_instruction_for(
        root,
        "external-call-timeout",
        "Organization instruction: bound every external call.",
        "error",
    );
}
fn write_org_instruction_for(root: &Path, id: &str, instruction: &str, severity: &str) {
    let raw = json!({
        "version": "2026-01",
        "rules": [{
            "id": id,
            "severity": severity,
            "instruction": instruction,
        }]
    })
    .to_string();
    std::fs::create_dir_all(root.join(".lgtm")).expect("create policy directory");
    std::fs::write(root.join(".lgtm/org-policy.json"), &raw).expect("write organization policy");
    std::fs::write(
        root.join(".lgtm/org-policy.sha256"),
        format!("{:x}", Sha256::digest(raw.as_bytes())),
    )
    .expect("write organization policy pin");
}
fn write_oversized_org_instruction(root: &Path) {
    let instruction = format!(
        "Organization instruction: {}",
        "x".repeat(crate::compile::MAX_PACKET_BYTES)
    );
    let raw = json!({
        "version": "2026-01",
        "rules": [{
            "id": "external-call-timeout",
            "severity": "error",
            "instruction": instruction,
        }]
    })
    .to_string();
    std::fs::create_dir_all(root.join(".lgtm")).expect("create policy directory");
    std::fs::write(root.join(".lgtm/org-policy.json"), &raw)
        .expect("write oversized organization policy");
    std::fs::write(
        root.join(".lgtm/org-policy.sha256"),
        format!("{:x}", Sha256::digest(raw.as_bytes())),
    )
    .expect("write oversized organization policy pin");
}
fn write_overlay_instruction(root: &Path) {
    let raw = r#"{"rules":[{"id":"external-call-timeout","severity":"error","instruction":"Overlay instruction: bound every external call."}]}"#;
    std::fs::create_dir_all(root.join(".lgtm")).expect("create overlay directory");
    std::fs::write(root.join(".lgtm/policy.json"), raw).expect("write overlay");
}
fn remove_intent(root: &Path) {
    let _ = std::fs::remove_file(root.join(".lgtm/evidence/current-task.intent.json"));
}
fn native_context(root: &Path, prompt: &str) -> (ExitCode, String) {
    let payload = json!({
        "cwd": root,
        "user_prompt": prompt,
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string")
        .to_string();
    (code, context)
}
#[test]
fn valid_payload_emits_claude_additional_context() {
    let root = native_fixture_root();
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/routes/events.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run(&mut payload.to_string().as_bytes(), &mut output);
    remove_intent(payload["cwd"].as_str().expect("fixture path").as_ref());
    let _ = std::fs::remove_dir_all(payload["cwd"].as_str().expect("fixture path"));
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
    assert!(!context.contains("Applicable engineering constraints:"));
    assert!(!context.contains("\nMUST\n"));
    assert!(context.len() < 8_192);
}
#[test]
fn non_native_adapter_uses_prompt_file_paths_for_guidance() {
    let payload = json!({
        "cwd": fixture_root(),
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &CodexAdapter,
    );
    remove_intent(&fixture_root());
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("External calls require timeouts"));
}
#[test]
fn native_claude_adapter_does_not_inject_prompt_derived_guidance() {
    let root = native_fixture_root();
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(payload["cwd"].as_str().expect("fixture path").as_ref());
    let _ = std::fs::remove_dir_all(payload["cwd"].as_str().expect("fixture path"));
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(context, "Detected task intent: bug-fix.");
    assert!(!context.contains("Applicable engineering constraints:"));
}
#[test]
fn native_claude_injects_resolved_organization_instruction_delta() {
    let root = native_fixture_root();
    write_org_instruction(&root);
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("Organization instruction: bound every external call."));
    assert!(!context.contains("Applicable engineering constraints:"));
    assert!(!context.contains("\nMUST\n"));
}
#[test]
fn native_scoped_override_states_applicability_for_markdown_task() {
    let root = native_fixture_root();
    write_org_instruction_for(
        &root,
        "rust-no-unsafe",
        "Organization instruction: review Rust unsafe blocks.",
        "warning",
    );
    let (code, context) = native_context(&root, "edit README.md");

    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("review Rust unsafe blocks"));
    assert!(context.contains("files: **/*.rs"));
}
#[test]
fn native_scoped_override_is_injected_for_rust_task() {
    let root = native_fixture_root();
    write_org_instruction_for(
        &root,
        "rust-no-unsafe",
        "Organization instruction: review Rust unsafe blocks.",
        "warning",
    );

    let (code, context) = native_context(&root, "edit src/lib.rs");

    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("review Rust unsafe blocks"));
}
#[test]
fn native_prompt_words_do_not_change_path_scoped_override_output() {
    let root = native_fixture_root();
    write_org_instruction_for(
        &root,
        "rust-no-unsafe",
        "Organization instruction: review Rust unsafe blocks.",
        "warning",
    );

    let first = native_context(&root, "fix src/lib.rs");
    let second = native_context(&root, "fix the Rust library implementation");

    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(first.0, ExitCode::SUCCESS);
    assert_eq!(second.0, ExitCode::SUCCESS);
    assert_eq!(first.1, second.1);
    assert!(first.1.contains("review Rust unsafe blocks"));
}
#[test]
fn native_always_applicable_override_is_injected_for_markdown_and_rust_tasks() {
    let root = native_fixture_root();
    write_org_instruction_for(
        &root,
        "preserve-unrelated-user-changes",
        "Organization instruction: preserve unrelated edits.",
        "error",
    );

    for prompt in ["edit README.md", "edit src/lib.rs"] {
        let (code, context) = native_context(&root, prompt);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(context.contains("preserve unrelated edits"));
    }

    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
}
#[test]
fn native_claude_reports_omitted_oversized_instruction_delta() {
    let root = native_fixture_root();
    write_oversized_org_instruction(&root);
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(!output.is_empty());
    assert!(
        code != ExitCode::SUCCESS || !output.is_empty(),
        "hook must not exit successfully without a response"
    );
    assert!(context.contains("Detected task intent: bug-fix."));
    assert!(context.contains("Resolved organization/repository instruction overrides omitted"));
    assert!(context.contains(&format!(
        "exceeded the {}-byte packet budget",
        crate::compile::MAX_PACKET_BYTES
    )));
    assert!(!context.contains("Organization instruction: "));
}
#[test]
fn native_claude_injects_resolved_overlay_instruction_delta() {
    let root = native_fixture_root();
    write_overlay_instruction(&root);
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("Overlay instruction: bound every external call."));
    assert!(!context.contains("Applicable engineering constraints:"));
    assert!(!context.contains("\nMUST\n"));
}
#[test]
fn native_claude_falls_back_when_rule_files_are_missing() {
    let root = std::env::temp_dir().join(format!(
        "lgtm-user-prompt-missing-rules-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create missing-rules fixture");
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(payload["cwd"].as_str().expect("fixture path").as_ref());
    let _ = std::fs::remove_dir_all(payload["cwd"].as_str().expect("fixture path"));
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("Applicable engineering constraints:"));
    assert!(!context.contains("MUST\n- None"));
}
#[test]
fn native_claude_fallback_packet_is_complete_and_bounded() {
    let root = std::env::temp_dir().join(format!(
        "lgtm-user-prompt-bounded-fallback-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    // Include every supported language so the scoped packet still exercises
    // whole-rule trimming rather than relying on the unscoped registry.
    for path in [
        "src/routes/api.py",
        "src/lib.rs",
        "src/main.go",
        "src/App.tsx",
        "src/main.java",
        "src/Program.cs",
        "src/main.cpp",
        "src/query.sql",
        "scripts/check.sh",
        "infra/main.tf",
    ] {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().expect("fixture parent"))
            .expect("create bounded-fallback parent");
        std::fs::write(file, "").expect("write bounded-fallback file");
    }
    let rules = crate::policy::load_embedded_registry().expect("embedded rules");
    let overlay_rules: Vec<_> = rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "severity": rule.severity,
                "instruction": format!("{} {}", rule.id, "x".repeat(512)),
            })
        })
        .collect();
    std::fs::create_dir_all(root.join(".lgtm")).expect("create overlay directory");
    std::fs::write(
        root.join(".lgtm/policy.json"),
        json!({"rules": overlay_rules}).to_string(),
    )
    .expect("write bounded-fallback overlay");
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/routes/api.py src/lib.rs src/main.go src/App.tsx src/main.java src/Program.cs src/main.cpp src/query.sql scripts/check.sh infra/main.tf using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(payload["cwd"].as_str().expect("fixture path").as_ref());
    let _ = std::fs::remove_dir_all(payload["cwd"].as_str().expect("fixture path"));
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");
    let packet = context
        .split_once("\n\n")
        .map(|(_, packet)| packet)
        .expect("fallback packet follows intent");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(packet.len() <= crate::compile::MAX_PACKET_BYTES);
    assert!(packet.contains("\nMUST\n"));
    assert!(packet.contains("\nREVIEW\n"));
    assert!(packet.contains("\nVerification required:\n"));
    assert!(!packet.contains("packet truncated"));
    assert!(packet.contains("Fallback packet bounded"));
    assert!(packet.contains("external-call-timeout"));
}
#[test]
fn an_oversized_instruction_marks_the_packet_incomplete() {
    let registry = crate::policy::load_embedded_registry().expect("embedded rules");
    let mut rule = registry[0].clone();
    rule.instruction = format!("Critical clause: {}", "x".repeat(MAX_INSTRUCTION_BYTES));
    let compiled = compile_selected(&[&rule], &[]);

    assert!(!packet_is_complete(&compiled.packet, &[&rule]));
}
#[test]
fn foreign_standards_document_does_not_suppress_guidance() {
    let root = foreign_fixture_root();
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/routes/api.py using requests.post",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &ClaudeAdapter,
    );
    remove_intent(&root);
    let _ = std::fs::remove_dir_all(&root);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    assert!(context.contains("Applicable engineering constraints:"));
    assert!(context.contains("Add an explicit timeout"));
}
#[test]
fn prompt_alias_is_accepted() {
    let root = native_fixture_root();
    let payload = json!({"cwd": root, "prompt": "document README.md"});
    let mut output = Vec::new();
    run(&mut payload.to_string().as_bytes(), &mut output);
    remove_intent(payload["cwd"].as_str().expect("fixture path").as_ref());
    let _ = std::fs::remove_dir_all(payload["cwd"].as_str().expect("fixture path"));
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

#[test]
fn non_native_route_prompt_emits_all_endpoint_security_guidance() {
    let root = native_fixture_root();
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/routes/api.py using @router.post jwt.decode request.get_json",
    });
    let mut output = Vec::new();
    let code = run_with_adapter(
        &mut payload.to_string().as_bytes(),
        &mut output,
        &CodexAdapter,
    );
    remove_intent(&root);
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid response JSON");
    let context = value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context string");

    assert_eq!(code, ExitCode::SUCCESS);
    for instruction in [
        "For each public or expensive route, document runtime validation, server-side authentication/authorization, rate limiting, secure cookies/CORS/CSRF, and non-debug defaults; report unknown semantics as review.",
        "For each public or expensive route, prove boundary validation, server-side authorization, rate limiting, secure cookie/CORS/CSRF settings, and non-debug defaults with runtime evidence; static signals never claim semantic proof.",
        "For public endpoints, require boundary validation, server-side auth/authorization, rate limits for expensive/public routes, secure cookies/CORS/CSRF, and non-debug defaults.",
    ] {
        assert!(
            context.contains(instruction),
            "missing endpoint guidance: {instruction}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
