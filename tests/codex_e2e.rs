//! Codex adapter lifecycle simulation with explicit JSON hook selection.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn run_hook(repo: &TempRepo, event: &str, payload: Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event, "--adapter", "codex"])
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", repo.path().join("bin").display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Codex hook spawns");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload writes");
    child.wait_with_output().expect("Codex hook completes")
}

fn tool_payload(repo: &TempRepo, event: &str, tool: &str, path: &str) -> Value {
    json!({
        "hookEventName": event,
        "session_id": "codex-e2e",
        "cwd": repo.path(),
        "tool_name": tool,
        "tool_input": {"file_path": path},
    })
}

fn install_fake_gitleaks(repo: &TempRepo) {
    let script = r#"#!/bin/sh
if [ "$1" = "version" ]; then echo "test-1.0"; exit 0; fi
report=""; source=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report-path) report="$2"; shift 2 ;;
    --source) source="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if grep -q 'PLANTED_SECRET_MARKER' "$source"; then
  printf '[{"RuleID":"test-secret","Description":"test finding","File":"%s","StartLine":1}]' "$source" > "$report"
  exit 2
fi
printf '[]' > "$report"
exit 0
"#;
    repo.write("bin/gitleaks", script);
    let path = repo.path().join("bin/gitleaks");
    let mut permissions = std::fs::metadata(&path)
        .expect("fake metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("fake executable");
}

#[test]
fn codex_hooks_deny_flag_block_allow_and_record_evidence() {
    let repo = TempRepo::new();
    install_fake_gitleaks(&repo);
    repo.write("src/app.py", "PLANTED_SECRET_MARKER = True\n");
    let path = repo.path().join("src/app.py");

    let denied = run_hook(
        &repo,
        "pre-tool-use",
        tool_payload(&repo, "PreToolUse", "Edit", "../outside.py"),
    );
    assert!(denied.status.success());
    let denied_json: Value = serde_json::from_slice(&denied.stdout).expect("deny JSON");
    assert_eq!(
        denied_json["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    let flagged = run_hook(
        &repo,
        "post-tool-use",
        tool_payload(&repo, "PostToolUse", "Write", &path.to_string_lossy()),
    );
    assert!(flagged.status.success());
    let flagged_json: Value = serde_json::from_slice(&flagged.stdout).expect("flag JSON");
    assert_eq!(flagged_json["decision"], "block");

    let blocked = run_hook(
        &repo,
        "stop",
        json!({
            "hookEventName": "Stop",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
        }),
    );
    assert!(
        blocked.status.success(),
        "Codex blocks through JSON, not exit 2"
    );
    let blocked_json: Value = serde_json::from_slice(&blocked.stdout).expect("Stop block JSON");
    assert_eq!(blocked_json["decision"], "block");

    repo.write("src/app.py", "value = 1\n");
    let clean = run_hook(
        &repo,
        "stop",
        json!({
            "hookEventName": "Stop",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
        }),
    );
    assert!(clean.status.success());
    assert!(String::from_utf8_lossy(&clean.stdout).contains("failed=0"));

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.lines().count() >= 2);
    let schema: Value = serde_json::from_str(include_str!("../schemas/evidence.schema.json"))
        .expect("evidence schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("evidence schema compiles");
    for line in evidence.lines() {
        let record: Value = serde_json::from_str(line).expect("evidence JSON");
        assert_eq!(record["task_id"], "codex-e2e");
        assert!(record["results"].is_array());
        let errors: Vec<_> = validator
            .iter_errors(&record)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "evidence schema violations: {errors:?}");
    }
}

#[test]
fn codex_hook_parse_failure_is_fail_safe() {
    let repo = TempRepo::new();
    let result = run_hook(&repo, "stop", json!({"hookEventName": "wrong"}));
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("codex hook failed"));
}
