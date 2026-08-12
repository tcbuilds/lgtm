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

fn git(repo: &TempRepo, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(args)
        .status()
        .expect("git command runs");
    assert!(status.success(), "git command failed: {args:?}");
}

fn initialize_repo(repo: &TempRepo) {
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[],"disabled_rules":[],"severity_overrides":{}}"#,
    );
    repo.write(".gitignore", ".lgtm/evidence/\nbin/\n");
    git(repo, &["init", "-q"]);
    git(
        repo,
        &[
            "config",
            "user.email",
            "254259785+tcbuilds@users.noreply.github.com",
        ],
    );
    git(repo, &["config", "user.name", "LGTM tests"]);
    git(repo, &["add", "."]);
    git(repo, &["commit", "-qm", "fixture"]);
    install_fake_gitleaks(repo);
}

fn record_edit(repo: &TempRepo, path: &str, content: &str, capture_baseline: bool) {
    let absolute = repo.path().join(path);
    if capture_baseline {
        let pre = run_hook(
            repo,
            "pre-tool-use",
            tool_payload(repo, "PreToolUse", "Write", &absolute.to_string_lossy()),
        );
        assert!(pre.status.success());
        assert!(pre.stdout.is_empty());
    }
    repo.write(path, content);
    let post = run_hook(
        repo,
        "post-tool-use",
        tool_payload(repo, "PostToolUse", "Write", &absolute.to_string_lossy()),
    );
    assert!(post.status.success());
    assert!(post.stdout.is_empty());
}

fn pending_transcript(repo: &TempRepo) -> Value {
    repo.write(
        ".lgtm/evidence/transcript.jsonl",
        "{\"type\":\"user\",\"message\":{\"content\":[]}}\n",
    );
    json!(repo.path().join(".lgtm/evidence/transcript.jsonl"))
}

fn stop_payload(repo: &TempRepo, transcript_path: Option<Value>) -> Value {
    let mut payload = json!({
        "hookEventName": "Stop",
        "session_id": "codex-e2e",
        "cwd": repo.path(),
    });
    if let Some(path) = transcript_path {
        payload["transcript_path"] = path;
    }
    payload
}

#[test]
fn codex_chat_only_lifecycle_is_silent_and_omits_unknown_intent() {
    let repo = TempRepo::new();
    initialize_repo(&repo);

    let prompt = run_hook(
        &repo,
        "user-prompt-submit",
        json!({
            "hookEventName": "UserPromptSubmit",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
            "prompt": "what is this repository?",
        }),
    );
    assert!(prompt.status.success());
    assert!(!String::from_utf8_lossy(&prompt.stdout).contains("Detected task intent: unknown"));

    let stop = run_hook(&repo, "stop", stop_payload(&repo, None));
    assert!(stop.status.success());
    assert!(
        stop.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&stop.stdout)
    );
    assert!(
        stop.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

#[test]
fn codex_config_only_turn_has_no_test_association_noise() {
    let repo = TempRepo::new();
    repo.write("settings.json", "{}\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "settings.json", "{\"enabled\":true}\n", true);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert!(stop.status.success());
    let response: Value = serde_json::from_slice(&stop.stdout).expect("Stop summary JSON");
    assert_eq!(response["systemMessage"], "lgtm: passed");
}

#[test]
fn codex_source_edit_keeps_actionable_test_association_signal() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", true);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert!(stop.status.success());
    let response: Value = serde_json::from_slice(&stop.stdout).expect("Stop summary JSON");
    let summary = response["systemMessage"].as_str().expect("summary text");
    assert!(summary.contains("UNVERIFIED new-behavior-tests-required"));
    assert!(summary.contains("src/lib.rs"));
}

#[test]
fn codex_stop_defers_claims_until_assistant_transcript_exists() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        "tests/lib_test.rs",
        "#[test]\nfn value_is_one() { assert_eq!(1, 1); }\n",
    );
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", true);
    record_edit(
        &repo,
        "tests/lib_test.rs",
        "#[test]\nfn value_is_two() { assert_eq!(2, 2); }\n",
        true,
    );
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert!(stop.status.success());
    let response: Value = serde_json::from_slice(&stop.stdout).expect("Stop summary JSON");
    assert_eq!(response["systemMessage"], "lgtm: passed");
}

#[test]
fn codex_source_edit_without_baseline_stays_unverified() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", false);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert!(stop.status.success());
    let response: Value = serde_json::from_slice(&stop.stdout).expect("Stop summary JSON");
    let summary = response["systemMessage"].as_str().expect("summary text");
    assert!(summary.contains("UNVERIFIED preserve-unrelated-user-changes"));
}

#[test]
fn codex_source_edit_without_transcript_stays_unverified() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        "tests/lib_test.rs",
        "#[test]\nfn value_is_one() { assert_eq!(1, 1); }\n",
    );
    initialize_repo(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", true);
    record_edit(
        &repo,
        "tests/lib_test.rs",
        "#[test]\nfn value_is_two() { assert_eq!(2, 2); }\n",
        true,
    );
    let stop = run_hook(&repo, "stop", stop_payload(&repo, None));
    assert!(stop.status.success());
    let response: Value = serde_json::from_slice(&stop.stdout).expect("Stop summary JSON");
    let summary = response["systemMessage"].as_str().expect("summary text");
    assert!(summary.contains("UNVERIFIED evidence-claims-honest"));
}

#[test]
fn codex_hooks_deny_flag_block_allow_and_record_evidence() {
    let repo = TempRepo::new();
    install_fake_gitleaks(&repo);
    repo.write(
        ".lgtm/execpolicy.json",
        &format!(
            r#"{{"prohibited_commands":[["git","{}","--hard"]]}}"#,
            "reset"
        ),
    );
    repo.write("src/app.py", "PLANTED_SECRET_MARKER = True\n");
    let path = repo.path().join("src/app.py");

    let subagent_start = run_hook(
        &repo,
        "subagent-start",
        json!({
            "hookEventName": "SubagentStart",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
            "agent_id": "agent-1",
            "agent_type": "reviewer",
        }),
    );
    assert!(subagent_start.status.success());
    let subagent_context: Value =
        serde_json::from_slice(&subagent_start.stdout).expect("subagent context JSON");
    assert_eq!(
        subagent_context["hookSpecificOutput"]["hookEventName"],
        "SubagentStart"
    );

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

    let command_denied = run_hook(
        &repo,
        "permission-request",
        json!({
            "hookEventName": "PermissionRequest",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
            "tool_name": "Bash",
            "tool_input": {"command": format!("git {} --hard HEAD", "reset")},
        }),
    );
    assert!(command_denied.status.success());
    let command_json: Value =
        serde_json::from_slice(&command_denied.stdout).expect("command deny JSON");
    assert_eq!(
        command_json["hookSpecificOutput"]["decision"]["behavior"],
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

    let subagent_blocked = run_hook(
        &repo,
        "subagent-stop",
        json!({
            "hookEventName": "SubagentStop",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
            "agent_id": "agent-1",
            "agent_type": "reviewer",
            "stop_hook_active": false,
        }),
    );
    assert!(subagent_blocked.status.success());
    let subagent_json: Value =
        serde_json::from_slice(&subagent_blocked.stdout).expect("subagent block JSON");
    assert_eq!(subagent_json["decision"], "block");

    let subagent_repeated = run_hook(
        &repo,
        "subagent-stop",
        json!({
            "hookEventName": "SubagentStop",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
            "agent_id": "agent-1",
            "agent_type": "reviewer",
            "stop_hook_active": true,
        }),
    );
    assert!(subagent_repeated.status.success());
    let repeated_json: Value =
        serde_json::from_slice(&subagent_repeated.stdout).expect("subagent summary JSON");
    assert!(repeated_json["systemMessage"].as_str().is_some());

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

    let subagent = run_hook(&repo, "subagent-stop", json!({"hookEventName": "Stop"}));
    assert!(subagent.status.success());
    assert!(subagent.stdout.is_empty());

    let permission = run_hook(
        &repo,
        "permission-request",
        json!({"hookEventName": "Stop"}),
    );
    assert!(permission.status.success());
    assert!(permission.stdout.is_empty());
}
