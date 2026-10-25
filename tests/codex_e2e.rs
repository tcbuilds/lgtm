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

fn run_check(repo: &TempRepo) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--tier", "full"])
        .current_dir(repo.path())
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", repo.path().join("bin").display()),
        )
        .output()
        .expect("explicit check completes")
}

fn assert_completion_notice(repo: &TempRepo, output: &Output) {
    assert!(output.status.success(), "completion failed: {output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).expect("completion notice JSON");
    assert!(response.get("decision").is_none());
    let message = response["systemMessage"]
        .as_str()
        .expect("completion message");
    assert!(message.contains("no checks ran"), "{message}");
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
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
if grep -q 'PLANTED_''SECRET_MARKER' "$source"; then
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

fn initialize_git_repo(repo: &TempRepo) {
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
}

fn initialize_repo(repo: &TempRepo) {
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[],"disabled_rules":[],"severity_overrides":{}}"#,
    );
    repo.write(".gitignore", ".lgtm/evidence/\nbin/\n");
    initialize_git_repo(repo);
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
fn codex_chat_only_lifecycle_reports_without_checks_and_omits_unknown_intent() {
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
    assert_completion_notice(&repo, &stop);
    assert!(stop.stderr.is_empty(), "stderr: {:?}", stop.stderr);
}

// Production command containment is available on Linux; macOS must surface
// the unavailable-containment result rather than assert a command exit status.
#[cfg(target_os = "linux")]
#[test]
fn codex_commit_observation_does_not_run_an_explicit_check() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        "bin/full-check",
        "#!/bin/sh\nprintf checked > full-check-ran\nexit 9\n",
    );
    let executable = repo.path().join("bin/full-check");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [executable.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    initialize_git_repo(&repo);
    install_fake_gitleaks(&repo);

    let output = run_hook(
        &repo,
        "pre-tool-use",
        json!({
            "hookEventName": "PreToolUse",
            "session_id": "codex-commit",
            "cwd": repo.path(),
            "tool_name": "exec_command",
            "tool_input": {"cmd": "git commit -m test"},
        }),
    );

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "commit observation emitted a permission response"
    );
    assert!(!repo.exists("full-check-ran"));
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));

    let check = run_check(&repo);
    assert_eq!(check.status.code(), Some(2));
    assert_eq!(repo.read("full-check-ran"), "checked");
    assert!(String::from_utf8_lossy(&check.stdout).contains("exit status 9"));
}

#[test]
fn codex_config_only_turn_reports_without_completion_checks() {
    let repo = TempRepo::new();
    repo.write("settings.json", "{}\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "settings.json", "{\"enabled\":true}\n", true);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert_completion_notice(&repo, &stop);
}

#[test]
fn codex_source_edit_keeps_post_tool_test_association_feedback() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", true);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert_completion_notice(&repo, &stop);
    let records = repo.read(".lgtm/evidence/current-task.results.jsonl");
    let association = records
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|record| record["result"]["rule_id"] == "new-behavior-tests-required")
        .expect("post-tool association feedback");
    assert_eq!(association["result"]["status"], "unverified");
    assert!(
        association["result"]["message"]
            .as_str()
            .expect("association message")
            .contains("src/lib.rs")
    );
}

#[test]
fn codex_stop_does_not_verify_pending_assistant_claims() {
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
    assert_completion_notice(&repo, &stop);
}

#[test]
fn codex_completion_does_not_require_a_baseline() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    initialize_repo(&repo);
    let transcript = pending_transcript(&repo);

    record_edit(&repo, "src/lib.rs", "pub fn value() -> u8 { 2 }\n", false);
    let stop = run_hook(&repo, "stop", stop_payload(&repo, Some(transcript)));
    assert_completion_notice(&repo, &stop);
    assert!(!repo.exists(".lgtm/evidence/current-task.baseline.json"));
}

#[test]
fn codex_completion_does_not_require_an_assistant_transcript() {
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
    assert_completion_notice(&repo, &stop);
}

#[test]
fn codex_hooks_observe_and_explicit_checks_record_real_evidence() {
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

    let observed = run_hook(
        &repo,
        "pre-tool-use",
        tool_payload(&repo, "PreToolUse", "Edit", "../outside.py"),
    );
    assert!(observed.status.success());
    assert!(
        observed.stdout.is_empty(),
        "outside-path observation must not deny"
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
    assert!(
        command_denied.stdout.is_empty(),
        "legacy policy must not deny a command"
    );

    let flagged = run_hook(
        &repo,
        "post-tool-use",
        tool_payload(&repo, "PostToolUse", "Write", &path.to_string_lossy()),
    );
    assert!(flagged.status.success());
    let flagged_json: Value = serde_json::from_slice(&flagged.stdout).expect("flag JSON");
    assert!(flagged_json.get("decision").is_none());
    assert_eq!(
        flagged_json["hookSpecificOutput"]["hookEventName"],
        "PostToolUse"
    );
    assert!(
        flagged_json["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("feedback context")
            .contains("no-committed-secrets")
    );

    let completion = run_hook(
        &repo,
        "stop",
        json!({
            "hookEventName": "Stop",
            "session_id": "codex-e2e",
            "cwd": repo.path(),
        }),
    );
    assert_completion_notice(&repo, &completion);

    let subagent_completion = run_hook(
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
    assert_completion_notice(&repo, &subagent_completion);

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
    assert_completion_notice(&repo, &subagent_repeated);

    let failed_check = run_check(&repo);
    assert_eq!(failed_check.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&failed_check.stdout).contains("lgtm check failed"));

    repo.write("src/app.py", "value = 1\n");
    let clean_check = run_check(&repo);
    assert!(
        clean_check.status.success(),
        "clean explicit check failed: {clean_check:?}"
    );

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.lines().count() >= 2);
    let schema: Value = serde_json::from_str(include_str!("../schemas/evidence.schema.json"))
        .expect("evidence schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("evidence schema compiles");
    for line in evidence.lines() {
        let record: Value = serde_json::from_str(line).expect("evidence JSON");
        assert_eq!(record["task_id"], "unknown-session");
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
