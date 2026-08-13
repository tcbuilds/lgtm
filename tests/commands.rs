use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

const COVERAGE_RULE_ID: &str = "required-repository-commands";

fn run_post_tool_use(repo: &TempRepo, session_id: &str, file: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PostToolUse hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": session_id,
            "tool_name": "Write",
            "tool_input": {"file_path": repo.path().join(file)}
        })
    )
    .expect("payload writes");
    child.wait_with_output().expect("PostToolUse hook exits")
}

fn run_pre_tool_use_command(
    repo: &TempRepo,
    session_id: &str,
    command: &str,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PreToolUse hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": session_id,
            "tool_name": "Bash",
            "tool_input": {"command": command}
        })
    )
    .expect("payload writes");
    child.wait_with_output().expect("PreToolUse hook exits")
}

fn write_coverage_fixture(repo: &TempRepo, report: &str, line_threshold: u8, branch_threshold: u8) {
    repo.write(
        "bin/coverage",
        &format!("#!/bin/sh\nprintf '%s\n' '{report}'\n"),
    );
    let executable = repo.path().join("bin/coverage");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "coverage",
                "language": "shell",
                "root": ".",
                "commands": [],
                "coverage": [{
                    "argv": [executable.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": line_threshold,
                    "branch_threshold_percent": branch_threshold
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
}

fn write_coverage_executable(repo: &TempRepo, relative: &str, report: &str) -> String {
    repo.write(relative, &format!("#!/bin/sh\nprintf '%s\\n' '{report}'\n"));
    let executable = repo.path().join(relative);
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    executable.to_string_lossy().into_owned()
}

fn write_workspace_coverage_fixture(repo: &TempRepo) {
    let selected = write_coverage_executable(
        repo,
        "bin/selected-coverage",
        "line coverage: 100% branch coverage: 100%",
    );
    let other = write_coverage_executable(
        repo,
        "bin/other-coverage",
        "line coverage: 0% branch coverage: 0%",
    );
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [
                {
                    "id": "selected",
                    "language": "shell",
                    "root": ".",
                    "commands": [],
                    "coverage": [{
                        "argv": [selected],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                },
                {
                    "id": "other",
                    "language": "shell",
                    "root": ".",
                    "commands": [],
                    "coverage": [{
                        "argv": [other],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                }
            ],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
}

fn run_full_stop(repo: &TempRepo, session_id: &str, stop_hook_active: bool) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "check": true,
        "tier": "full",
        "stop_hook_active": stop_hook_active
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop hook starts");
    write!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("Stop hook exits")
}

fn run_stop_with_workspace(repo: &TempRepo, session_id: &str, workspace: &str) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "workspace": workspace,
        "tier": "full",
        "stop_hook_active": false
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("workspace Stop hook starts");
    write!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("Stop hook exits")
}

fn run_full_check(repo: &TempRepo) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--tier", "full"])
        .current_dir(repo.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("full check starts")
}

fn run_workspace_full_check(repo: &TempRepo, workspace: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--workspace", workspace, "--tier", "full"])
        .current_dir(repo.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("workspace full check starts")
}

fn latest_evidence(repo: &TempRepo) -> Value {
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    serde_json::from_str(evidence.lines().last().expect("evidence record")).expect("evidence JSON")
}

fn projected_coverage_result<'a>(record: &'a Value, status: &str) -> &'a Value {
    record["results"]
        .as_array()
        .expect("serialized results")
        .iter()
        .find(|result| {
            result["rule_id"].as_str() == Some(COVERAGE_RULE_ID)
                && result["status"].as_str() == Some(status)
        })
        .expect("projected coverage result")
}

#[test]
fn failing_required_command_blocks_commit_and_records_full_evidence() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write("bin/required-check", "#!/bin/sh\nexit 7\n");
    let executable = repo.path().join("bin/required-check");
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
    assert!(
        run_post_tool_use(&repo, "command-e2e", "src/app.rs")
            .status
            .success()
    );

    let output = run_pre_tool_use_command(&repo, "command-e2e", "git commit -m test");

    assert!(output.status.success(), "Claude deny uses a JSON response");
    let decision: Value = serde_json::from_slice(&output.stdout).expect("deny decision JSON");
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = decision["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("deny reason");
    assert!(reason.contains("pre-commit full gate failed"));
    assert!(reason.contains("required-repository-commands"));
    assert!(reason.contains("exit status 7"));

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["tier"], "full");
    assert_eq!(record["commands"][0]["exit_code"], 7);
    assert!(record["commands"][0]["duration_ms"].is_number());
    assert_eq!(
        record["commands"][0]["command"],
        executable.to_string_lossy().as_ref()
    );
}

#[test]
fn stop_is_targeted_and_reuses_successful_precommit_evidence() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let command_marker = repo.path().join("command-runs");
    let coverage_marker = repo.path().join("coverage-runs");
    let targeted_marker = repo.path().join("targeted-runs");
    repo.write(
        "bin/required-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    repo.write(
        "bin/coverage-check",
        "#!/bin/sh\nprintf x >> \"$1\"\necho 'line coverage: 85% branch coverage: 90%'\nexit 0\n",
    );
    repo.write(
        "bin/targeted-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    let command = repo.path().join("bin/required-check");
    let coverage = repo.path().join("bin/coverage-check");
    let targeted = repo.path().join("bin/targeted-check");
    for path in [&command, &coverage, &targeted] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [
                    {
                        "argv": [command.to_string_lossy(), command_marker.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "tier": "full",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    },
                    {
                        "argv": [targeted.to_string_lossy(), targeted_marker.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "tier": "targeted",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    }
                ],
                "coverage": [{
                    "argv": [coverage.to_string_lossy(), coverage_marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": 80,
                    "branch_threshold_percent": 90
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "precommit-full", "src/app.rs")
            .status
            .success()
    );
    let command_claim = format!("{} {}", command.display(), command_marker.display());
    repo.write(
        "transcript.jsonl",
        &format!(
            "{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n",
            serde_json::to_string(&format!("Ran `{command_claim}`; it passed.")).unwrap()
        ),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": "precommit-full",
            "transcript_path": repo.path().join("transcript.jsonl")
        })
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");
    assert_eq!(output.status.code(), Some(2));
    assert!(!command_marker.exists(), "Stop must not run full commands");
    assert!(!coverage_marker.exists(), "Stop must not run coverage");
    assert_eq!(repo.read("targeted-runs"), "x");

    let precommit = run_pre_tool_use_command(&repo, "precommit-full", "git commit -m test");
    assert!(
        precommit.status.success(),
        "PreToolUse stderr: {:?}",
        precommit.stderr
    );
    assert!(precommit.stdout.is_empty());
    assert_eq!(repo.read("command-runs"), "x");
    assert_eq!(repo.read("coverage-runs"), "x");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": "precommit-full",
            "transcript_path": repo.path().join("transcript.jsonl")
        })
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");
    assert!(output.status.success(), "Stop stderr: {:?}", output.stderr);
    assert_eq!(repo.read("command-runs"), "x", "Stop reran full command");
    assert_eq!(repo.read("coverage-runs"), "x", "Stop reran coverage");
    assert_eq!(repo.read("targeted-runs"), "xx");

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["tier"], "targeted");
    assert_eq!(
        record["commands"][0]["command"],
        format!("{} {}", targeted.display(), targeted_marker.display())
    );
}

#[test]
fn precommit_reuses_full_evidence_with_only_warning_severity_failures() {
    let repo = TempRepo::new();
    let oversized = format!(
        "pub fn oversized() {{\n{} }}\n",
        "    let value = 1;\n".repeat(51)
    );
    repo.write("src/app.rs", &oversized);
    let marker = repo.path().join("warning-gate-runs");
    repo.write(
        "bin/required-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    let executable = repo.path().join("bin/required-check");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "prototype",
            "workspaces": [{
                "id": "tests",
                "language": "rust",
                "root": ".",
                "commands": [{
                    "argv": [executable.to_string_lossy(), marker.to_string_lossy()],
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
            "severity_overrides": {"function-size": "warning"}
        })
        .to_string(),
    );

    let first = run_pre_tool_use_command(&repo, "warning-reuse", "git commit -m first");
    assert!(first.status.success());
    assert!(
        first.stdout.is_empty(),
        "first precommit output: {}",
        String::from_utf8_lossy(&first.stdout)
    );
    let first_record = latest_evidence(&repo);
    assert!(first_record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["rule_id"] == "function-size"
                && result["status"] == "failed"
                && result["severity"] == "warning"
        })
    }));
    assert_eq!(repo.read("warning-gate-runs"), "x");

    let second = run_pre_tool_use_command(&repo, "warning-reuse", "git commit -m second");
    assert!(second.status.success());
    assert!(
        second.stdout.is_empty(),
        "second precommit output: {}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert_eq!(
        repo.read("warning-gate-runs"),
        "x",
        "reusable warning-only evidence must avoid rerunning the full gate"
    );
}

#[test]
fn explicit_cli_tier_runs_only_requested_commands() {
    let repo = TempRepo::new();
    let marker = repo.path().join("executed");
    let mut commands = Vec::new();
    for (name, tier) in [("fast", "fast"), ("targeted", "targeted"), ("full", "full")] {
        let script = repo.path().join(format!("bin/{name}"));
        repo.write(
            &format!("bin/{name}"),
            "#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$1\"\nexit 0\n",
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
        commands.push(json!({
            "argv": [script.to_string_lossy(), marker.to_string_lossy(), name],
            "cwd": ".",
            "timeout_seconds": 30,
            "tier": tier,
            "purpose": "verify",
            "source": "fixture",
            "confidence": "high"
        }));
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "checks",
                "language": "shell",
                "root": ".",
                "commands": commands,
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    for tier in ["fast", "targeted", "full"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["check", "--tier", tier])
            .current_dir(repo.path())
            .output()
            .expect("check starts");
        assert!(
            output.status.success(),
            "{tier} stderr: {:?}",
            output.stderr
        );
        assert_eq!(repo.read("executed"), format!("{tier}\n"));
        std::fs::remove_file(&marker).expect("marker exists");
    }
}

#[test]
fn invalid_command_timeout_is_surfaced_as_unverified() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"command_timeout_seconds":0,"required_commands":{}}"#,
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"cwd":repo.path(),"session_id":"timeout-invalid","check":true})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    assert!(stdout.contains("between 1 and 3600"));
}

#[test]
fn passing_line_and_branch_coverage_passes_stop_and_persists_result() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 85% branch coverage: 90%", 80, 90);

    let output = run_full_stop(&repo, "coverage-pass", false);

    assert!(output.status.success(), "passing coverage must allow Stop");
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("failed=0"), "summary must report failed=0");
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(
        projected_coverage_result(&record, "passed")["status"],
        "passed"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn evidence_append_recovers_from_a_truncated_final_jsonl_record() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 100% branch coverage: 100%", 80, 80);
    assert!(
        run_full_stop(&repo, "before-truncation", false)
            .status
            .success()
    );
    let evidence_path = repo.path().join(".lgtm/evidence/evidence.jsonl");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&evidence_path)
        .and_then(|mut file| file.write_all(b"{\"task_id\":"))
        .expect("append truncated evidence tail");

    let output = run_full_stop(&repo, "after-truncation", false);

    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let latest: Value = serde_json::from_str(evidence.lines().last().expect("latest evidence"))
        .expect("latest evidence remains parseable JSON");
    assert_eq!(latest["task_id"], "after-truncation");
    assert!(!evidence.contains("{\"task_id\":{\"task_id\""));
}

#[test]
fn ratio_and_decimal_coverage_uses_the_percentage_value() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "line coverage: 120/120 100% branch coverage: 119/120 99.17%",
        100,
        99,
    );

    let output = run_full_stop(&repo, "coverage-ratio", false);

    assert!(
        output.status.success(),
        "ratio totals must not be parsed as percentages"
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(record["coverage"][0]["line_percent"], 100.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 99.17);
}

#[test]
fn out_of_range_coverage_is_unverified_and_persists_valid_evidence() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "line coverage: 120/120 120% branch coverage: 100%",
        80,
        80,
    );

    let output = run_full_stop(&repo, "coverage-out-of-range", false);

    assert!(
        output.status.success(),
        "invalid tool output must be unverified rather than fail open after an evidence error"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(record["coverage"][0]["line_percent"], Value::Null);
    assert_eq!(record["coverage"][0]["branch_percent"], 100.0);
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn workspace_scoped_full_check_ignores_other_workspace_coverage_failure() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_workspace_full_check(&repo, "selected");

    let record = latest_evidence(&repo);
    let coverage = record["coverage"].as_array().expect("coverage evidence");
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0]["workspace_id"], "selected");
    assert_eq!(coverage[0]["status"], "passed");
    assert!(
        output.status.success(),
        "selected workspace full check passes"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn full_check_without_workspace_selector_runs_all_coverage() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_full_check(&repo);

    assert!(
        !output.status.success(),
        "failing workspace must block all-workspace check"
    );
    let record = latest_evidence(&repo);
    let coverage = record["coverage"].as_array().expect("coverage evidence");
    assert_eq!(coverage.len(), 2);
    assert!(
        coverage
            .iter()
            .any(|item| { item["workspace_id"] == "selected" && item["status"] == "passed" })
    );
    assert!(
        coverage
            .iter()
            .any(|item| item["workspace_id"] == "other" && item["status"] == "failed")
    );
    let results = record["results"].as_array().expect("serialized results");
    assert!(results.iter().any(|result| {
        result["message"].as_str().is_some_and(|message| {
            message.contains("workspace=selected")
                && message.contains("scope=unit")
                && message.contains("tool=")
        })
    }));
    assert!(results.iter().any(|result| {
        result["message"].as_str().is_some_and(|message| {
            message.contains("workspace=other") && message.contains("failed configured thresholds")
        })
    }));
}

#[test]
fn unknown_workspace_selector_fails_in_central_check_execution() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_workspace_full_check(&repo, "typo");

    assert!(!output.status.success(), "unknown workspace must fail");
    let decision: Value =
        serde_json::from_slice(&output.stderr).expect("check block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains("unknown workspace `typo`"));
    assert!(reason.contains("available workspaces: selected, other"));
    assert!(reason.contains("select a configured workspace id"));
    let record = latest_evidence(&repo);
    assert!(record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["status"] == "failed"
                && result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("unknown workspace `typo`"))
        })
    }));
}

#[test]
fn unknown_workspace_selector_in_direct_hook_payload_is_denied() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_stop_with_workspace(&repo, "workspace-typo", "typo");

    assert_eq!(output.status.code(), Some(2));
    let decision: Value = serde_json::from_slice(&output.stderr).expect("Stop block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains("unknown workspace `typo`"));
    assert!(reason.contains("available workspaces: selected, other"));
    let record = latest_evidence(&repo);
    assert!(
        record["rules"]["failed"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert_eq!(record["coverage"][0]["status"], "not_applicable");
}

#[test]
fn below_threshold_coverage_blocks_stop_and_full_check() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);

    let stop = run_full_stop(&repo, "coverage-fail", false);

    assert_eq!(stop.status.code(), Some(2));
    let decision: Value = serde_json::from_slice(&stop.stderr).expect("block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains(COVERAGE_RULE_ID));
    assert!(reason.contains("coverage"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
    assert_eq!(
        projected_coverage_result(&record, "failed")["status"],
        "failed"
    );
    assert!(
        record["rules"]["failed"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );

    let check = run_full_check(&repo);

    assert!(
        !check.status.success(),
        "full check must fail below threshold"
    );
    let check_decision: Value =
        serde_json::from_slice(&check.stderr).expect("full check block decision JSON");
    assert_eq!(check_decision["decision"], "block");
    let check_reason = check_decision["reason"]
        .as_str()
        .expect("full check reason");
    assert!(check_reason.contains(COVERAGE_RULE_ID));
    assert!(check_reason.contains("coverage"));
}

#[test]
fn semantic_coverage_labels_ignore_baseline_substrings_end_to_end() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "Baseline coverage: 100%\nLine coverage: 50%\nBranch coverage: 90%",
        80,
        80,
    );

    let stop = run_full_stop(&repo, "coverage-label-boundary", false);

    assert_eq!(stop.status.code(), Some(2));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
    assert_eq!(record["coverage"][0]["line_percent"], 50.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 90.0);
}

#[test]
fn unparseable_coverage_is_unverified_and_does_not_fail_stop() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "coverage report unavailable", 80, 80);

    let output = run_full_stop(&repo, "coverage-unverified", false);

    assert!(
        output.status.success(),
        "unverified coverage must allow Stop"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(
        projected_coverage_result(&record, "unverified")["status"],
        "unverified"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn missing_coverage_executable_is_unverified_and_does_not_fail_stop() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 100% branch coverage: 100%", 80, 80);
    let missing = repo.path().join("bin/missing-coverage");
    let mut config: Value =
        serde_json::from_str(&repo.read(".lgtm/config.json")).expect("coverage config JSON");
    config["workspaces"][0]["coverage"][0]["argv"][0] = json!(missing);
    repo.write(".lgtm/config.json", &config.to_string());

    let output = run_full_stop(&repo, "coverage-missing", false);

    assert!(
        output.status.success(),
        "missing coverage executable must allow Stop"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(
        projected_coverage_result(&record, "unverified")["status"],
        "unverified"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn downgraded_coverage_failure_remains_actionable() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);
    let mut config: Value =
        serde_json::from_str(&repo.read(".lgtm/config.json")).expect("coverage config JSON");
    config["profile"] = json!("prototype");
    repo.write(".lgtm/config.json", &config.to_string());

    let output = run_full_check(&repo);

    assert!(
        output.status.success(),
        "warning-severity profile must not block"
    );
    let summary = String::from_utf8(output.stdout).expect("summary is UTF-8");
    assert!(summary.contains("REVIEW required-repository-commands"));
    assert!(summary.contains("workspace=coverage scope=unit tool="));
    assert!(summary.contains("raise coverage and rerun"));
}

#[test]
fn active_stop_hook_summarizes_failed_coverage_instead_of_blocking() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);

    let output = run_full_stop(&repo, "coverage-active", true);

    assert!(
        output.status.success(),
        "active Stop hook must return a summary"
    );
    assert!(
        output.stderr.is_empty(),
        "summary path must not emit a block"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|line| line.contains("failed=1"))
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
}
