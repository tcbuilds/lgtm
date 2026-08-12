use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

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

#[test]
fn failing_required_command_blocks_stop_and_records_evidence() {
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
        json!({"cwd": repo.path(), "session_id": "command-e2e"})
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");

    assert_eq!(output.status.code(), Some(2));
    let decision: Value = serde_json::from_slice(&output.stderr).expect("block decision JSON");
    assert_eq!(decision["decision"], "block");
    assert!(decision["reason"].as_str().is_some_and(|reason| {
        reason.contains("required-repository-commands") && reason.contains("exit status 7")
    }));

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["commands"][0]["exit_code"], 7);
    assert!(record["commands"][0]["duration_ms"].is_number());
    assert_eq!(
        record["commands"][0]["command"],
        executable.to_string_lossy().as_ref()
    );
}

#[test]
fn native_stop_runs_full_command_and_coverage_without_tier() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write("bin/required-check", "#!/bin/sh\nexit 0\n");
    repo.write(
        "bin/coverage-check",
        "#!/bin/sh\necho 'line coverage: 85% branch coverage: 90%'\nexit 0\n",
    );
    let command = repo.path().join("bin/required-check");
    let coverage = repo.path().join("bin/coverage-check");
    for path in [&command, &coverage] {
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
                "commands": [{
                    "argv": [command.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": [{
                    "argv": [coverage.to_string_lossy()],
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
        run_post_tool_use(&repo, "native-full", "src/app.rs")
            .status
            .success()
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
        json!({"cwd": repo.path(), "session_id": "native-full"})
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");
    assert!(output.status.success(), "Stop stderr: {:?}", output.stderr);

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["commands"][0]["exit_code"], 0);
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(record["coverage"][0]["line_percent"], 85.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 90.0);
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
