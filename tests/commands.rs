use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

#[test]
fn failing_required_command_blocks_stop_and_records_evidence() {
    let repo = TempRepo::new();
    repo.write("bin/required-check", "#!/bin/sh\nexit 7\n");
    let executable = repo.path().join("bin/required-check");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "required_commands": {
                "tests": [executable.to_string_lossy()]
            }
        })
        .to_string(),
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
        json!({"cwd":repo.path(),"session_id":"timeout-invalid"})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    assert!(stdout.contains("between 1 and 3600"));
}
