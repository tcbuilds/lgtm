use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn stop(repo: &TempRepo) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop starts");
    write!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"cwd": repo.path(), "session_id": "override-e2e"})
    )
    .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn allowed_disable_is_recorded_in_task_evidence() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"disabled_rules":["new-behavior-tests-required"]}"#,
    );
    let output = stop(&repo);
    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().unwrap()).unwrap();
    assert_eq!(
        record["overrides"][0]["rule_id"],
        "new-behavior-tests-required"
    );
    assert_eq!(record["overrides"][0]["action"], "disabled");
}

#[test]
fn security_disable_attempt_is_surfaced_without_blocking_hook_protocol() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"disabled_rules":["no-committed-secrets"]}"#,
    );
    let output = stop(&repo);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no-committed-secrets"));
    assert!(stderr.contains("non-overridable"));
}
