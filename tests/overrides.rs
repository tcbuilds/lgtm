use std::process::Command;

use serde_json::Value;

mod common;
use common::TempRepo;

fn check(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--tier", "full"])
        .current_dir(repo.path())
        .output()
        .expect("explicit check completes")
}

#[test]
fn allowed_disable_is_recorded_in_task_evidence() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"disabled_rules":["new-behavior-tests-required"]}"#,
    );
    let output = check(&repo);
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
fn protected_rule_disable_is_rejected_by_explicit_check() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"disabled_rules":["no-committed-secrets"]}"#,
    );
    let output = check(&repo);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no-committed-secrets"));
    assert!(stderr.contains("non-overridable"));
}
