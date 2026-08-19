use std::process::Command;

use serde_json::json;

mod common;
use common::TempRepo;

#[test]
fn report_renders_latest_evidence_without_finding_descriptions() {
    let repo = TempRepo::new();
    let result = json!({
        "rule_id":"example-rule","status":"warning","severity":"warning",
        "message":"repo controlled secret-value","locations":[{"file":"src/app.py","line":4}],
        "evidence":{"check":"example.check","finding_descriptions":["secret-value"]}
    });
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"task-1","agent":"claude-code","profile":"default","results":[result],
                "commands":[{"command":"pytest --token secret-command-value","exit_code":0,"duration_ms":12}],
                "overrides":[{"rule_id":"example-rule","action":"severity","severity":"warning"}]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Task: task-1"));
    assert!(stdout.contains("Pi enforcement recorded: stale/unverified scope=none"));
    assert!(stdout.contains("Pi installation current: not-installed scope=none"));
    assert!(stdout.contains("Pi enforcement effective: stale/unverified scope=none"));
    assert!(stdout.contains("src/app.py"));
    assert!(stdout.contains("example-rule: warning"));
    assert!(stdout.contains("pytest: exit=Some(0) duration_ms=12"));
    assert!(!stdout.contains("secret-value"));
    assert!(!stdout.contains("secret-command-value"));
}

#[test]
fn report_never_upgrades_recorded_pi_state_after_extension_deletion() {
    let repo = TempRepo::new();
    let result = json!({
        "rule_id":"example-rule","status":"passed","severity":"info",
        "message":"ok","locations":[],"evidence":{"check":"example.check"}
    });
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"pi-task","agent":"claude-code","harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"attested"},
                "profile":"default","results":[result]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("Pi enforcement recorded: active scope=project"));
    assert!(stdout.contains("Pi installation current: not-installed scope=none"));
    assert!(stdout.contains("Pi enforcement effective: not-installed scope=none"));
}

#[test]
fn report_sanitizes_hostile_recorded_scope() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"hostile-scope","agent":"claude-code","harness":"pi",
                "enforcement":{"state":"active","scope":"../../escape","reason":"recorded"},
                "profile":"default","results":[]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("recorded: active scope=none"));
    assert!(!stdout.contains("escape"));
}

#[test]
fn malformed_evidence_fails_clearly() {
    let repo = TempRepo::new();
    repo.write("bad.jsonl", "not-json\n");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence", "bad.jsonl"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("malformed evidence line 1")
    );
}

#[test]
fn report_does_not_use_current_repository_for_external_evidence() {
    let evidence_repo = TempRepo::new();
    let current_repo = TempRepo::new();
    evidence_repo.write(
        "evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"session-b",
                "agent":"claude-code",
                "harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"recorded"},
                "profile":"default",
                "results":[]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(evidence_repo.path().join("evidence.jsonl"))
        .current_dir(current_repo.path())
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("current: unavailable"));
    assert!(stdout.contains("recorded-only"));
    assert!(!stdout.contains("Pi installation current: active"));
}

#[cfg(unix)]
#[test]
fn report_rejects_symlinked_evidence_ancestry_for_current_state() {
    use std::os::unix::fs::symlink;

    let target = TempRepo::new();
    target.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"symlinked",
                "agent":"claude-code",
                "harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"recorded"},
                "profile":"default",
                "results":[]
            })
        ),
    );
    let alias = TempRepo::new();
    symlink(target.path().join(".lgtm"), alias.path().join(".lgtm"))
        .expect("symlink lgtm directory");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(alias.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("current: unavailable"));
    assert!(stdout.contains("recorded-only"));
}

#[test]
fn report_dedupes_absolute_and_relative_repo_paths() {
    let repo = TempRepo::new();
    let absolute = repo.path().join("src/app.py");
    let outside = std::env::temp_dir().join("outside-report.py");
    let results = [
        json!({"rule_id":"one","status":"passed","severity":"error","message":"ok","locations":[{"file":"src/app.py"}],"evidence":{"check":"x"}}),
        json!({"rule_id":"two","status":"passed","severity":"error","message":"ok","locations":[{"file":absolute},{"file":outside}],"evidence":{"check":"x"}}),
    ];
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({"task_id":"paths","agent":"claude-code","profile":"default","results":results})
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("Files changed (2):"));
    assert_eq!(stdout.matches("- src/app.py").count(), 1);
    assert!(stdout.contains(&outside.to_string_lossy().to_string()));
}
