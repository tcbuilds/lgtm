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
    assert!(stdout.contains("src/app.py"));
    assert!(stdout.contains("example-rule: warning"));
    assert!(stdout.contains("pytest: exit=Some(0) duration_ms=12"));
    assert!(!stdout.contains("secret-value"));
    assert!(!stdout.contains("secret-command-value"));
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
