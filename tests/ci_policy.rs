#[path = "common/mod.rs"]
mod common;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::TempRepo;

const WORKFLOW: &str = include_str!("../.github/workflows/lgtm.yml");
const STEP_NAME: &str = "      - name: Enforce unresolved MUST failures only\n";
const OUTCOME_EXPR: &str = "${{ steps.lgtm.outcome }}";

fn enforcement_script(outcome: &str) -> String {
    let step_start = WORKFLOW
        .find(STEP_NAME)
        .expect("workflow enforcement step should exist");
    let step = &WORKFLOW[step_start + STEP_NAME.len()..];
    let run_start = "        run: |\n";
    let script_start = step
        .find(run_start)
        .expect("enforcement step should use a run block")
        + run_start.len();
    let body = &step[script_start..];
    let script_end = body
        .find("      - name:")
        .expect("enforcement step should end at the next named step");

    body[..script_end]
        .lines()
        .map(|line| line.strip_prefix("          ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
        .replace(OUTCOME_EXPR, outcome)
}

fn enforcement_succeeds(outcome: &str, evidence: Option<&str>, log: &str) -> bool {
    let repo = TempRepo::new();
    if let Some(evidence) = evidence {
        repo.write(".lgtm/evidence/evidence.jsonl", evidence);
    }
    repo.write("lgtm-check.log", log);

    let script = enforcement_script(outcome);
    assert!(!script.contains(OUTCOME_EXPR));
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(script)
        .current_dir(repo.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("bash should start");
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        if let Some(status) = child.try_wait().expect("child status should be readable") {
            return status.success();
        }
        if Instant::now() >= deadline {
            // Timeout already fails the test; cleanup is best effort if the child just exited.
            let _ = child.kill();
            let _ = child.wait();
            panic!("workflow enforcement step exceeded its five-second timeout");
        }
        // This poll supervises a bounded subprocess, not application timing.
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn enforcement_blocks_only_unresolved_error_severity_failures() {
    let warning_failure = r#"{"results":[{"status":"failed","severity":"warning","rule_id":"RULE-1","message":"review"}]}"#;
    let error_failure = r#"{"results":[{"status":"failed","severity":"error","rule_id":"RULE-1","message":"must fix"}]}"#;
    let passed_error = r#"{"results":[{"status":"passed","severity":"error","rule_id":"RULE-1","message":"clean"}]}"#;

    assert!(enforcement_succeeds(
        "success",
        Some(warning_failure),
        "LGTM summary failed=1\n"
    ));
    assert!(!enforcement_succeeds(
        "success",
        Some(error_failure),
        "LGTM summary failed=1\n"
    ));
    assert!(enforcement_succeeds(
        "success",
        Some(passed_error),
        "LGTM summary failed=1\n"
    ));
    assert!(!enforcement_succeeds(
        "failure",
        Some(r#"{"results":[]}"#),
        "LGTM summary failed=0\n"
    ));
    assert!(!enforcement_succeeds(
        "success",
        None,
        "LGTM summary failed=0\n"
    ));
    assert!(!enforcement_succeeds(
        "success",
        Some("{not-json}\n"),
        "LGTM summary failed=0\n"
    ));
    assert!(!enforcement_succeeds(
        "success",
        Some(r#"{"results":[{"status":"broken","severity":"error"}]}"#),
        "LGTM summary failed=0\n"
    ));
    assert!(!enforcement_succeeds(
        "success",
        Some(r#"{"results":[{"status":"failed","severity":"error"}]} {"results":[]}"#),
        "LGTM summary failed=0\n"
    ));
}
