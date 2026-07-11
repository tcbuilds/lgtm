mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use common::TempRepo;
use serde_json::json;

fn run_stop(repo: &TempRepo, claim: &str) -> std::process::Output {
    repo.write(
        ".lgtm/config.json",
        r#"{"required_commands":{"verify":["true"]}}"#,
    );
    repo.write("transcript.jsonl", &format!("{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n", serde_json::to_string(claim).expect("claim serializes")));
    let payload = json!({ "cwd": repo.path(), "session_id": "claims", "transcript_path": repo.path().join("transcript.jsonl") });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop starts");
    writeln!(child.stdin.take().expect("stdin"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("Stop completes")
}

#[test]
fn unsupported_success_claim_blocks_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`cargo test` passed");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("evidence-claims-honest"));
}

#[test]
fn matching_required_command_claim_passes_honesty_check() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`true` passed successfully");
    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.contains("evidence-claims-honest"));
    assert!(evidence.contains("\"status\":\"passed\""));
}
