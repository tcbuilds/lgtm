//! Integration tests for `lgtm hook post-tool-use`.
//!
//! Each test runs the compiled binary end to end: it pipes a PostToolUse hook
//! payload to stdin and asserts on the exit code, stdout decision envelope, and
//! the evidence JSONL written under the resolved repo root. The planted-secret
//! test exercises the real gitleaks binary, so it is skipped (not failed) when
//! gitleaks is not installed — a missing tool must never wedge the suite, the
//! same contract the hook itself honors.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

/// Run `lgtm hook post-tool-use`, piping `stdin`, returning exit code, stdout,
/// and stderr.
fn run_hook(stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lgtm binary should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(stdin.as_bytes())
        .expect("writing stdin should succeed");
    let output = child.wait_with_output().expect("process should complete");
    let code = output
        .status
        .code()
        .expect("process should exit with a code, not a signal");
    let stdout = String::from_utf8(output.stdout).expect("stdout should be valid UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be valid UTF-8");
    (code, stdout, stderr)
}

/// True when a `gitleaks` binary is on PATH. The planted-secret test needs the
/// real tool; when it is absent the test is skipped so the suite still passes on
/// a bare machine, matching the hook's own missing-tool contract.
fn gitleaks_available() -> bool {
    Command::new("gitleaks")
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The single evidence-ledger path relative to a repo root.
const LEDGER: &str = ".lgtm/evidence/current-task.results.jsonl";

#[test]
fn planted_secret_emits_block_naming_the_rule() {
    if !gitleaks_available() {
        eprintln!("skipping: gitleaks not installed");
        return;
    }
    let repo = TempRepo::new();
    // A realistic AWS access-key id plus a generic high-entropy key. The
    // EXAMPLE-suffixed AWS key gitleaks allowlists is deliberately avoided so the
    // scan actually flags the file. The AWS key prefix is assembled at runtime
    // from fragments so this test's own source never carries a literal
    // `AKIA...`-shaped token that lgtm's own secret scan (or gitleaks over this
    // repo) would flag.
    let aws_key = format!("{}{}", "AKIA", "Z3ROBME2X7HGKLMN");
    let generic_key = "a8f5f167f44f4964e6c998dee827110c";
    let leak_contents =
        format!("aws_access_key = \"{aws_key}\"\ngeneric = \"api_key = '{generic_key}'\"\n");
    repo.write("leak.py", &leak_contents);
    let leak_path = repo.path().join("leak.py");

    let stdin = json!({
        "session_id": "sess-block",
        "hook_event_name": "PostToolUse",
        "cwd": repo.path().to_string_lossy(),
        "tool_name": "Write",
        "tool_input": { "file_path": leak_path.to_string_lossy() },
        "tool_response": {},
    })
    .to_string();

    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "post-tool-use must always exit 0");

    let decision: Value =
        serde_json::from_str(stdout.trim()).expect("a secret finding must emit a JSON decision");
    assert_eq!(
        decision["decision"],
        json!("block"),
        "a secret finding must block"
    );
    let reason = decision["reason"]
        .as_str()
        .expect("block reason must be a string");
    assert!(
        reason.contains("no-committed-secrets"),
        "block reason must name the rule: {reason}"
    );
    assert!(
        reason.to_lowercase().contains("rotate"),
        "block reason must carry remediation: {reason}"
    );
    assert!(
        reason.starts_with("PostToolUse feedback: the tool already ran;"),
        "post-tool feedback must disclose that side effects already occurred: {reason}"
    );

    let ledger = repo.read(LEDGER);
    let record: Value = serde_json::from_str(ledger.lines().next().expect("a record was written"))
        .expect("evidence record must be valid JSON");
    assert_eq!(record["session_id"], json!("sess-block"));
    assert_eq!(record["result"]["status"], json!("failed"));
    assert_eq!(record["result"]["rule_id"], json!("no-committed-secrets"));
}

#[test]
fn clean_file_exits_zero_silently_and_records_pass() {
    if !gitleaks_available() {
        eprintln!("skipping: gitleaks not installed");
        return;
    }
    let repo = TempRepo::new();
    repo.write("ok.py", "def add(a, b):\n    return a + b\n");
    let clean_path = repo.path().join("ok.py");

    let stdin = json!({
        "session_id": "sess-clean",
        "hook_event_name": "PostToolUse",
        "cwd": repo.path().to_string_lossy(),
        "tool_name": "Edit",
        "tool_input": { "file_path": clean_path.to_string_lossy() },
    })
    .to_string();

    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "a clean scan must exit 0");
    assert!(
        stdout.trim().is_empty(),
        "a clean scan must emit no decision on stdout"
    );

    let ledger = repo.read(LEDGER);
    let record: Value = serde_json::from_str(ledger.lines().next().expect("a record was written"))
        .expect("evidence record must be valid JSON");
    assert_eq!(record["result"]["status"], json!("passed"));
}

#[test]
fn non_edit_tool_is_ignored_without_evidence() {
    let repo = TempRepo::new();
    let stdin = json!({
        "session_id": "sess-read",
        "hook_event_name": "PostToolUse",
        "cwd": repo.path().to_string_lossy(),
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/hostname" },
    })
    .to_string();

    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "an ignored tool must exit 0");
    assert!(
        stdout.trim().is_empty(),
        "an ignored tool must emit nothing"
    );
    assert!(
        !repo.exists(LEDGER),
        "an ignored tool must not write evidence"
    );
}

#[test]
fn malformed_stdin_exits_zero_with_diagnostic() {
    let (code, stdout, stderr) = run_hook("{ definitely not json");
    assert_eq!(code, 0, "malformed stdin must exit 0 and never block");
    assert!(
        stdout.trim().is_empty(),
        "malformed stdin must emit nothing"
    );
    assert!(
        stderr.contains("parse failed: entity=stdin"),
        "malformed stdin must be diagnosed in the standard shape: {stderr}"
    );
}
