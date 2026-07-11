//! Integration tests for `lgtm hook session-start`.
//!
//! Each test runs the compiled binary and pipes a SessionStart hook payload to
//! its stdin, asserting on the process exit code, stdout contract, and stderr.
//! A throwaway temporary directory is used as the resolved repo root so config
//! presence and detection are exercised end to end without touching the repo.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

/// Run `lgtm hook session-start`, piping `stdin`, and return exit code, stdout,
/// and stderr.
fn run_hook(stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "session-start"])
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

/// Parse a contract from stdout and return its `additionalContext`.
fn additional_context(stdout: &str) -> String {
    let value: Value = serde_json::from_str(stdout.trim()).expect("stdout must be JSON");
    assert_eq!(
        value["hookSpecificOutput"]["hookEventName"],
        json!("SessionStart")
    );
    value["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext must be a string")
        .to_string()
}

#[test]
fn valid_stdin_emits_contract_on_stdout() {
    let repo = TempRepo::new();
    let stdin = json!({
        "session_id": "s1",
        "transcript_path": "/tmp/t.jsonl",
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": repo.path().to_string_lossy(),
    })
    .to_string();

    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "session-start must exit 0");
    let context = additional_context(&stdout);
    assert!(context.contains("The harness is authoritative"));
    assert!(context.contains("Verification claims require evidence"));
}

#[test]
fn malformed_stdin_exits_zero_no_stdout_with_stderr() {
    let (code, stdout, stderr) = run_hook("{ definitely not json");
    assert_eq!(code, 0, "malformed stdin must exit 0 and never panic");
    assert!(
        stdout.is_empty(),
        "malformed stdin must produce no contract"
    );
    assert!(
        stderr.contains("parse failed: entity=stdin"),
        "malformed stdin must be diagnosed on stderr in the standard shape"
    );
}

#[test]
fn absent_config_notes_not_initialized() {
    let repo = TempRepo::new();
    let stdin = json!({ "cwd": repo.path().to_string_lossy() }).to_string();
    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0);
    let context = additional_context(&stdout);
    assert!(context.contains("lgtm is not initialized"));
    assert!(context.contains("lgtm init"));
}

#[test]
fn present_config_reflects_profile_and_commands() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[tool.ruff]\n");
    repo.write(
        ".lgtm/config.json",
        &json!({ "profile": "strict", "languages": ["python"] }).to_string(),
    );
    let stdin = json!({ "cwd": repo.path().to_string_lossy() }).to_string();

    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0);
    let context = additional_context(&stdout);
    assert!(context.contains("Profile: strict."));
    assert!(context.contains("Detected languages: python."));
    assert!(context.contains("ruff check ."));
}

#[test]
fn mismatched_config_version_is_surfaced_by_binary_hook() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"99","profile":"default"}"#,
    );
    let stdin = json!({ "cwd": repo.path() }).to_string();
    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "hook mismatch must fail safe");
    assert!(
        additional_context(&stdout).contains("config version mismatch: expected `1`, found `99`")
    );
}

#[test]
fn malformed_config_still_emits_contract_with_note() {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", "{ not valid");
    let stdin = json!({ "cwd": repo.path().to_string_lossy() }).to_string();
    let (code, stdout, _stderr) = run_hook(&stdin);
    assert_eq!(code, 0, "malformed config must fail safe");
    let context = additional_context(&stdout);
    assert!(
        context.contains("The harness is authoritative"),
        "malformed config must still emit the invariant bullets"
    );
    assert!(
        context.contains("config malformed"),
        "malformed config must note the fault in the contract"
    );
    assert!(
        context.contains("fix .lgtm/config.json"),
        "malformed config note must point at the file to fix"
    );
}
