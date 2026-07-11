use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

mod common;
use common::TempRepo;

const EVENTS: [&str; 5] = [
    "session-start",
    "user-prompt-submit",
    "pre-tool-use",
    "post-tool-use",
    "stop",
];

fn run(event: &str, payload: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook starts");
    child
        .stdin
        .take()
        .expect("stdin available")
        .write_all(payload)
        .expect("payload writes");
    child.wait_with_output().expect("hook exits")
}

#[test]
fn every_hook_rejects_malformed_stdin_without_blocking_the_session() {
    for event in EVENTS {
        let output = run(event, b"{not-json");
        assert!(
            output.status.success(),
            "{event} blocked on malformed stdin"
        );
        assert!(
            !output.stderr.is_empty(),
            "{event} did not log malformed stdin"
        );
    }
}

#[test]
fn every_hook_survives_malformed_repository_config() {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", "{not-json");
    let payload = json!({
        "cwd": repo.path(),
        "session_id": "malformed-config",
        "user_prompt": "edit src/lib.py",
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/lib.py"}
    })
    .to_string();

    for event in EVENTS {
        let output = run(event, payload.as_bytes());
        assert!(
            output.status.success(),
            "{event} blocked the process on malformed config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn single_binary_cli_startup_remains_fast() {
    let started = Instant::now();
    for _ in 0..20 {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .arg("--version")
            .output()
            .expect("binary starts");
        assert!(output.status.success());
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "20 cold CLI starts exceeded five seconds"
    );
}
