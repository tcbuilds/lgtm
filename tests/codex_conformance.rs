//! Opt-in smoke coverage for the installed Codex CLI hook contract.

use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn run_hook(repo: &TempRepo, event: &str, payload: Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event, "--adapter", "codex"])
        .current_dir(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lgtm hook starts");
    serde_json::to_writer(child.stdin.take().expect("hook stdin is piped"), &payload)
        .expect("hook payload writes");
    child.wait_with_output().expect("lgtm hook completes")
}

#[test]
fn codex_cli_conformance_is_opt_in_and_reports_not_applicable_cleanly() {
    if std::env::var_os("LGTM_CODEX_CONFORMANCE").is_none() {
        eprintln!("not_applicable: set LGTM_CODEX_CONFORMANCE=1 to run Codex smoke coverage");
        return;
    }
    let version = match Command::new("codex").arg("--version").output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).to_string()
        }
        Ok(output) => panic!(
            "Codex is present but --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => {
            eprintln!("not_applicable: Codex CLI unavailable ({error})");
            return;
        }
    };

    let repo = TempRepo::new();
    let init = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "codex", "--accept-guesses"])
        .current_dir(repo.path())
        .output()
        .expect("Codex init starts");
    assert!(init.status.success(), "Codex init failed: {:?}", init);
    let hooks = repo.read_json(".codex/hooks.json");
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "Stop",
    ] {
        assert!(hooks["hooks"][event].is_array(), "missing {event} wiring");
    }

    let cwd = repo.path().to_string_lossy().into_owned();
    let file = repo.path().join("safe.txt").to_string_lossy().into_owned();
    let payloads = [
        (
            "session-start",
            json!({"hookEventName":"SessionStart","cwd":cwd}),
        ),
        (
            "user-prompt-submit",
            json!({"hookEventName":"UserPromptSubmit","cwd":cwd,"prompt":"review this"}),
        ),
        (
            "pre-tool-use",
            json!({"hookEventName":"PreToolUse","cwd":cwd,"tool_name":"apply_patch","tool_input":{"file_path":file}}),
        ),
        (
            "permission-request",
            json!({"hookEventName":"PermissionRequest","cwd":cwd,"tool_name":"apply_patch","tool_input":{"file_path":file}}),
        ),
        (
            "post-tool-use",
            json!({"hookEventName":"PostToolUse","cwd":cwd,"tool_name":"apply_patch","tool_input":{"file_path":file}}),
        ),
        (
            "subagent-start",
            json!({"hookEventName":"SubagentStart","cwd":cwd,"agent_id":"agent-1","agent_type":"reviewer"}),
        ),
        (
            "subagent-stop",
            json!({"hookEventName":"SubagentStop","cwd":cwd,"stop_hook_active":true}),
        ),
        (
            "stop",
            json!({"hookEventName":"Stop","cwd":cwd,"stop_hook_active":true}),
        ),
    ];
    for (event, payload) in payloads {
        let output = run_hook(&repo, event, payload);
        assert!(output.status.success(), "{event} failed: {:?}", output);
        if !output.stdout.is_empty() {
            serde_json::from_slice::<Value>(&output.stdout)
                .unwrap_or_else(|error| panic!("{event} emitted invalid JSON: {error}"));
        }
    }
    eprintln!(
        "Codex conformance: version={} discovery=project-local trust=review-required-via-/hooks",
        version.trim()
    );
}
