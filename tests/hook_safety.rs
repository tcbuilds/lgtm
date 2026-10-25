use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::PathBuf;
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

// Bound every spawned process so a hung hook or check cannot stall the suite.
const HOOK_DEADLINE: Duration = Duration::from_secs(15);
#[cfg(target_os = "linux")]
const CHECK_DEADLINE: Duration = Duration::from_secs(30);
const COMPLETION_SUMMARY: &str = "no checks ran at completion";
const CONFIGURED_COMMAND_EXIT_CODE: i32 = 7;

fn hook_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Run a command with piped stdin and a deadline-based wait.
///
/// The child is killed when the deadline passes, then `wait_with_output` drains
/// both pipes after the process has exited, so a full pipe cannot block it.
fn run_bounded(mut command: Command, payload: Option<&[u8]>, limit: Duration) -> Output {
    let mut child = command.spawn().expect("process starts");
    if let Some(payload) = payload {
        child
            .stdin
            .take()
            .expect("stdin available")
            .write_all(payload)
            .expect("payload writes");
    }
    let deadline = Instant::now() + limit;
    while child.try_wait().expect("child state readable").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("output captured")
}

fn run(event: &str, payload: &[u8]) -> Output {
    run_bounded(hook_command(&["hook", event]), Some(payload), HOOK_DEADLINE)
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

// Automatic completion hooks must ignore every payload field, including a
// `check: true` full-tier request, and only report that checks are on demand.
#[cfg(unix)]
struct CompletionHook {
    name: &'static str,
    args: &'static [&'static str],
    hook_event_name: Option<&'static str>,
    protocol: &'static str,
}

#[cfg(unix)]
const COMPLETION_HOOKS: [CompletionHook; 3] = [
    CompletionHook {
        name: "claude-stop",
        args: &["hook", "stop"],
        hook_event_name: None,
        protocol: "claude",
    },
    CompletionHook {
        name: "codex-stop",
        args: &["hook", "stop", "--adapter", "codex"],
        hook_event_name: Some("Stop"),
        protocol: "codex",
    },
    CompletionHook {
        name: "codex-subagent-stop",
        args: &["hook", "subagent-stop", "--adapter", "codex"],
        hook_event_name: Some("SubagentStop"),
        protocol: "codex",
    },
];

#[cfg(unix)]
fn completion_payload(repo: &TempRepo, transcript: &str, hook_event_name: Option<&str>) -> String {
    let mut payload = json!({
        "cwd": repo.path(),
        "session_id": "completion-safety",
        "transcript_path": transcript,
        "check": true,
        "workspace": "verify",
        "tier": "full",
    });
    if let Some(name) = hook_event_name {
        payload["hookEventName"] = json!(name);
    }
    payload.to_string()
}

#[cfg(unix)]
fn assert_completion_only(hook: &CompletionHook, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{} must exit 0, stderr: {stderr}",
        hook.name
    );
    for stream in [&*stdout, &*stderr] {
        assert!(
            !stream.contains("\"decision\""),
            "{} emitted a blocking decision: {stream}",
            hook.name
        );
        assert!(
            !stream.contains("permissionDecision"),
            "{} emitted a permission denial: {stream}",
            hook.name
        );
        assert!(
            !stream.to_ascii_lowercase().contains("passed"),
            "{} claimed checks passed: {stream}",
            hook.name
        );
    }
    match hook.protocol {
        "claude" => assert!(
            stdout.contains(COMPLETION_SUMMARY),
            "{} must report that no checks ran: {stdout}",
            hook.name
        ),
        "codex" => {
            let parsed: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("codex completion must emit JSON");
            assert!(
                parsed.get("decision").is_none(),
                "{} emitted a codex blocking decision: {stdout}",
                hook.name
            );
            let summary = parsed
                .get("systemMessage")
                .and_then(serde_json::Value::as_str)
                .expect("codex completion must carry a systemMessage");
            assert!(
                summary.contains(COMPLETION_SUMMARY),
                "{} must report that no checks ran: {stdout}",
                hook.name
            );
        }
        other => panic!("unknown completion protocol {other}"),
    }
}

// A valid V2 policy with one full-tier command that marks its run and fails.
#[cfg(unix)]
struct CheckFixture {
    repo: TempRepo,
    marker: PathBuf,
}

#[cfg(unix)]
impl CheckFixture {
    fn new() -> Self {
        let repo = TempRepo::new();
        let script = repo.path().join("check.sh");
        let marker = repo.path().join("check-marker");
        repo.write(
            "check.sh",
            &format!("#!/bin/sh\nprintf checked > \"$1\"\nexit {CONFIGURED_COMMAND_EXIT_CODE}\n"),
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("configured command should be executable");
        repo.write(
            ".lgtm/config.json",
            &json!({
                "version": "2",
                "profile": "default",
                "workspaces": [{
                    "id": "verify",
                    "language": "shell",
                    "root": ".",
                    "commands": [{
                        "argv": [script.display().to_string(), marker.display().to_string()],
                        "cwd": ".",
                        "timeout_seconds": 10,
                        "tier": "full",
                        "purpose": "test",
                        "source": "manual-smoke",
                        "confidence": "high"
                    }]
                }],
                "disabled_rules": [],
                "severity_overrides": {}
            })
            .to_string(),
        );
        Self { repo, marker }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum PolicyState {
    Valid,
    Malformed,
    Missing,
}

#[cfg(unix)]
fn apply_policy_state(repo: &TempRepo, state: PolicyState) {
    match state {
        PolicyState::Valid => {}
        PolicyState::Malformed => repo.write(".lgtm/config.json", "{not-json"),
        PolicyState::Missing => {
            std::fs::remove_file(repo.path().join(".lgtm/config.json"))
                .expect("fixture policy should be removable");
        }
    }
}

#[cfg(target_os = "linux")]
fn check_command(repo: &TempRepo) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command
        .args(["check", "--tier", "full", "--workspace", "verify"])
        .current_dir(repo.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[cfg(unix)]
#[test]
fn automatic_completion_hooks_never_run_a_configured_full_tier_command() {
    let fixture = CheckFixture::new();
    let transcript = fixture
        .repo
        .path()
        .join("absent-transcript.jsonl")
        .display()
        .to_string();

    for hook in &COMPLETION_HOOKS {
        let payload = completion_payload(&fixture.repo, &transcript, hook.hook_event_name);
        let output = run_bounded(
            hook_command(hook.args),
            Some(payload.as_bytes()),
            HOOK_DEADLINE,
        );
        assert_completion_only(hook, &output);
        assert!(
            !fixture.marker.exists(),
            "{} must not run the configured full-tier command",
            hook.name
        );
    }
}

#[cfg(unix)]
#[test]
fn broken_policy_and_transcript_state_never_turns_completion_into_a_denial_or_a_check() {
    let fixture = CheckFixture::new();
    let absent = fixture
        .repo
        .path()
        .join("absent-transcript.jsonl")
        .display()
        .to_string();
    let directory = fixture.repo.path().display().to_string();

    let cases = [
        (
            "valid policy with an absent transcript",
            PolicyState::Valid,
            absent.as_str(),
        ),
        (
            "valid policy with a directory transcript",
            PolicyState::Valid,
            directory.as_str(),
        ),
        ("malformed policy", PolicyState::Malformed, absent.as_str()),
        ("missing policy", PolicyState::Missing, absent.as_str()),
    ];

    for (state_name, state, transcript) in cases {
        apply_policy_state(&fixture.repo, state);
        for hook in &COMPLETION_HOOKS {
            let payload = completion_payload(&fixture.repo, transcript, hook.hook_event_name);
            let output = run_bounded(
                hook_command(hook.args),
                Some(payload.as_bytes()),
                HOOK_DEADLINE,
            );
            assert_completion_only(hook, &output);
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains("check failed"),
                "{} with {state_name} reported a failed check",
                hook.name
            );
            assert!(
                !fixture.marker.exists(),
                "{} with {state_name} must not run the configured command",
                hook.name
            );
        }
    }
}

// Positive control: the same valid policy must still run the configured command
// when a check is requested explicitly, so the absent-marker assertions above
// cannot pass because the fixture itself is broken. Command execution
// containment is Linux-only, matching the repository's other command tests.
#[cfg(target_os = "linux")]
#[test]
fn explicit_lgtm_check_still_runs_the_configured_full_tier_command() {
    let fixture = CheckFixture::new();

    let output = run_bounded(check_command(&fixture.repo), None, CHECK_DEADLINE);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report = format!("{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(&fixture.marker).ok().as_deref(),
        Some("checked"),
        "explicit lgtm check must run the configured full-tier command; stdout: {} stderr: {stderr}",
        String::from_utf8_lossy(&output.stdout),
    );
    assert!(
        !output.status.success(),
        "configured command exit {CONFIGURED_COMMAND_EXIT_CODE} must fail an explicit check, stderr: {stderr}"
    );
    assert!(
        report.contains("lgtm check failed:"),
        "explicit check must report the failing command: {report}"
    );
    assert!(
        report.contains("required-repository-commands"),
        "explicit check must attribute the failure to the configured command: {report}"
    );
}
