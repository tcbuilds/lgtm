use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use lgtm::adapter::{HookAdapter, HookEvent, HookResponse, OutputStream, PiAdapter};

mod common;
use common::TempRepo;

fn exact(event: HookEvent, response: HookResponse, expected: &str) {
    let encoded = PiAdapter
        .encode_response(event, response)
        .expect("Pi response is event-valid");
    assert_eq!(encoded.body, expected);
    assert_eq!(encoded.stream, OutputStream::Stdout);
    assert_eq!(encoded.exit_code, 0);
}

#[test]
fn pi_adapter_pins_allow_and_advisory_context_bytes() {
    exact(HookEvent::PreToolUse, HookResponse::Allow, "");
    exact(
        HookEvent::BeforeAgentStart,
        HookResponse::InjectMessage("guidance".to_string()),
        r#"{"message":{"content":"guidance","customType":"lgtm","display":false}}"#,
    );
    exact(
        HookEvent::BeforeAgentStart,
        HookResponse::InjectSystemPrompt("system".to_string()),
        r#"{"systemPrompt":"system"}"#,
    );
}

#[test]
fn pi_adapter_tool_result_only_replaces_content() {
    let encoded = PiAdapter
        .encode_response(
            HookEvent::PostToolUse,
            HookResponse::PostToolFeedback {
                reason: "review".to_string(),
            },
        )
        .expect("Pi tool result response is event-valid");
    assert_eq!(
        encoded.body,
        r#"{"content":[{"text":"review","type":"text"}]}"#
    );
    for field in ["details", "isError", "usage"] {
        assert!(
            !encoded.body.contains(field),
            "feedback must not replace {field}"
        );
    }
}

#[test]
fn pi_adapter_rejects_invalid_payloads_and_response_pairs() {
    for payload in ["{ not json", "null", "[]", "\"text\""] {
        assert!(
            PiAdapter
                .parse_request(HookEvent::PreToolUse, payload)
                .is_err()
        );
    }
    for payload in [r#"{"type":null}"#, r#"{"type":7}"#] {
        assert!(
            PiAdapter
                .parse_request(HookEvent::PreToolUse, payload)
                .is_err(),
            "malformed Pi event must be rejected: {payload}"
        );
    }
    assert!(
        PiAdapter
            .parse_request(HookEvent::PreToolUse, r#"{"type":"tool_result"}"#)
            .is_err()
    );
    for payload in [
        r#"{"type":"tool_call","toolName":"bash","input":{"command":"echo ok"},"cwd":"/repo"}"#,
        r#"{"type":"tool_call","toolName":"bash","input":{"command":"echo ok"},"sessionId":"session"}"#,
    ] {
        assert!(
            PiAdapter
                .parse_request(HookEvent::PreToolUse, payload)
                .is_err(),
            "tool events require cwd and session identity: {payload}"
        );
    }
    for event in [
        HookEvent::UserPromptSubmit,
        HookEvent::PermissionRequest,
        HookEvent::SubagentStart,
    ] {
        assert!(
            PiAdapter
                .parse_request(event, r#"{"type":"input"}"#)
                .is_err(),
            "unsupported Pi event must fail: {event:?}"
        );
    }
    assert!(
        PiAdapter
            .encode_response(
                HookEvent::Stop,
                HookResponse::PostToolFeedback {
                    reason: "unsupported".to_string(),
                },
            )
            .is_err()
    );
}

fn init_pi_repo(repo: &TempRepo) {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .env("HOME", repo.path())
        .current_dir(repo.path())
        .output()
        .expect("Pi init should execute");
    assert!(output.status.success(), "Pi init failed: {output:?}");
}

fn run_pi_hook(repo: &TempRepo, event: &str, payload: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event, "--adapter", "pi"])
        .env("HOME", repo.path())
        .current_dir(repo.path())
        .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Pi hook should spawn");
    child
        .stdin
        .take()
        .expect("hook stdin should be available")
        .write_all(payload.as_bytes())
        .expect("hook payload should be writable");
    child.wait_with_output().expect("Pi hook should finish")
}

/// Assert one Pi pre-tool observation left the permission decision to the host.
///
/// The automatic pre-tool path never answers the host agent's permission
/// decision, so valid tool metadata must exit successfully with no response on
/// stdout even when policy is missing, malformed, or prohibits the action.
fn assert_passthrough_without_permission_response(output: &std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} must exit successfully: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "{context} must not emit a permission response: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn every_pi_tool_policy_event_ignores_each_malformed_policy_file() {
    for malformed in ["config.json", "execpolicy.json"] {
        let repo = TempRepo::new();
        init_pi_repo(&repo);
        repo.write(&format!(".lgtm/{malformed}"), "not-json");
        let output = run_pi_hook(
            &repo,
            "pre-tool-use",
            &format!(
                r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"printf ok"}},"cwd":"{}","sessionId":"pi-session"}}"#,
                repo.path().display()
            ),
        );
        assert_passthrough_without_permission_response(&output, &format!("malformed {malformed}"));
    }
}

#[test]
fn pi_lowercase_tool_calls_reach_the_observer_without_a_permission_response() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    repo.write(
        ".lgtm/execpolicy.json",
        r#"{"prohibited_commands":[["rm","-rf"]]}"#,
    );
    let prohibited = run_pi_hook(
        &repo,
        "pre-tool-use",
        &format!(
            r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"rm -rf /"}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert_passthrough_without_permission_response(&prohibited, "a prohibited command");

    let benign = run_pi_hook(
        &repo,
        "pre-tool-use",
        &format!(
            r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"printf ok"}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert_passthrough_without_permission_response(&benign, "a benign command");
}

#[test]
fn prohibited_pi_edit_and_write_paths_reach_the_observer_without_a_permission_response() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    repo.write(
        ".lgtm/config.json",
        r#"{"prohibited_paths":["secrets/**"]}"#,
    );
    for tool in ["edit", "write"] {
        let output = run_pi_hook(
            &repo,
            "pre-tool-use",
            &format!(
                r#"{{"type":"tool_call","toolName":"{tool}","input":{{"path":"secrets/key.txt","edits":[],"content":"text"}},"cwd":"{}","sessionId":"pi-session"}}"#,
                repo.path().display()
            ),
        );
        assert_passthrough_without_permission_response(
            &output,
            &format!("a prohibited {tool} path"),
        );
    }
}

#[test]
fn malformed_pi_tool_input_exits_nonzero_without_stdout() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    let output = run_pi_hook(
        &repo,
        "pre-tool-use",
        &format!(
            r#"{{"type":"tool_call","toolName":"edit","input":{{"path":{{"nested":true}}}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tool input path is not a string"));
}

#[test]
fn missing_policy_does_not_fail_or_block_the_pi_pre_tool_observer() {
    for missing in [".lgtm/config.json", ".lgtm/execpolicy.json"] {
        let repo = TempRepo::new();
        init_pi_repo(&repo);
        std::fs::remove_file(repo.path().join(missing)).expect("remove policy fixture");
        let output = run_pi_hook(
            &repo,
            "pre-tool-use",
            &format!(
                r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"printf ok"}},"cwd":"{}","sessionId":"pi-session"}}"#,
                repo.path().display()
            ),
        );
        assert_passthrough_without_permission_response(&output, &format!("missing {missing}"));
    }
}

#[test]
fn malformed_policy_does_not_fail_or_block_the_pi_pre_tool_observer() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    repo.write(".lgtm/execpolicy.json", "{not valid json");
    let output = run_pi_hook(
        &repo,
        "pre-tool-use",
        &format!(
            r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"printf ok"}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert_passthrough_without_permission_response(&output, "a malformed execpolicy");
}

#[test]
fn unsupported_legacy_severity_does_not_fail_or_block_the_pi_pre_tool_observer() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    repo.write(
        ".lgtm/config.json",
        r#"{"severity_overrides":{"regression-test-required":"critical"}}"#,
    );
    let output = run_pi_hook(
        &repo,
        "pre-tool-use",
        &format!(
            r#"{{"type":"tool_call","toolName":"bash","input":{{"command":"printf ok"}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert_passthrough_without_permission_response(&output, "an unsupported legacy severity");
}

#[test]
fn pi_agent_end_does_not_write_settled_evidence() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    let ended = run_pi_hook(
        &repo,
        "agent-end",
        r#"{"type":"agent_end","sessionId":"pi-session"}"#,
    );
    assert!(ended.status.success());
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));

    let settled = run_pi_hook(
        &repo,
        "agent-settled",
        r#"{"type":"agent_settled","sessionId":"pi-session"}"#,
    );
    assert!(!settled.status.success());
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
}

#[cfg(unix)]
#[test]
fn concurrent_untrusted_pi_settled_events_do_not_write_evidence() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    let root = repo.path().to_path_buf();
    std::thread::scope(|scope| {
        for index in 0..8 {
            let root = root.clone();
            scope.spawn(move || {
                let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
                    .args(["hook", "agent-settled", "--adapter", "pi"])
                    .current_dir(&root)
                    .env("LGTM_HOOK_BINARY", env!("CARGO_BIN_EXE_lgtm"))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("settled hook spawns");
                child
                    .stdin
                    .take()
                    .expect("settled stdin")
                    .write_all(
                        format!("{{\"type\":\"agent_settled\",\"sessionId\":\"session-{index}\"}}")
                            .as_bytes(),
                    )
                    .expect("settled payload writes");
                assert!(!child.wait().expect("settled hook waits").success());
            });
        }
    });
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
}

#[cfg(unix)]
#[test]
fn pi_read_result_injects_matching_guidance_once_per_session() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    init_pi_repo(&repo);
    std::fs::set_permissions(repo.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private repository fixture");
    repo.write("src/app.py", "value = 1\n");
    let payload = |content: &str| {
        format!(
            r#"{{"type":"tool_result","toolName":"read","input":{{"path":"src/app.py","__lgtmPolicyInput":"lgtm-pi-policy-input-v1"}},"content":[{{"type":"text","text":"{content}"}}],"details":{{"source":"pi"}},"isError":false,"usage":{{"input":1}},"cwd":"{}","sessionId":"pi-read-session"}}"#,
            repo.path().display()
        )
    };

    let first = run_pi_hook(&repo, "post-tool-use", &payload("original"));
    assert!(first.status.success(), "first read hook failed: {first:?}");
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    assert!(first_stdout.contains("# Python"));
    assert!(first_stdout.contains("# Python Patterns"));
    assert!(!first_stdout.contains("\n# Rust\n"));
    assert!(!first_stdout.contains("<!-- lgtm-entry-document: standards-v1 -->"));

    let second = run_pi_hook(&repo, "post-tool-use", &payload("original"));
    assert!(
        second.status.success(),
        "second read hook failed: {second:?}"
    );
    assert!(
        second.stdout.is_empty(),
        "the shared session store must suppress duplicate guidance"
    );
}

#[cfg(unix)]
#[test]
fn pi_read_guidance_normalizes_absolute_nested_and_unsafe_paths() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let repo = TempRepo::new();
    let outside = TempRepo::new();
    init_pi_repo(&repo);
    std::fs::set_permissions(repo.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private repository fixture");
    repo.write("src/app.py", "value = 1\n");
    std::fs::create_dir(repo.path().join("workspace")).expect("nested cwd");
    outside.write("outside.py", "value = 2\n");
    symlink(
        outside.path().join("outside.py"),
        repo.path().join("link.py"),
    )
    .expect("escape symlink");

    let run_read = |path: &str, cwd: &Path, session: &str| {
        let payload = serde_json::json!({
            "type": "tool_result",
            "toolName": "read",
            "input": {
                "path": path,
                "__lgtmPolicyInput": "lgtm-pi-policy-input-v1"
            },
            "content": [{"type": "text", "text": "original"}],
            "isError": false,
            "cwd": cwd,
            "sessionId": session
        });
        run_pi_hook(&repo, "post-tool-use", &payload.to_string())
    };

    let absolute = run_read(
        &repo.path().join("src/app.py").to_string_lossy(),
        repo.path(),
        "absolute-session",
    );
    assert!(absolute.status.success());
    assert!(String::from_utf8_lossy(&absolute.stdout).contains("# Python"));

    let nested = run_read(
        "../src/app.py",
        &repo.path().join("workspace"),
        "nested-session",
    );
    assert!(nested.status.success());
    assert!(String::from_utf8_lossy(&nested.stdout).contains("# Python"));

    let symlinked = run_read("link.py", repo.path(), "symlink-session");
    assert!(!symlinked.status.success());
    assert!(symlinked.stdout.is_empty());

    let outside_path = outside.path().join("outside.py");
    let outside_read = run_read(
        &outside_path.to_string_lossy(),
        repo.path(),
        "outside-session",
    );
    assert!(!outside_read.status.success());
    assert!(outside_read.stdout.is_empty());
}

#[test]
fn pi_post_tool_dispatch_preserves_result_fields_when_no_feedback_is_needed() {
    let repo = TempRepo::new();
    init_pi_repo(&repo);
    repo.write(".git/HEAD", "ref: refs/heads/main\n");
    repo.write("notes.txt", "plain text\n");
    let output = run_pi_hook(
        &repo,
        "post-tool-use",
        &format!(
            r#"{{"type":"tool_result","toolName":"write","input":{{"path":"notes.txt","content":"plain text"}},"content":[{{"type":"text","text":"original"}}],"details":{{"marker":1}},"isError":false,"usage":{{"input":1}},"cwd":"{}","sessionId":"pi-session"}}"#,
            repo.path().display()
        ),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unverified"));
}

#[test]
fn pi_cli_dispatches_without_falling_through_to_claude() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "before-agent-start", "--adapter", "pi"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("lgtm binary should spawn");
    child
        .stdin
        .take()
        .expect("stdin should be piped")
        .write_all(b"{ not json")
        .expect("stdin write should succeed");
    let output = child.wait_with_output().expect("Pi hook should exit");
    assert!(!output.status.success());
    assert_eq!(output.stdout, b"");
    let stderr = String::from_utf8(output.stderr).expect("stderr should be UTF-8");
    assert!(stderr.contains("pi hook failed"));
    assert!(!stderr.contains("claude hook failed"));
}
