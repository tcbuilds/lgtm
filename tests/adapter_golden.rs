//! Golden adapter-contract tests for all five Claude Code lifecycle hooks.
//!
//! These lock today's exact stdin -> (stdout, stderr, exit-code) behavior for
//! every normalized outcome the adapter can emit: allow, inject-context, deny,
//! and block/stop. They drive the compiled binary end to end, so they are
//! decoupled from the adapter's internal structure and must pass unchanged
//! across the adapter-neutral refactor. If any golden output changes, the
//! refactor is wrong; fix the refactor, never the golden.
//!
//! Assertion contract: every case asserts the exact stdout bytes (full-string
//! equality, never parsed-JSON, so key order, escaping, and the trailing
//! newline are all locked), the exact exit code, and stderr. Stderr is asserted
//! byte-for-byte where it is deterministic (empty, or a fixed diagnostic line).
//! The only stderr that is not byte-stable is a PostToolUse block's operator
//! diagnostics: their exact set depends on which external scanners (gitleaks,
//! ruff, semgrep) and whether a git repo are present on the runner, so those
//! cases assert the deterministic invariant instead — no decision leaks to
//! stderr, every line is a well-formed operator diagnostic, and the
//! config-version diagnostic is present.
//!
//! Determinism: every fixture is a throwaway repo with pinned config, and paths
//! that appear in output are derived in-test from the temp dir we control.
//!
//! Block-path coverage: two PostToolUse block goldens exist. The native module
//! dependency cycle (`post_tool_use_blocks_native_module_cycle`) requires no
//! external tool and runs on every runner. The secret-scan block
//! (`post_tool_use_blocks_secret_on_stdout_exit_zero`) additionally locks the
//! `gitleaks` path and runs only where `gitleaks` is installed, matching the
//! hook's own missing-tool contract.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

mod common;
use common::TempRepo;

/// The config-version diagnostic every hook that loads an unversioned config
/// emits to stderr. The throwaway fixtures pin no config version, so this line
/// is deterministic regardless of which external scanners are installed.
const CONFIG_VERSION_DIAGNOSTIC: &str = "validate failed: entity=config-version reason=version missing; legacy compatibility accepted, run lgtm init retryable=false";

/// Run `lgtm hook <event>`, piping `stdin`, returning (exit code, stdout,
/// stderr). A process killed by a signal has no code and fails the test.
fn run_hook(event: &str, stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event])
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

/// True when a `gitleaks` binary is on PATH.
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

/// Assert the deterministic invariant for a PostToolUse block's stderr, whose
/// exact diagnostic set is runner-dependent (varies with the presence of
/// gitleaks, ruff, semgrep, and git): the decision never leaks to stderr, the
/// unversioned-config diagnostic is always emitted, and every line is a
/// well-formed operator diagnostic of the shape `<action> failed: entity=<id>
/// reason=<cause> retryable=<bool>`.
fn assert_operator_diagnostics(stderr: &str) {
    assert!(
        !stderr.contains("\"decision\""),
        "a PostToolUse decision must never leak onto stderr: {stderr:?}"
    );
    assert!(
        stderr.contains(CONFIG_VERSION_DIAGNOSTIC),
        "the config-version diagnostic must be present on stderr: {stderr:?}"
    );
    for line in stderr.lines() {
        assert!(
            line.contains(" failed: entity=")
                && (line.ends_with(" retryable=true") || line.ends_with(" retryable=false")),
            "every stderr line must be a well-formed operator diagnostic: {line:?}"
        );
    }
}

#[test]
fn session_start_injects_context_envelope() {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", "{}");
    let stdin = json!({ "cwd": repo.path(), "source": "startup" }).to_string();

    let (code, stdout, stderr) = run_hook("session-start", &stdin);
    assert_eq!(code, 0, "session-start must always exit 0");
    assert_eq!(
        stdout,
        concat!(
            r#"{"hookSpecificOutput":{"additionalContext":"lgtm engineering harness — active.\n"#,
            r#"- The harness is authoritative.\n"#,
            r#"- Hook failures must be fixed, not bypassed.\n"#,
            r#"- Verification claims require evidence; do not claim a check passed unless it ran.\n"#,
            r#"- Repository-local conventions take precedence unless they violate a MUST rule.\n"#,
            r#"- Do not bypass or edit harness files unless the task explicitly concerns the harness.\n"#,
            r#"Session source: startup.\nProfile: default.\nDetected languages: none.\n"#,
            r#"Configured languages: none.\nRequired commands: none detected.\n"#,
            r#"Config version missing; legacy compatibility accepted. Run `lgtm init` to add the current version pin."#,
            r#"","hookEventName":"SessionStart"}}"#,
            "\n"
        ),
        "SessionStart envelope must be byte-for-byte stable"
    );
    assert_eq!(
        stderr, "",
        "SessionStart must emit nothing on stderr: {stderr:?}"
    );
}

#[test]
fn user_prompt_submit_injects_intent_framed_context() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[project]\nname = \"fixture\"\n");
    repo.write("src/routes/events.py", "def route():\n    pass\n");
    let stdin = json!({
        "cwd": repo.path(),
        "user_prompt": "fix src/routes/events.py using requests.post",
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("user-prompt-submit", &stdin);
    assert_eq!(code, 0, "user-prompt-submit must always exit 0");
    assert_eq!(
        stdout,
        concat!(
            r#"{"hookSpecificOutput":{"additionalContext":"Detected task intent: bug-fix.\n\n"#,
            r#"Applicable engineering constraints:\n\nMUST\n"#,
            r#"- Add an explicit timeout and ensure cancellation or cleanup is handled.\n"#,
            r#"- Add deterministic tests for new or changed source behavior.\n"#,
            r#"- Do not claim a command or tests passed unless current Stop evidence proves exit status 0.\n"#,
            r#"- Preserve unrelated work and restrict edits to files recorded for this task.\n"#,
            r#"- Run every configured repository validation command and fix failures.\n\nREVIEW\n"#,
            r#"- Files over 300 lines require review and should be split before 500 lines.\n"#,
            r#"- Functions should keep parameters, nesting, and cyclomatic complexity bounded.\n"#,
            r#"- Keep functions near 20–30 lines and split before 50 unless a documented exemption applies.\n"#,
            r#"- Review the diff for debug prints, scaffolding, broad suppressions, and temporary code.\n\n"#,
            r#"Verification required:\n- check: command.required\n- check: git.diff\n"#,
            r#"- check: native.file-size\n- check: native.function-complexity\n- check: native.function-size\n"#,
            r#"- check: semgrep.external-call-timeout\n- check: transcript.claims\n"#,
            r#"- evidence: changed_locations\n- evidence: check_result\n- evidence: command_result\n\n"#,
            r#"Examples (guidance only):\n"#,
            r#"- good: keep one abstraction level; bad: combine unrelated branches\n"#,
            r#"- good: satisfy External calls require timeouts; bad: bypass it\n"#,
            r#"- good: satisfy New behavior tests required; bad: bypass it\n"#,
            r#"- good: satisfy Preserve unrelated user changes; bad: bypass it\n"#,
            r#"- good: satisfy Required repository commands pass; bad: bypass it\n"#,
            r#"- good: satisfy Verification claims require evidence; bad: bypass it\n"#,
            r#"- good: ship focused code; bad: leave debug output or temporary suppressions\n"#,
            r#"- good: split cohesive responsibilities; bad: grow one multi-concern function\n\n"#,
            r#"Do not claim a check passed unless it was executed successfully.\n"#,
            r#"","hookEventName":"UserPromptSubmit"}}"#,
            "\n"
        ),
        "UserPromptSubmit envelope must be byte-for-byte stable"
    );
    assert_eq!(
        stderr,
        format!("{CONFIG_VERSION_DIAGNOSTIC}\n"),
        "UserPromptSubmit stderr must carry exactly the unversioned-config diagnostic: {stderr:?}"
    );
}

#[test]
fn pre_tool_use_allows_non_edit_tool_silently() {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", "{}");
    let stdin = json!({
        "cwd": repo.path(),
        "session_id": "golden",
        "tool_name": "Read",
        "tool_input": { "file_path": "../outside.py" },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("pre-tool-use", &stdin);
    assert_eq!(code, 0, "an allowed pre-tool-use must exit 0");
    assert_eq!(
        stdout, "",
        "an allowed pre-tool-use must emit nothing on stdout: {stdout:?}"
    );
    assert_eq!(
        stderr, "",
        "an allowed pre-tool-use must emit nothing on stderr: {stderr:?}"
    );
}

#[test]
fn pre_tool_use_denies_traversal_with_exact_envelope() {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", "{}");
    let stdin = json!({
        "cwd": repo.path(),
        "session_id": "golden",
        "tool_name": "Edit",
        "tool_input": { "file_path": "../outside.py" },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("pre-tool-use", &stdin);
    assert_eq!(code, 0, "a pre-tool-use deny is exit 0 with an envelope");
    assert_eq!(
        stdout,
        concat!(
            "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",",
            "\"permissionDecision\":\"deny\",",
            "\"permissionDecisionReason\":\"target escapes repository\"},",
            "\"systemMessage\":\"target escapes repository\"}\n"
        ),
        "deny envelope must be byte-for-byte stable: exact key order, escaping, and a single trailing newline"
    );
    assert_eq!(
        stderr, "",
        "a pre-tool-use deny must emit nothing on stderr: {stderr:?}"
    );
}

#[test]
fn post_tool_use_allows_non_edit_tool_silently() {
    let repo = TempRepo::new();
    let stdin = json!({
        "session_id": "golden",
        "cwd": repo.path(),
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/hostname" },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("post-tool-use", &stdin);
    assert_eq!(code, 0, "an ignored post-tool-use must exit 0");
    assert_eq!(
        stdout, "",
        "an ignored post-tool-use must emit nothing on stdout: {stdout:?}"
    );
    assert_eq!(
        stderr, "",
        "an ignored post-tool-use must emit nothing on stderr: {stderr:?}"
    );
}

/// Native block golden that requires no external tool: PostToolUse scans the
/// single edited file, and a self-importing Python module forms a one-node
/// dependency cycle the native `module-boundary-review` check fails on. This
/// exercises the block path (decision on stdout, exit 0) on every runner,
/// independent of gitleaks. Stdout carries no path, so it is fully static.
#[test]
fn post_tool_use_blocks_native_module_cycle() {
    let repo = TempRepo::new();
    repo.write("cycle.py", "from .cycle import value\n\nvalue = 1\n");
    let cycle_path = repo.path().join("cycle.py");
    let stdin = json!({
        "session_id": "golden",
        "cwd": repo.path(),
        "tool_name": "Write",
        "tool_input": { "file_path": cycle_path.to_string_lossy() },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("post-tool-use", &stdin);
    assert_eq!(code, 0, "a native-check block must still exit 0");
    assert_eq!(
        stdout,
        concat!(
            r#"{"decision":"block","reason":"PostToolUse feedback: the tool already ran; Module dependency cycle detected (1 file(s)). "#,
            r#"Break the cycle or add an adapter boundary between modules."}"#,
            "\n"
        ),
        "the native module-cycle block must be byte-for-byte stable"
    );
    assert_operator_diagnostics(&stderr);
}

#[test]
fn post_tool_use_blocks_secret_on_stdout_exit_zero() {
    if !gitleaks_available() {
        eprintln!(
            "SKIP post_tool_use_blocks_secret_on_stdout_exit_zero: gitleaks not on PATH; the secret-block path is unexercised on this runner. The tool-free native block path is covered by post_tool_use_blocks_native_module_cycle."
        );
        return;
    }
    let repo = TempRepo::new();
    let aws_key = format!("{}{}", "AKIA", "Z3ROBME2X7HGKLMN");
    let generic_key = "a8f5f167f44f4964e6c998dee827110c";
    repo.write(
        "leak.py",
        &format!("aws_access_key = \"{aws_key}\"\ngeneric = \"api_key = '{generic_key}'\"\n"),
    );
    let leak_path = repo.path().join("leak.py");
    // The block reason embeds the canonicalized edited path; derive it the same
    // way the hook does (resolve_target canonicalizes) so the assertion is exact
    // rather than loosened.
    let canonical_leak = std::fs::canonicalize(&leak_path)
        .expect("leak fixture should canonicalize")
        .to_string_lossy()
        .into_owned();
    let stdin = json!({
        "session_id": "golden",
        "cwd": repo.path().to_string_lossy(),
        "tool_name": "Write",
        "tool_input": { "file_path": leak_path.to_string_lossy() },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("post-tool-use", &stdin);
    assert_eq!(code, 0, "post-tool-use block must still exit 0");
    assert_eq!(
        stdout,
        format!(
            "{{\"decision\":\"block\",\"reason\":\"PostToolUse feedback: the tool already ran; no-committed-secrets: gitleaks found 2 potential secrets in the touched files ({canonical_leak}). Detected rule ids: aws-access-token, generic-api-key. The secret values are redacted; remove them and rotate any exposed credential. Remove the secret from the file, load it from an environment variable or secret manager, and rotate the exposed credential.\"}}\n"
        ),
        "the gitleaks secret-block must be byte-for-byte stable, path included"
    );
    assert_operator_diagnostics(&stderr);
}

/// Pinned Stop config with one always-passing `true` verification command.
const STOP_CONFIG: &str = r#"{"version":"2","profile":"default","workspaces":[{"id":"verify","language":"shell","root":".","commands":[{"argv":["true"],"cwd":".","timeout_seconds":30,"tier":"full","purpose":"verify","source":"test","confidence":"high"}],"coverage":[]}],"disabled_rules":[],"severity_overrides":{}}"#;

/// Write a Stop fixture whose transcript carries a single assistant `claim`.
fn stop_fixture(claim: &str) -> (TempRepo, String) {
    let repo = TempRepo::new();
    repo.write(".lgtm/config.json", STOP_CONFIG);
    let text = serde_json::to_string(claim).expect("claim serializes");
    repo.write(
        "transcript.jsonl",
        &format!(
            "{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{text}}}]}}}}\n"
        ),
    );
    let stdin = json!({
        "cwd": repo.path(),
        "session_id": "golden",
        "transcript_path": repo.path().join("transcript.jsonl"),
        "tier": "full",
    })
    .to_string();
    (repo, stdin)
}

#[test]
fn stop_allows_with_plain_text_summary_on_stdout() {
    let (_repo, stdin) = stop_fixture("`true` passed successfully");

    let (code, stdout, stderr) = run_hook("stop", &stdin);
    assert_eq!(code, 0, "a clean Stop must exit 0");
    assert_eq!(
        stdout,
        "lgtm Stop: passed=2 warning=0 unverified=8 failed=0\n\
         UNVERIFIED no-committed-secrets: Secret scan unverified: no scannable edited files were recorded for this session.\n\
         UNVERIFIED regression-test-required: git diff failed or repository is unavailable\n\
         UNVERIFIED new-behavior-tests-required: git diff failed or repository is unavailable\n\
         UNVERIFIED preserve-unrelated-user-changes: git diff failed or repository is unavailable\n\
         UNVERIFIED new-dependency-review: git diff failed or repository is unavailable\n\
         UNVERIFIED auth-change-security-review: git diff failed or repository is unavailable\n\
         UNVERIFIED error-contract-review: git diff failed or repository is unavailable\n\
         UNVERIFIED behavior-test-quality: git diff failed or repository is unavailable\n",
        "a clean Stop must write the exact plain-text summary on stdout"
    );
    assert_eq!(
        stderr, "",
        "a clean Stop must emit nothing on stderr: {stderr:?}"
    );
}

#[test]
fn stop_blocks_on_stderr_with_exit_two() {
    let (_repo, stdin) = stop_fixture("`cargo test` passed");

    let (code, stdout, stderr) = run_hook("stop", &stdin);
    assert_eq!(code, 2, "a blocked Stop must exit 2");
    assert_eq!(
        stdout, "",
        "a blocked Stop must not emit a decision on stdout: {stdout:?}"
    );
    assert_eq!(
        stderr,
        concat!(
            r#"{"decision":"block","reason":"lgtm Stop blocked: unresolved MUST violations:\n"#,
            r#"- evidence-claims-honest: A verification claim lacks matching current Stop command evidence with exit status 0.\n"#,
            r#"  Repair: Run the claimed command successfully during Stop, or correct the claim."}"#,
            "\n"
        ),
        "the Stop block envelope must be byte-for-byte stable on stderr"
    );
}

#[test]
fn every_hook_fails_open_on_malformed_stdin() {
    let garbage = "{ this is not json ]]";
    // Each hook exits 0 with empty stdout and emits its own fixed operator
    // diagnostic to stderr. The serde error text is deterministic for this
    // pinned input, so stderr is asserted exactly.
    let expected_stderr = [
        (
            "session-start",
            "parse failed: entity=stdin reason=key must be a string at line 1 column 3 retryable=false\n",
        ),
        (
            "user-prompt-submit",
            "user prompt hook failed: entity=stdin reason=key must be a string at line 1 column 3 retryable=false\n",
        ),
        (
            "pre-tool-use",
            "pre-tool-use failed: entity=stdin reason=malformed or oversized payload retryable=false\n",
        ),
        (
            "post-tool-use",
            "parse failed: entity=stdin reason=key must be a string at line 1 column 3 retryable=false\n",
        ),
        (
            "stop",
            "stop failed: entity=hook reason=parse stdin (key must be a string at line 1 column 3) retryable=true\n",
        ),
    ];
    for (event, stderr_golden) in expected_stderr {
        let (code, stdout, stderr) = run_hook(event, garbage);
        assert_eq!(
            code, 0,
            "{event} must exit 0 on malformed stdin (fail-safe), got {code}"
        );
        assert_eq!(
            stdout, "",
            "{event} must emit nothing on stdout for malformed stdin: {stdout:?}"
        );
        assert_eq!(
            stderr, stderr_golden,
            "{event} must emit its exact fail-safe diagnostic on stderr"
        );
    }
}

#[test]
fn post_tool_use_secret_scan_is_non_blocking_when_gitleaks_absent() {
    if gitleaks_available() {
        eprintln!(
            "SKIP post_tool_use_secret_scan_is_non_blocking_when_gitleaks_absent: gitleaks present; the block golden covers this runner"
        );
        return;
    }
    let repo = TempRepo::new();
    let aws_key = format!("{}{}", "AKIA", "Z3ROBME2X7HGKLMN");
    repo.write("leak.py", &format!("aws_access_key = \"{aws_key}\"\n"));
    let leak_path = repo.path().join("leak.py");
    let stdin = json!({
        "session_id": "golden",
        "cwd": repo.path().to_string_lossy(),
        "tool_name": "Write",
        "tool_input": { "file_path": leak_path.to_string_lossy() },
    })
    .to_string();

    let (code, stdout, stderr) = run_hook("post-tool-use", &stdin);
    assert_eq!(
        code, 0,
        "an unverified secret scan (missing gitleaks) must exit 0"
    );
    assert_eq!(
        stdout, "",
        "an unverified secret scan must not emit a block on stdout: {stdout:?}"
    );
    assert_operator_diagnostics(&stderr);
    assert!(
        stderr.contains(
            "scan failed: entity=no-committed-secrets reason=check unverified; not blocking retryable=false"
        ),
        "a missing-gitleaks secret scan must record the unverified secret check on stderr: {stderr:?}"
    );
}
