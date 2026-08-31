mod common;

use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::TempRepo;
use serde_json::json;

fn run_stop(repo: &TempRepo, claim: &str) -> std::process::Output {
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[{"id":"verify","language":"shell","root":".","commands":[{"argv":["true"],"cwd":".","timeout_seconds":30,"tier":"full","purpose":"verify","source":"test","confidence":"high"}],"coverage":[]}],"disabled_rules":[],"severity_overrides":{}}"#,
    );
    repo.write("transcript.jsonl", &format!("{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n", serde_json::to_string(claim).expect("claim serializes")));
    let payload = json!({ "cwd": repo.path(), "session_id": "claims", "transcript_path": repo.path().join("transcript.jsonl"), "tier": "full" });
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

#[cfg(target_os = "linux")]
fn run_pre_tool_use_command(
    repo: &TempRepo,
    session_id: &str,
    command: &str,
) -> std::process::Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": command}
    });
    let path = format!(
        "{}:{}",
        repo.path().join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "pre-tool-use"])
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PreToolUse starts");
    writeln!(child.stdin.take().expect("stdin"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("PreToolUse completes")
}

#[cfg(target_os = "linux")]
fn run_full_stop(repo: &TempRepo, session_id: &str) -> std::process::Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "check": false,
        "tier": "full"
    });
    let path = format!(
        "{}:{}",
        repo.path().join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("full Stop starts");
    writeln!(child.stdin.take().expect("stdin"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("full Stop completes")
}

#[test]
fn unsupported_success_claim_blocks_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`cargo test` passed");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("evidence-claims-honest"));
}

// Production command containment is available on Linux; macOS must surface
// configured commands as unavailable rather than claim that they passed.
#[cfg(target_os = "linux")]
#[test]
fn matching_required_command_claim_passes_honesty_check() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`true` passed successfully");
    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.contains("evidence-claims-honest"));
    assert!(evidence.contains("\"status\":\"passed\""));
}

#[test]
fn operational_lgtm_claim_does_not_block_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`lgtm doctor` passed; the hook probe succeeded.");
    assert!(output.status.success());
}

#[cfg(target_os = "linux")]
fn clean_gitleaks_script() -> &'static str {
    "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n"
}

#[cfg(target_os = "linux")]
fn oversized_gate_fixture() -> (TempRepo, String) {
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    let repo = oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nIFS= read -r state < \"$2\"\ncase \"$state\" in\n    *mutated*) exit 7 ;;\nesac\nexit 0\n",
        clean_gitleaks_script(),
        &initial,
    );
    (repo, filler)
}

#[cfg(target_os = "linux")]
fn oversized_truncating_gate_fixture() -> (TempRepo, String) {
    // The fake scanner changes the initially oversized source before reporting
    // clean, so the pre-scanner latch must survive that normalization.
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    let repo = oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nsource=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    if [ \"$1\" = --source ]; then source=\"$2\"; shift 2; continue; fi\n    shift\ndone\n: > \"$source\"\nprintf '[]\\n' > \"$report\"\n",
        &initial,
    );
    (repo, filler)
}

#[cfg(target_os = "linux")]
fn configured_command_truncating_gate_fixture() -> TempRepo {
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\n: > \"$2\"\nexit 0\n",
        clean_gitleaks_script(),
        &initial,
    )
}

#[cfg(target_os = "linux")]
fn configured_command_oversized_from_empty_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nprintf '%*s' 262145 '' > \"$2\"\nexit 0\n",
        clean_gitleaks_script(),
        "",
    )
}

#[cfg(target_os = "linux")]
fn scanner_oversized_then_command_empty_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\n: > \"$2\"\nexit 0\n",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nsource=\nwhile [ \"$#\" -gt 0 ]; do\n    case \"$1\" in\n        --report-path) report=\"$2\"; shift 2 ;;\n        --source) source=\"$2\"; shift 2 ;;\n        *) shift ;;\n    esac\ndone\ncase \"$source\" in\n    */src/oversized.json)\n        printf '%*s' 262145 '' >> \"$source\"\n        printf 'scanner-mutated\\n' > \"${source%/*}/scanner-mutated\"\n        ;;\nesac\nprintf '[]\\n' > \"$report\"\n",
        "{\"state\":\"initial\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn scanner_valid_content_then_command_restores_pre_scan_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        r#"#!/bin/sh
printf x >> "$1"
printf '{"state":"a"}\n' > "$2"
exit 0
"#,
        r#"#!/bin/sh
if [ "$1" = version ]; then printf 'fixture\n'; exit 0; fi
report=
source=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --report-path) report="$2"; shift 2 ;;
        --source) source="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf '{"state":"b"}\n' > "$source"
printf '[]\n' > "$report"
"#,
        "{\"state\":\"a\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn configured_command_valid_content_mutation_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        r#"#!/bin/sh
printf x >> "$1"
printf '{"state":"b"}\n' > "$2"
exit 0
"#,
        clean_gitleaks_script(),
        "{\"state\":\"a\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn oversized_gate_fixture_with_command(
    command_script: &str,
    gitleaks_script: &str,
    initial_contents: &str,
) -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/oversized-check");
    let counter = repo.path().join("full-gate-runs");
    let touched = repo.path().join("src/oversized.json");
    repo.write("bin/oversized-check", command_script);
    // Keep the full-gate result deterministic without depending on a host
    // gitleaks installation.
    repo.write("bin/gitleaks", gitleaks_script);
    let gitleaks = repo.path().join("bin/gitleaks");
    for executable in [&command, &gitleaks] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
    repo.write("src/oversized.json", initial_contents);
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
                    "argv": [
                        command.to_string_lossy(),
                        counter.to_string_lossy(),
                        touched.to_string_lossy()
                    ],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "verify",
                    "source": "test",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&[
        "add",
        "bin/oversized-check",
        "bin/gitleaks",
        "src/oversized.json",
        ".lgtm/config.json",
    ]);
    git(&[
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "initial",
    ]);

    repo
}

#[cfg(target_os = "linux")]
fn symlink_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/symlink-check");
    let counter = repo.path().join("full-gate-runs");
    let link = repo.path().join("src/tracked.json");

    repo.write(".gitignore", "vendor/\n");
    repo.write(
        "bin/symlink-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nif /bin/grep -q '\"state\":\"mutated\"' \"$2\"; then exit 7; fi\nexit 0\n",
    );
    repo.write(
        "bin/gitleaks",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n",
    );
    repo.write("src/ordinary.rs", "fn value() -> u8 { 1 }\n");
    repo.write("vendor/ignored.json", "{\"state\":\"initial\"}\n");
    std::os::unix::fs::symlink("../vendor/ignored.json", &link)
        .expect("tracked supported-extension symlink");

    let gitleaks = repo.path().join("bin/gitleaks");
    for executable in [&command, &gitleaks] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
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
                    "argv": [
                        command.to_string_lossy(),
                        counter.to_string_lossy(),
                        link.to_string_lossy()
                    ],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "verify",
                    "source": "test",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&[
        "add",
        ".gitignore",
        "bin/symlink-check",
        "bin/gitleaks",
        "src/ordinary.rs",
        "src/tracked.json",
        ".lgtm/config.json",
    ]);
    git(&[
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "initial",
    ]);

    repo
}

#[cfg(target_os = "linux")]
fn extensionless_directory_symlink_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/directory-symlink-check");
    let counter = repo.path().join("full-gate-runs");
    let hidden = repo.path().join("src/hidden");
    let touched = repo.path().join("src/hidden/state.json");

    repo.write(".gitignore", "vendor/");
    repo.write(
        "bin/directory-symlink-check",
        r#"#!/bin/sh
printf x >> "$1"
IFS= read -r state < "$2"
case "$state" in
    *mutated*) exit 7 ;;
esac
exit 0
"#,
    );
    repo.write("bin/gitleaks", clean_gitleaks_script());
    repo.write("src/ordinary.rs", "fn value() -> u8 { 1 }\n");
    repo.write("vendor/hidden/state.json", "{\"state\":\"initial\"}\n");
    std::os::unix::fs::symlink("../vendor/hidden", &hidden)
        .expect("extensionless directory symlink");

    let gitleaks = repo.path().join("bin/gitleaks");
    for executable in [&command, &gitleaks] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
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
                    "argv": [
                        command.to_string_lossy(),
                        counter.to_string_lossy(),
                        touched.to_string_lossy()
                    ],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "verify",
                    "source": "test",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&[
        "add",
        ".gitignore",
        "bin/directory-symlink-check",
        "bin/gitleaks",
        "src/ordinary.rs",
        "src/hidden",
        ".lgtm/config.json",
    ]);
    git(&[
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "initial",
    ]);

    repo
}

#[cfg(target_os = "linux")]
fn unresolved_ledger_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/unresolved-check");
    let counter = repo.path().join("full-gate-runs");
    let session_id = "unresolved-ledger-retry";

    repo.write(
        "bin/unresolved-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    // Keep the full Stop deterministic without depending on a host gitleaks
    // installation.
    repo.write(
        "bin/gitleaks",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n",
    );
    let gitleaks = repo.path().join("bin/gitleaks");
    for executable in [&command, &gitleaks] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }

    // Keep the anchor under a test path so the Stop diff-association policy
    // has no missing-source obligation unrelated to this reuse regression.
    repo.write("tests/anchor.rs", "fn anchor() -> u8 { 1 }\n");
    // Keep both candidates in one no-committed-secrets record: the valid
    // edited_file anchors the scanned path while the unresolved location must
    // still make the candidate set non-reusable.
    let anchor_record = json!({
        "session_id": session_id,
        "edited_file": "tests/anchor.rs",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "passed",
            "severity": "error",
            "message": "clean",
            "locations": [{"file": "src/missing.rs", "line": 1}],
            "evidence": {
                "check": "gitleaks.detect",
                "tool_version": null,
                "finding_descriptions": []
            }
        }
    });
    repo.write(
        ".lgtm/evidence/current-task.results.jsonl",
        &format!("{anchor_record}\n"),
    );
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
                    "argv": [command.to_string_lossy(), counter.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "verify",
                    "source": "test",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    // The diff association check must see a real repository so a passing Stop
    // record is not obscured by an unrelated git-unavailable result.
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&[
        "add",
        "bin/unresolved-check",
        "bin/gitleaks",
        "tests/anchor.rs",
        ".lgtm/config.json",
    ]);
    git(&[
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "user.name=test",
        "commit",
        "-qm",
        "initial",
    ]);

    repo
}

#[cfg(target_os = "linux")]
#[test]
fn unresolved_ledger_candidate_propagates_uncertainty_to_precommit_rerun() {
    let repo = unresolved_ledger_gate_fixture();
    let first = run_full_stop(&repo, "unresolved-ledger-retry");
    assert!(first.status.success(), "full Stop: {:?}", first.stderr);
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("full Stop evidence record"),
    )
    .expect("full Stop evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the missing location ledger candidate makes the Stop digest uncertain"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the full Stop command evidence is passing"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "uncertainty propagates to passing command provenance"
    );

    let second = run_pre_tool_use_command(&repo, "unresolved-ledger-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "pre-commit gate: {:?}",
        second.stderr
    );
    assert!(
        second.stdout.is_empty(),
        "a passing rerun emits no decision"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain Stop record must not be reused by pre-commit"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn tracked_symlink_to_ignored_target_forces_same_session_full_gate_rerun() {
    let repo = symlink_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "symlink-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the omitted symlink makes the touched set non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    repo.write("vendor/ignored.json", "{\"state\":\"mutated\"}\n");
    let second = run_pre_tool_use_command(&repo, "symlink-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the command must observe the mutated symlink target"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the target mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "uncertain symlink evidence must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn extensionless_directory_symlink_forces_same_session_full_gate_rerun() {
    let repo = extensionless_directory_symlink_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "directory-symlink-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the extensionless directory symlink makes the candidate set non-reusable"
    );

    repo.write(
        "vendor/hidden/state.json",
        r#"{"state":"mutated"}
"#,
    );
    let second = run_pre_tool_use_command(&repo, "directory-symlink-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the rerun command must observe the mutated hidden target"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the target mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "an extensionless directory symlink must force a same-session full-gate rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_mutation_reruns_same_session_full_gate() {
    let (repo, filler) = oversized_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "oversized-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "oversized touched content is recorded as non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    // Keep the replacement oversized so both attempts are in the same
    // bounded-overflow class, while changing the content the command reads.
    repo.write(
        "src/oversized.json",
        &format!("{{\"state\":\"mutated\",\"padding\":\"{filler}\"}}\n"),
    );
    let second = run_pre_tool_use_command(&repo, "oversized-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the mutated oversized file must not authorize evidence reuse"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the retry must execute the full command instead of reusing evidence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_truncation_by_gitleaks_latches_non_reusable_full_gate_evidence() {
    let (repo, _filler) = oversized_truncating_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "oversized-truncate", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the fake gitleaks scanner truncates the scanned file"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the pre-scan oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves the pre-scan uncertainty"
    );

    let second = run_pre_tool_use_command(&repo, "oversized-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain first attempt must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_empty_replacement_does_not_reuse_same_session_evidence() {
    let (repo, _filler) = oversized_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "oversized-empty", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "oversized touched content persists the uncertain sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    // A regular empty replacement must not match the persisted uncertain
    // digest from the oversized first attempt.
    repo.write("src/oversized.json", "");
    let replacement =
        run_pre_tool_use_command(&repo, "oversized-empty", "git commit -m empty-replacement");
    assert!(
        replacement.status.success(),
        "empty replacement gate: {:?}",
        replacement.stderr
    );
    assert!(
        replacement.stdout.is_empty(),
        "empty replacement full gate should pass"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "an empty replacement must rerun instead of reusing oversized evidence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_truncation_by_configured_command_latches_non_reusable_evidence() {
    let repo = configured_command_truncating_gate_fixture();
    let first =
        run_pre_tool_use_command(&repo, "oversized-command-truncate", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the configured command truncates the initially oversized source"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the pre-command oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves the pre-command uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured truncating command exits successfully"
    );

    let second =
        run_pre_tool_use_command(&repo, "oversized-command-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain first attempt must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn post_command_oversized_file_persists_uncertainty_and_forces_same_session_rerun() {
    let repo = configured_command_oversized_from_empty_fixture();
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the touched file starts empty"
    );

    let first = run_pre_tool_use_command(&repo, "post-command-oversized", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json").len(),
        256 * 1024 + 1,
        "the configured command makes the touched file oversized"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "post-command oversized content persists the non-reusable sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance preserves post-command uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured command passes despite making the file oversized"
    );

    repo.write("src/oversized.json", "");
    let second = run_pre_tool_use_command(&repo, "post-command-oversized", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "post-command uncertainty must force a same-session rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scanner_oversized_then_configured_command_empty_latches_non_reusable_evidence() {
    let repo = scanner_oversized_then_command_empty_fixture();
    let first = run_pre_tool_use_command(&repo, "scanner-command-truncate", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/scanner-mutated"),
        "scanner-mutated\n",
        "the fake scanner must mutate the target before its clean report"
    );
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the configured command restores a representable empty source"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "scanner-introduced oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves scanner-introduced uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured normalizing command exits successfully"
    );

    let second = run_pre_tool_use_command(&repo, "scanner-command-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "scanner-introduced uncertainty must force a same-session rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn valid_scanner_mutation_requires_post_scan_digest_equality() {
    let repo = scanner_valid_content_then_command_restores_pre_scan_fixture();
    let first = run_pre_tool_use_command(&repo, "scanner-valid-equality", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(repo.read("src/oversized.json"), "{\"state\":\"a\"}\n");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "a valid scanner A-to-B mutation must latch the non-reusable sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance must carry the scanner latch"
    );

    let second = run_pre_tool_use_command(&repo, "scanner-valid-equality", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    assert!(second.stdout.is_empty(), "retry gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "a scanner-valid mutation must force a same-session rerun even after command normalization"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn valid_configured_command_mutation_requires_post_command_digest_equality() {
    let repo = configured_command_valid_content_mutation_fixture();
    let first = run_pre_tool_use_command(&repo, "command-valid-equality", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(repo.read("src/oversized.json"), "{\"state\":\"b\"}\n");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "a valid configured-command A-to-B mutation must latch the sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance must carry the post-command mismatch"
    );

    let second = run_pre_tool_use_command(&repo, "command-valid-equality", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    assert!(second.stdout.is_empty(), "retry gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "a configured-command valid mutation must force a same-session rerun"
    );
}
