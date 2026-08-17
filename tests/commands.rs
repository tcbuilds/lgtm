#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

const COVERAGE_RULE_ID: &str = "required-repository-commands";

#[cfg(target_os = "linux")]
fn encode_supervisor_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}

fn run_post_tool_use(repo: &TempRepo, session_id: &str, file: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PostToolUse hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": session_id,
            "tool_name": "Write",
            "tool_input": {"file_path": repo.path().join(file)}
        })
    )
    .expect("payload writes");
    child.wait_with_output().expect("PostToolUse hook exits")
}

fn run_pre_tool_use_command(
    repo: &TempRepo,
    session_id: &str,
    command: &str,
) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PreToolUse hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": session_id,
            "tool_name": "Bash",
            "tool_input": {"command": command}
        })
    )
    .expect("payload writes");
    child.wait_with_output().expect("PreToolUse hook exits")
}

fn write_coverage_fixture(repo: &TempRepo, report: &str, line_threshold: u8, branch_threshold: u8) {
    repo.write(
        "bin/coverage",
        &format!("#!/bin/sh\nprintf '%s\n' '{report}'\n"),
    );
    let executable = repo.path().join("bin/coverage");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "coverage",
                "language": "shell",
                "root": ".",
                "commands": [],
                "coverage": [{
                    "argv": [executable.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": line_threshold,
                    "branch_threshold_percent": branch_threshold
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
}

fn write_coverage_executable(repo: &TempRepo, relative: &str, report: &str) -> String {
    repo.write(relative, &format!("#!/bin/sh\nprintf '%s\\n' '{report}'\n"));
    let executable = repo.path().join(relative);
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    executable.to_string_lossy().into_owned()
}

fn write_workspace_coverage_fixture(repo: &TempRepo) {
    let selected = write_coverage_executable(
        repo,
        "bin/selected-coverage",
        "line coverage: 100% branch coverage: 100%",
    );
    let other = write_coverage_executable(
        repo,
        "bin/other-coverage",
        "line coverage: 0% branch coverage: 0%",
    );
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [
                {
                    "id": "selected",
                    "language": "shell",
                    "root": ".",
                    "commands": [],
                    "coverage": [{
                        "argv": [selected],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                },
                {
                    "id": "other",
                    "language": "shell",
                    "root": ".",
                    "commands": [],
                    "coverage": [{
                        "argv": [other],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                }
            ],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
}

fn run_full_stop(repo: &TempRepo, session_id: &str, stop_hook_active: bool) -> Output {
    run_full_stop_with_environment(repo, session_id, stop_hook_active, None, None, None)
}

fn run_full_stop_with_path_and_home(
    repo: &TempRepo,
    session_id: &str,
    stop_hook_active: bool,
    path: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
) -> Output {
    run_full_stop_with_environment(repo, session_id, stop_hook_active, path, home, None)
}

fn run_full_stop_with_environment(
    repo: &TempRepo,
    session_id: &str,
    stop_hook_active: bool,
    path: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    ci: Option<&std::ffi::OsStr>,
) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "check": true,
        "tier": "full",
        "stop_hook_active": stop_hook_active
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if let Some(ci) = ci {
        command.env("CI", ci);
    }
    let mut child = command.spawn().expect("Stop hook starts");
    write!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("Stop hook exits")
}

fn run_stop_with_workspace(repo: &TempRepo, session_id: &str, workspace: &str) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "workspace": workspace,
        "tier": "full",
        "stop_hook_active": false
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("workspace Stop hook starts");
    write!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("Stop hook exits")
}

fn run_full_check(repo: &TempRepo) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--tier", "full"])
        .current_dir(repo.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("full check starts")
}

fn run_workspace_full_check(repo: &TempRepo, workspace: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--workspace", workspace, "--tier", "full"])
        .current_dir(repo.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("workspace full check starts")
}

fn latest_evidence(repo: &TempRepo) -> Value {
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    serde_json::from_str(evidence.lines().last().expect("evidence record")).expect("evidence JSON")
}

fn projected_coverage_result<'a>(record: &'a Value, status: &str) -> &'a Value {
    record["results"]
        .as_array()
        .expect("serialized results")
        .iter()
        .find(|result| {
            result["rule_id"].as_str() == Some(COVERAGE_RULE_ID)
                && result["status"].as_str() == Some(status)
        })
        .expect("projected coverage result")
}

#[test]
fn failing_required_command_blocks_commit_and_records_full_evidence() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write("bin/required-check", "#!/bin/sh\nexit 7\n");
    let executable = repo.path().join("bin/required-check");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [executable.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "command-e2e", "src/app.rs")
            .status
            .success()
    );

    let output = run_pre_tool_use_command(&repo, "command-e2e", "git commit -m test");

    assert!(output.status.success(), "Claude deny uses a JSON response");
    let decision: Value = serde_json::from_slice(&output.stdout).expect("deny decision JSON");
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = decision["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("deny reason");
    assert!(reason.contains("pre-commit full gate failed"));
    assert!(reason.contains("required-repository-commands"));
    assert!(reason.contains("exit status 7"));

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["tier"], "full");
    assert_eq!(record["commands"][0]["exit_code"], 7);
    assert!(record["commands"][0]["duration_ms"].is_number());
    assert_eq!(
        record["commands"][0]["command"],
        executable.to_string_lossy().as_ref()
    );
}

#[test]
fn stop_is_targeted_and_reuses_successful_precommit_evidence() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let command_marker = repo.path().join("command-runs");
    let coverage_marker = repo.path().join("coverage-runs");
    let targeted_marker = repo.path().join("targeted-runs");
    repo.write(
        "bin/required-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    repo.write(
        "bin/coverage-check",
        "#!/bin/sh\nprintf x >> \"$1\"\necho 'line coverage: 85% branch coverage: 90%'\nexit 0\n",
    );
    repo.write(
        "bin/targeted-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    let command = repo.path().join("bin/required-check");
    let coverage = repo.path().join("bin/coverage-check");
    let targeted = repo.path().join("bin/targeted-check");
    for path in [&command, &coverage, &targeted] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [
                    {
                        "argv": [command.to_string_lossy(), command_marker.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "tier": "full",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    },
                    {
                        "argv": [targeted.to_string_lossy(), targeted_marker.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "tier": "targeted",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    }
                ],
                "coverage": [{
                    "argv": [coverage.to_string_lossy(), coverage_marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": 80,
                    "branch_threshold_percent": 90
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "precommit-full", "src/app.rs")
            .status
            .success()
    );
    let command_claim = format!("{} {}", command.display(), command_marker.display());
    repo.write(
        "transcript.jsonl",
        &format!(
            "{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n",
            serde_json::to_string(&format!("Ran `{command_claim}`; it passed.")).unwrap()
        ),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": "precommit-full",
            "transcript_path": repo.path().join("transcript.jsonl")
        })
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");
    assert_eq!(output.status.code(), Some(2));
    assert!(!command_marker.exists(), "Stop must not run full commands");
    assert!(!coverage_marker.exists(), "Stop must not run coverage");
    assert_eq!(repo.read("targeted-runs"), "x");

    let precommit = run_pre_tool_use_command(&repo, "precommit-full", "git commit -m test");
    assert!(
        precommit.status.success(),
        "PreToolUse stderr: {:?}",
        precommit.stderr
    );
    assert!(precommit.stdout.is_empty());
    assert_eq!(repo.read("command-runs"), "x");
    assert_eq!(repo.read("coverage-runs"), "x");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Stop hook starts");
    write!(
        child.stdin.take().expect("stdin available"),
        "{}",
        json!({
            "cwd": repo.path(),
            "session_id": "precommit-full",
            "transcript_path": repo.path().join("transcript.jsonl")
        })
    )
    .expect("payload writes");
    let output = child.wait_with_output().expect("Stop hook exits");
    assert!(output.status.success(), "Stop stderr: {:?}", output.stderr);
    assert_eq!(repo.read("command-runs"), "x", "Stop reran full command");
    assert_eq!(repo.read("coverage-runs"), "x", "Stop reran coverage");
    assert_eq!(repo.read("targeted-runs"), "xx");

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence record"))
        .expect("evidence JSON");
    assert_eq!(record["tier"], "targeted");
    assert_eq!(
        record["commands"][0]["command"],
        format!("{} {}", targeted.display(), targeted_marker.display())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn setsid_f_delayed_config_replacement_denies_and_is_not_reused() {
    let repo = TempRepo::new();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .output()
            .expect("git starts");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    git(&["init", "-q"]);
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        "bin/escape-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nsetsid -f /bin/sh -c 'sleep 1; cp \"$1\" \"$2\"; git -C \"$3\" add .lgtm/config.json' sh \"$2\" \"$3\" \"$4\" </dev/null >/dev/null 2>&1\nexit 0\n",
    );
    let command = repo.path().join("bin/escape-check");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    let marker = repo.path().join("escape-runs");
    let replacement_path = repo.path().join(".git/replacement-config.json");
    let config_path = repo.path().join(".lgtm/config.json");
    let replacement = json!({
        "version": "2",
        "profile": "default",
        "workspaces": [],
        "disabled_rules": [],
        "severity_overrides": {}
    })
    .to_string();
    std::fs::write(&replacement_path, &replacement).expect("replacement config");
    let original = json!({
        "version": "2",
        "profile": "default",
        "workspaces": [{
            "id": "tests",
            "language": "shell",
            "root": ".",
            "commands": [{
                "argv": [
                    command.to_string_lossy(),
                    marker.to_string_lossy(),
                    replacement_path.to_string_lossy(),
                    config_path.to_string_lossy(),
                    repo.path().to_string_lossy()
                ],
                "cwd": ".",
                "timeout_seconds": 30,
                "tier": "full",
                "purpose": "test",
                "source": "fixture",
                "confidence": "high"
            }],
            "coverage": []
        }],
        "disabled_rules": [],
        "severity_overrides": {}
    })
    .to_string();
    repo.write(".lgtm/config.json", &original);
    git(&["add", "src/app.rs", "bin/escape-check", ".lgtm/config.json"]);
    assert!(
        run_post_tool_use(&repo, "session-escape", "src/app.rs")
            .status
            .success()
    );

    for expected_runs in ["x", "xx"] {
        let authorization =
            run_pre_tool_use_command(&repo, "session-escape", "sleep 2 && git commit -m test");
        assert!(authorization.status.success());
        let decision: Value =
            serde_json::from_slice(&authorization.stdout).expect("containment deny decision");
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            decision["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("descendant outlived the direct command"))
        );
        assert_eq!(repo.read("escape-runs"), expected_runs);

        let record = latest_evidence(&repo);
        assert_eq!(record["commands"][0]["exit_code"], Value::Null);
        assert_eq!(
            record["platform"],
            format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        );
        assert_eq!(record["containment_version"], "linux-isolated-subreaper-v3");
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["status"] == "failed"
                    && result["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("descendant outlived"))
            })
        }));
    }

    std::thread::sleep(std::time::Duration::from_millis(1_200));
    assert_eq!(repo.read(".lgtm/config.json"), original);
}

#[cfg(target_os = "linux")]
#[test]
fn adopted_zombie_before_first_proc_scan_denies_and_is_not_reused() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        "bin/adopted-zombie-check",
        "#!/bin/sh\nsetsid -f /bin/sh -c 'printf x >> \"$1\"; sleep 0.05; exit 0' sh \"$1\" </dev/null >/dev/null 2>&1 &\nwhile [ ! -f \"$1\" ]; do sleep 0.01; done\nsleep 0.2\nexit 0\n",
    );
    let command = repo.path().join("bin/adopted-zombie-check");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    let marker = repo.path().join("adopted-zombie-runs");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [command.to_string_lossy(), marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "adopted-zombie", "src/app.rs")
            .status
            .success()
    );

    for expected_runs in ["x", "xx"] {
        let output = run_pre_tool_use_command(&repo, "adopted-zombie", "git commit -m test");
        assert!(output.status.success());
        let decision: Value = serde_json::from_slice(&output.stdout).expect("deny decision JSON");
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            decision["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("descendant outlived the direct command"))
        );
        assert_eq!(repo.read("adopted-zombie-runs"), expected_runs);

        let record = latest_evidence(&repo);
        assert_eq!(record["commands"][0]["exit_code"], Value::Null);
        assert_eq!(record["containment_version"], "linux-isolated-subreaper-v3");
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["status"] == "failed"
                    && result["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("descendant outlived"))
            })
        }));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn isolated_supervisor_preserves_unrelated_child_waitability() {
    let mut unrelated = Command::new("/bin/sh")
        .args(["-c", "sleep 0.2; exit 23"])
        .spawn()
        .expect("unrelated child starts");
    let request = json!({
        "argv": ["/bin/true"],
        "repository_root": encode_supervisor_bytes(
            std::env::current_dir()
                .expect("repository root")
                .as_os_str()
                .as_bytes(),
        ),
        "workspace_root": encode_supervisor_bytes(b"."),
        "cwd": encode_supervisor_bytes(b"."),
        "timeout_ms": "00000000000000001000",
        "path": std::env::var_os("PATH")
            .map(|value| encode_supervisor_bytes(value.as_os_str().as_bytes())),
        "home": std::env::var_os("HOME")
            .map(|value| encode_supervisor_bytes(value.as_os_str().as_bytes())),
        "ci": std::env::var_os("CI")
            .map(|value| encode_supervisor_bytes(value.as_os_str().as_bytes()))
    });
    let supervisor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("__command-supervisor")
        .env_clear()
        .env(
            "LGTM_INTERNAL_COMMAND_SUPERVISOR_REQUEST",
            request.to_string(),
        )
        .output()
        .expect("isolated supervisor starts");
    assert!(supervisor.status.success());
    let response: Value = serde_json::from_slice(&supervisor.stdout).expect("supervisor response");
    assert_eq!(response["outcome"], "completed");
    assert_eq!(response["code"], 0);

    let status = unrelated.wait().expect("unrelated owner can still wait");
    assert_eq!(status.code(), Some(23));
}

#[test]
fn precommit_reuses_full_evidence_with_only_warning_severity_failures() {
    let repo = TempRepo::new();
    let oversized = format!(
        "pub fn oversized() {{\n{} }}\n",
        "    let value = 1;\n".repeat(51)
    );
    repo.write("src/app.rs", &oversized);
    let marker = repo.path().join("warning-gate-runs");
    repo.write(
        "bin/required-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    let executable = repo.path().join("bin/required-check");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "prototype",
            "workspaces": [{
                "id": "tests",
                "language": "rust",
                "root": ".",
                "commands": [{
                    "argv": [executable.to_string_lossy(), marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {"function-size": "warning"}
        })
        .to_string(),
    );

    let first = run_pre_tool_use_command(&repo, "warning-reuse", "git commit -m first");
    assert!(first.status.success());
    assert!(
        first.stdout.is_empty(),
        "first precommit output: {}",
        String::from_utf8_lossy(&first.stdout)
    );
    let first_record = latest_evidence(&repo);
    assert!(first_record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["rule_id"] == "function-size"
                && result["status"] == "failed"
                && result["severity"] == "warning"
        })
    }));
    assert_eq!(repo.read("warning-gate-runs"), "x");

    let second = run_pre_tool_use_command(&repo, "warning-reuse", "git commit -m second");
    assert!(second.status.success());
    assert!(
        second.stdout.is_empty(),
        "second precommit output: {}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert_eq!(
        repo.read("warning-gate-runs"),
        "x",
        "reusable warning-only evidence must avoid rerunning the full gate"
    );
}

#[test]
fn timed_out_required_command_denies_each_retry_and_is_never_reused() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let marker = repo.path().join("timeout-runs");
    repo.write(
        "bin/timeout-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nsleep 2\n",
    );
    let command = repo.path().join("bin/timeout-check");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [command.to_string_lossy(), marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 1,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "timeout-retry", "src/app.rs")
            .status
            .success()
    );

    for expected_runs in ["x", "xx"] {
        let output = run_pre_tool_use_command(&repo, "timeout-retry", "git commit -m test");
        let decision: Value = serde_json::from_slice(&output.stdout).expect("deny decision JSON");
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            decision["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("missing, timed out, or wait failed"))
        );
        assert_eq!(repo.read("timeout-runs"), expected_runs);
    }
}

#[test]
fn failed_coverage_threshold_denies_each_retry_and_is_never_reused() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let marker = repo.path().join("coverage-failure-runs");
    repo.write(
        "bin/coverage-check",
        "#!/bin/sh\nprintf x >> \"$1\"\necho 'line coverage: 50%'\n",
    );
    let coverage = repo.path().join("bin/coverage-check");
    std::fs::set_permissions(&coverage, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [],
                "coverage": [{
                    "argv": [coverage.to_string_lossy(), marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": 80
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "coverage-retry", "src/app.rs")
            .status
            .success()
    );

    for expected_runs in ["x", "xx"] {
        let output = run_pre_tool_use_command(&repo, "coverage-retry", "git commit -m test");
        let decision: Value = serde_json::from_slice(&output.stdout).expect("deny decision JSON");
        assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(
            decision["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .is_some_and(|reason| reason.contains("coverage for workspace tests"))
        );
        assert_eq!(repo.read("coverage-failure-runs"), expected_runs);
    }
}

#[test]
fn config_trust_is_revalidated_before_successful_evidence_reuse() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let marker = repo.path().join("trusted-config-runs");
    repo.write("bin/required-check", "#!/bin/sh\nprintf x >> \"$1\"\n");
    let command = repo.path().join("bin/required-check");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("fixture executable");
    let config_path = repo.path().join(".lgtm/config.json");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "tests",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [command.to_string_lossy(), marker.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "config-trust", "src/app.rs")
            .status
            .success()
    );
    let first = run_pre_tool_use_command(&repo, "config-trust", "git commit -m test");
    assert!(first.stdout.is_empty());
    assert_eq!(repo.read("trusted-config-runs"), "x");

    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o666))
        .expect("world-writable config");
    let denied = run_pre_tool_use_command(&repo, "config-trust", "git commit -m test");
    let decision: Value = serde_json::from_slice(&denied.stdout).expect("deny decision JSON");
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(repo.read("trusted-config-runs"), "x");

    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .expect("trusted config restored");
    let rerun = run_pre_tool_use_command(&repo, "config-trust", "git commit -m test");
    assert!(rerun.stdout.is_empty());
    assert_eq!(repo.read("trusted-config-runs"), "xx");
}

#[test]
fn explicit_cli_tier_runs_only_requested_commands() {
    let repo = TempRepo::new();
    let marker = repo.path().join("executed");
    let mut commands = Vec::new();
    for (name, tier) in [("fast", "fast"), ("targeted", "targeted"), ("full", "full")] {
        let script = repo.path().join(format!("bin/{name}"));
        repo.write(
            &format!("bin/{name}"),
            "#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$1\"\nexit 0\n",
        );
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
        commands.push(json!({
            "argv": [script.to_string_lossy(), marker.to_string_lossy(), name],
            "cwd": ".",
            "timeout_seconds": 30,
            "tier": tier,
            "purpose": "verify",
            "source": "fixture",
            "confidence": "high"
        }));
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "checks",
                "language": "shell",
                "root": ".",
                "commands": commands,
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    for tier in ["fast", "targeted", "full"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["check", "--tier", tier])
            .current_dir(repo.path())
            .output()
            .expect("check starts");
        assert!(
            output.status.success(),
            "{tier} stderr: {:?}",
            output.stderr
        );
        assert_eq!(repo.read("executed"), format!("{tier}\n"));
        std::fs::remove_file(&marker).expect("marker exists");
    }
}

#[test]
fn invalid_command_timeout_is_surfaced_as_unverified() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"command_timeout_seconds":0,"required_commands":{}}"#,
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "stop"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write!(
        child.stdin.take().unwrap(),
        "{}",
        json!({"cwd":repo.path(),"session_id":"timeout-invalid","check":true})
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    assert!(stdout.contains("between 1 and 3600"));
}

#[test]
fn passing_line_and_branch_coverage_passes_stop_and_persists_result() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 85% branch coverage: 90%", 80, 90);

    let output = run_full_stop(&repo, "coverage-pass", false);

    assert!(output.status.success(), "passing coverage must allow Stop");
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("failed=0"), "summary must report failed=0");
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(
        projected_coverage_result(&record, "passed")["status"],
        "passed"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn evidence_append_recovers_from_a_truncated_final_jsonl_record() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 100% branch coverage: 100%", 80, 80);
    assert!(
        run_full_stop(&repo, "before-truncation", false)
            .status
            .success()
    );
    let evidence_path = repo.path().join(".lgtm/evidence/evidence.jsonl");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&evidence_path)
        .and_then(|mut file| file.write_all(b"{\"task_id\":"))
        .expect("append truncated evidence tail");

    let output = run_full_stop(&repo, "after-truncation", false);

    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let latest: Value = serde_json::from_str(evidence.lines().last().expect("latest evidence"))
        .expect("latest evidence remains parseable JSON");
    assert_eq!(latest["task_id"], "after-truncation");
    assert!(!evidence.contains("{\"task_id\":{\"task_id\""));
}

#[test]
fn ratio_and_decimal_coverage_uses_the_percentage_value() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "line coverage: 120/120 100% branch coverage: 119/120 99.17%",
        100,
        99,
    );

    let output = run_full_stop(&repo, "coverage-ratio", false);

    assert!(
        output.status.success(),
        "ratio totals must not be parsed as percentages"
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(record["coverage"][0]["line_percent"], 100.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 99.17);
}

#[test]
fn out_of_range_coverage_is_unverified_and_persists_valid_evidence() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "line coverage: 120/120 120% branch coverage: 100%",
        80,
        80,
    );

    let output = run_full_stop(&repo, "coverage-out-of-range", false);

    assert!(
        output.status.success(),
        "invalid tool output must be unverified rather than fail open after an evidence error"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(record["coverage"][0]["line_percent"], Value::Null);
    assert_eq!(record["coverage"][0]["branch_percent"], 100.0);
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn workspace_scoped_full_check_ignores_other_workspace_coverage_failure() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_workspace_full_check(&repo, "selected");

    let record = latest_evidence(&repo);
    let coverage = record["coverage"].as_array().expect("coverage evidence");
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0]["workspace_id"], "selected");
    assert_eq!(coverage[0]["status"], "passed");
    assert!(
        output.status.success(),
        "selected workspace full check passes"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn full_check_without_workspace_selector_runs_all_coverage() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_full_check(&repo);

    assert!(
        !output.status.success(),
        "failing workspace must block all-workspace check"
    );
    let record = latest_evidence(&repo);
    let coverage = record["coverage"].as_array().expect("coverage evidence");
    assert_eq!(coverage.len(), 2);
    assert!(
        coverage
            .iter()
            .any(|item| { item["workspace_id"] == "selected" && item["status"] == "passed" })
    );
    assert!(
        coverage
            .iter()
            .any(|item| item["workspace_id"] == "other" && item["status"] == "failed")
    );
    let results = record["results"].as_array().expect("serialized results");
    assert!(results.iter().any(|result| {
        result["message"].as_str().is_some_and(|message| {
            message.contains("workspace=selected")
                && message.contains("scope=unit")
                && message.contains("tool=")
        })
    }));
    assert!(results.iter().any(|result| {
        result["message"].as_str().is_some_and(|message| {
            message.contains("workspace=other") && message.contains("failed configured thresholds")
        })
    }));
}

#[test]
fn unknown_workspace_selector_fails_in_central_check_execution() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_workspace_full_check(&repo, "typo");

    assert!(!output.status.success(), "unknown workspace must fail");
    let decision: Value =
        serde_json::from_slice(&output.stderr).expect("check block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains("unknown workspace `typo`"));
    assert!(reason.contains("available workspaces: selected, other"));
    assert!(reason.contains("select a configured workspace id"));
    let record = latest_evidence(&repo);
    assert!(record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["status"] == "failed"
                && result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("unknown workspace `typo`"))
        })
    }));
}

#[test]
fn unknown_workspace_selector_in_direct_hook_payload_is_denied() {
    let repo = TempRepo::new();
    write_workspace_coverage_fixture(&repo);

    let output = run_stop_with_workspace(&repo, "workspace-typo", "typo");

    assert_eq!(output.status.code(), Some(2));
    let decision: Value = serde_json::from_slice(&output.stderr).expect("Stop block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains("unknown workspace `typo`"));
    assert!(reason.contains("available workspaces: selected, other"));
    let record = latest_evidence(&repo);
    assert!(
        record["rules"]["failed"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert_eq!(record["coverage"][0]["status"], "not_applicable");
}

#[test]
fn below_threshold_coverage_blocks_stop_and_full_check() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);

    let stop = run_full_stop(&repo, "coverage-fail", false);

    assert_eq!(stop.status.code(), Some(2));
    let decision: Value = serde_json::from_slice(&stop.stderr).expect("block decision JSON");
    assert_eq!(decision["decision"], "block");
    let reason = decision["reason"].as_str().expect("block reason");
    assert!(reason.contains(COVERAGE_RULE_ID));
    assert!(reason.contains("coverage"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
    assert_eq!(
        projected_coverage_result(&record, "failed")["status"],
        "failed"
    );
    assert!(
        record["rules"]["failed"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );

    let check = run_full_check(&repo);

    assert!(
        !check.status.success(),
        "full check must fail below threshold"
    );
    let check_decision: Value =
        serde_json::from_slice(&check.stderr).expect("full check block decision JSON");
    assert_eq!(check_decision["decision"], "block");
    let check_reason = check_decision["reason"]
        .as_str()
        .expect("full check reason");
    assert!(check_reason.contains(COVERAGE_RULE_ID));
    assert!(check_reason.contains("coverage"));
}

#[test]
fn semantic_coverage_labels_ignore_baseline_substrings_end_to_end() {
    let repo = TempRepo::new();
    write_coverage_fixture(
        &repo,
        "Baseline coverage: 100%\nLine coverage: 50%\nBranch coverage: 90%",
        80,
        80,
    );

    let stop = run_full_stop(&repo, "coverage-label-boundary", false);

    assert_eq!(stop.status.code(), Some(2));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
    assert_eq!(record["coverage"][0]["line_percent"], 50.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 90.0);
}

#[test]
fn unparseable_coverage_is_unverified_and_does_not_fail_stop() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "coverage report unavailable", 80, 80);

    let output = run_full_stop(&repo, "coverage-unverified", false);

    assert!(
        output.status.success(),
        "unverified coverage must allow Stop"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(
        projected_coverage_result(&record, "unverified")["status"],
        "unverified"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[cfg(target_os = "linux")]
#[test]
fn nested_workspace_commands_and_coverage_use_repository_relative_effective_cwds() {
    let repo = TempRepo::new();
    repo.write(
        "workspace/src/required-check",
        "#!/bin/sh\ntouch command-marker\nexit 0\n",
    );
    repo.write(
        "workspace/tests/coverage-check",
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    );
    for path in [
        repo.path().join("workspace/src/required-check"),
        repo.path().join("workspace/tests/coverage-check"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("nested fixture executable");
    }
    repo.write("workspace/src/app.rs", "pub fn value() -> u8 { 1 }\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "workspace",
                "language": "shell",
                "root": "workspace",
                "commands": [{
                    "argv": ["./required-check"],
                    "cwd": "workspace/src",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": [{
                    "argv": ["./coverage-check"],
                    "cwd": "workspace/tests",
                    "timeout_seconds": 30,
                    "scope": "unit",
                    "line_threshold_percent": 80,
                    "branch_threshold_percent": 80
                }]
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    let output = run_full_stop(&repo, "nested-workspace", false);

    assert!(output.status.success(), "nested workspace should pass");
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["cwd"], "workspace/src");
    assert_eq!(record["commands"][0]["exit_code"], 0);
    assert_eq!(record["coverage"][0]["cwd"], "workspace/tests");
    assert_eq!(record["coverage"][0]["status"], "passed");
    assert_eq!(record["coverage"][0]["line_percent"], 100.0);
    assert_eq!(record["coverage"][0]["branch_percent"], 100.0);
    assert!(repo.path().join("workspace/src/command-marker").is_file());
    assert!(
        repo.path()
            .join("workspace/tests/coverage-marker")
            .is_file()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_and_stop_accept_parent_relative_executable_paths() {
    let repo = TempRepo::new();
    repo.write(
        "workspace/bin/check",
        "#!/bin/sh\ntouch ../relative-path-marker\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/bin/check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("parent-relative executable fixture");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["../bin/check"], "cwd": "workspace/src",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));

    let stop = run_full_stop(&repo, "parent-relative-executable", false);
    assert!(stop.status.success());
    assert!(repo.exists("workspace/relative-path-marker"));
}

#[cfg(unix)]
#[test]
fn doctor_accepts_final_symlinks_for_absolute_and_coverage_paths() {
    let repo = TempRepo::new();
    for path in ["workspace/bin/real-command", "workspace/bin/real-coverage"] {
        repo.write(path, "#!/bin/sh\nexit 0\n");
        std::fs::set_permissions(
            repo.path().join(path),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("final symlink target executable");
    }
    let absolute_command = repo.path().join("workspace/bin/absolute-command");
    let bare_command = repo.path().join("workspace/bin/bare-command");
    let coverage_link = repo.path().join("workspace/bin/coverage-link");
    std::os::unix::fs::symlink(
        repo.path().join("workspace/bin/real-command"),
        &absolute_command,
    )
    .expect("absolute executable symlink");
    std::os::unix::fs::symlink(
        repo.path().join("workspace/bin/real-command"),
        &bare_command,
    )
    .expect("bare executable symlink");
    std::os::unix::fs::symlink(
        repo.path().join("workspace/bin/real-coverage"),
        &coverage_link,
    )
    .expect("coverage executable symlink");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    std::fs::create_dir_all(repo.path().join("workspace/tests")).expect("coverage cwd fixture");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [
                    {"argv": [absolute_command.to_string_lossy()], "cwd": "workspace/src",
                        "timeout_seconds": 30, "tier": "full", "purpose": "test",
                        "source": "fixture", "confidence": "high"},
                    {"argv": ["bare-command"], "cwd": "workspace/src",
                        "timeout_seconds": 30, "tier": "full", "purpose": "test",
                        "source": "fixture", "confidence": "high"}
                ],
                "coverage": [{"argv": ["../bin/coverage-link"], "cwd": "workspace/tests",
                    "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .env("PATH", repo.path().join("workspace/bin"))
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    let stdout = String::from_utf8(doctor.stdout).expect("doctor output is UTF-8");
    assert!(stdout.contains("config doctor: clean"));
    assert!(!stdout.contains("MISSING"));
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_cwd_during_command_invalidates_fresh_passing_evidence() {
    let repo = TempRepo::new();
    repo.write(
        "workspace/checks/check",
        "#!/bin/sh\nset -eu\ncurrent=$(pwd)\nparent=$(dirname \"$current\")\nmv \"$current\" \"$parent/checks-old\"\nmkdir \"$parent/checks\"\nprintf x > \"$parent/postrun-runs\"\n",
    );
    let command = repo.path().join("workspace/checks/check");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("post-run command executable");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [command], "cwd": "workspace/checks",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = run_full_stop(&repo, "postrun-cwd-replacement", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["exit_code"], Value::Null);
    assert!(record["results"].as_array().is_some_and(|results| {
        results
            .iter()
            .any(|result| result["status"] == "unverified")
    }));
    assert_eq!(repo.read("workspace/postrun-runs"), "x");
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_nested_cwd_rejects_reuse_of_successful_evidence() {
    let repo = TempRepo::new();
    let outside = std::env::temp_dir().join(format!("lgtm-reuse-cwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir(&outside).expect("outside fixture");
    std::fs::create_dir_all(repo.path().join("workspace/checks")).expect("nested cwd fixture");
    repo.write(
        "workspace/bin/check",
        "#!/bin/sh\nprintf x > ../command-runs\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/bin/check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("reuse executable fixture");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    let executable = repo.path().join("workspace/bin/check");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [executable.to_string_lossy()], "cwd": "workspace/checks",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    assert!(
        run_post_tool_use(&repo, "cwd-reuse", "workspace/src/app.rs")
            .status
            .success()
    );
    let first = run_pre_tool_use_command(&repo, "cwd-reuse", "git commit -m first");
    assert!(first.status.success());
    assert!(
        first.stdout.is_empty(),
        "successful evidence should authorize first run"
    );
    assert_eq!(repo.read("workspace/command-runs"), "x");

    std::fs::remove_dir_all(repo.path().join("workspace/checks")).expect("remove nested cwd");
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace/checks"))
        .expect("replace nested cwd with symlink");
    let second = run_pre_tool_use_command(&repo, "cwd-reuse", "git commit -m retry");
    assert!(second.status.success());
    assert!(
        !second.stdout.is_empty(),
        "invalidated evidence must deny reuse"
    );
    assert_eq!(
        repo.read("workspace/command-runs"),
        "x",
        "outside cwd must not execute"
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["exit_code"], Value::Null);
    assert!(record["results"].as_array().is_some_and(|results| {
        results
            .iter()
            .any(|result| result["status"] == "unverified")
    }));
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_nested_cwds_with_normal_directories_forces_fresh_results() {
    let repo = TempRepo::new();
    for path in ["workspace/checks", "workspace/coverage"] {
        std::fs::create_dir_all(repo.path().join(path)).expect("nested cwd fixture");
    }
    repo.write(
        "workspace/checks/check",
        "#!/bin/sh\nprintf x >> ../command-runs\nexit 0\n",
    );
    repo.write(
        "workspace/coverage/coverage",
        "#!/bin/sh\nprintf x >> ../coverage-runs\necho 'line coverage: 100% branch coverage: 100%'\nexit 0\n",
    );
    for path in [
        repo.path().join("workspace/checks/check"),
        repo.path().join("workspace/coverage/coverage"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("initial cwd executable");
    }
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["./check"], "cwd": "workspace/checks",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": [{"argv": ["./coverage"], "cwd": "workspace/coverage",
                    "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    assert!(
        run_post_tool_use(&repo, "cwd-identity", "workspace/src/app.rs")
            .status
            .success()
    );
    let first = run_pre_tool_use_command(&repo, "cwd-identity", "git commit -m first");
    assert!(first.status.success());
    assert!(
        first.stdout.is_empty(),
        "initial passing gate should authorize"
    );
    assert_eq!(repo.read("workspace/command-runs"), "x");
    assert_eq!(repo.read("workspace/coverage-runs"), "x");

    std::fs::rename(
        repo.path().join("workspace/checks"),
        repo.path().join("workspace/checks-old"),
    )
    .expect("rename command cwd");
    std::fs::rename(
        repo.path().join("workspace/coverage"),
        repo.path().join("workspace/coverage-old"),
    )
    .expect("rename coverage cwd");
    for path in ["workspace/checks", "workspace/coverage"] {
        std::fs::create_dir_all(repo.path().join(path)).expect("replacement cwd");
    }
    repo.write("workspace/checks/check", "#!/bin/sh\nexit 7\n");
    repo.write(
        "workspace/coverage/coverage",
        "#!/bin/sh\necho 'line coverage: 0% branch coverage: 0%'\nexit 7\n",
    );
    for path in [
        repo.path().join("workspace/checks/check"),
        repo.path().join("workspace/coverage/coverage"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("replacement cwd executable");
    }

    let second = run_pre_tool_use_command(&repo, "cwd-identity", "git commit -m retry");
    assert!(second.status.success());
    assert!(
        !second.stdout.is_empty(),
        "replacement results must deny reuse"
    );
    assert_eq!(
        repo.read("workspace/command-runs"),
        "x",
        "old command cwd was not rerun"
    );
    assert_eq!(
        repo.read("workspace/coverage-runs"),
        "x",
        "old coverage cwd was not rerun"
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["exit_code"], 7);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["rule_id"] == COVERAGE_RULE_ID
                && result["status"] == "failed"
                && result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("coverage"))
        })
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_only_command_cwd_forces_fresh_command_evidence() {
    let repo = TempRepo::new();
    std::fs::create_dir_all(repo.path().join("workspace/checks")).expect("nested cwd fixture");
    repo.write(
        "workspace/checks/check",
        "#!/bin/sh\nprintf x >> ../command-runs\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/checks/check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("command fixture executable");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["./check"], "cwd": "workspace/checks",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    assert!(
        run_post_tool_use(&repo, "command-cwd-identity", "workspace/src/app.rs")
            .status
            .success()
    );
    let first = run_pre_tool_use_command(&repo, "command-cwd-identity", "git commit -m first");
    assert!(first.status.success());
    assert!(first.stdout.is_empty(), "initial command should authorize");
    assert_eq!(repo.read("workspace/command-runs"), "x");

    std::fs::rename(
        repo.path().join("workspace/checks"),
        repo.path().join("workspace/checks-old"),
    )
    .expect("rename command cwd");
    std::fs::create_dir_all(repo.path().join("workspace/checks")).expect("replacement cwd");
    repo.write("workspace/checks/check", "#!/bin/sh\nexit 7\n");
    std::fs::set_permissions(
        repo.path().join("workspace/checks/check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("replacement executable");

    let second = run_pre_tool_use_command(&repo, "command-cwd-identity", "git commit -m retry");
    assert!(second.status.success());
    assert!(
        !second.stdout.is_empty(),
        "replacement command must deny reuse"
    );
    assert_eq!(
        repo.read("workspace/command-runs"),
        "x",
        "stale command was not rerun"
    );
    assert_eq!(latest_evidence(&repo)["commands"][0]["exit_code"], 7);
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_only_coverage_cwd_forces_fresh_coverage_evidence() {
    let repo = TempRepo::new();
    std::fs::create_dir_all(repo.path().join("workspace/coverage"))
        .expect("nested coverage cwd fixture");
    repo.write(
        "workspace/coverage/coverage",
        "#!/bin/sh\nprintf x >> ../coverage-runs\necho 'line coverage: 100% branch coverage: 100%'\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/coverage/coverage"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("coverage fixture executable");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [],
                "coverage": [{"argv": ["./coverage"], "cwd": "workspace/coverage",
                    "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    assert!(
        run_post_tool_use(&repo, "coverage-cwd-identity", "workspace/src/app.rs")
            .status
            .success()
    );
    let first = run_pre_tool_use_command(&repo, "coverage-cwd-identity", "git commit -m first");
    assert!(first.status.success());
    assert!(
        first.stdout.is_empty(),
        "initial coverage should authorize: {}",
        String::from_utf8_lossy(&first.stdout)
    );
    assert_eq!(repo.read("workspace/coverage-runs"), "x");

    std::fs::rename(
        repo.path().join("workspace/coverage"),
        repo.path().join("workspace/coverage-old"),
    )
    .expect("rename coverage cwd");
    std::fs::create_dir_all(repo.path().join("workspace/coverage")).expect("replacement cwd");
    repo.write(
        "workspace/coverage/coverage",
        "#!/bin/sh\necho 'line coverage: 0% branch coverage: 0%'\nexit 7\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/coverage/coverage"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("replacement coverage executable");

    let second = run_pre_tool_use_command(&repo, "coverage-cwd-identity", "git commit -m retry");
    assert!(second.status.success());
    assert!(
        !second.stdout.is_empty(),
        "replacement coverage must deny reuse"
    );
    assert_eq!(
        repo.read("workspace/coverage-runs"),
        "x",
        "stale coverage was not rerun"
    );
    assert_eq!(
        latest_evidence(&repo)["coverage"][0]["status"],
        "unverified"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_and_stop_accept_long_relative_executable_paths() {
    let repo = TempRepo::new();
    let components: Vec<String> = (0..129).map(|index| format!("d{index}")).collect();
    let executable = format!("{}/check", components.join("/"));
    repo.write(
        &format!("workspace/{executable}"),
        "#!/bin/sh\nprintf x >> ../long-command-runs\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join(format!("workspace/{executable}")),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("long executable permissions");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [executable], "cwd": "workspace",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));
    assert!(
        run_post_tool_use(&repo, "long-executable", "workspace/src/app.rs")
            .status
            .success()
    );
    let authorized_stop = run_full_stop(&repo, "long-executable", false);
    assert!(authorized_stop.status.success());
    assert_eq!(repo.read("long-command-runs"), "x");
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_path_survives_doctor_and_supervisor_execution() {
    let repo = TempRepo::new();
    let home = OsString::from_vec(b"non-utf8-home-\xfe".to_vec());
    let path_component = OsString::from_vec(b"non-utf8-bin-\xff".to_vec());
    let path_directory = repo.path().join(&path_component);
    std::fs::create_dir_all(&path_directory).expect("non-UTF-8 PATH directory");
    std::fs::write(
        path_directory.join("check"),
        "#!/bin/sh\nprintf '%s' \"$HOME\" > non-utf8-home-marker\nprintf x > non-utf8-path-marker\nexit 0\n",
    )
    .expect("non-UTF-8 PATH executable");
    std::fs::set_permissions(
        path_directory.join("check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("non-UTF-8 PATH executable permissions");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": ".",
                "commands": [{"argv": ["check"], "cwd": ".",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let path = OsString::from_vec(path_directory.as_os_str().as_bytes().to_vec());
    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .env("PATH", &path)
        .env("HOME", &home)
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));

    assert!(
        run_post_tool_use(&repo, "non-utf8-path", "workspace/src/app.rs")
            .status
            .success()
    );
    let stop = run_full_stop_with_path_and_home(
        &repo,
        "non-utf8-path",
        false,
        Some(&path),
        Some(home.as_os_str()),
    );
    assert!(stop.status.success(), "Stop stderr: {:?}", stop.stderr);
    assert_eq!(repo.read("non-utf8-path-marker"), "x");
    assert_eq!(
        std::fs::read(repo.path().join("non-utf8-home-marker")).expect("HOME marker reads"),
        home.as_os_str().as_bytes(),
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["exit_code"], 0);
    assert!(record["commands"][0]["cwd_identity"].as_str().is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_ci_survives_doctor_and_supervisor_execution() {
    let repo = TempRepo::new();
    let ci = OsString::from_vec(b"ci-value-\xfe".to_vec());
    let path_directory = repo.path().join("workspace/bin");
    std::fs::create_dir_all(&path_directory).expect("CI PATH directory");
    repo.write(
        "workspace/bin/check",
        "#!/bin/sh\nprintf '%s' \"$CI\" > ci-marker\nexit 0\n",
    );
    std::fs::set_permissions(
        path_directory.join("check"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("CI executable permissions");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": ".",
                "commands": [{"argv": ["check"], "cwd": ".", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .env("PATH", &path_directory)
        .env("CI", &ci)
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));

    let stop = run_full_stop_with_environment(
        &repo,
        "non-utf8-ci",
        false,
        Some(path_directory.as_os_str()),
        None,
        Some(ci.as_os_str()),
    );
    assert!(stop.status.success(), "Stop stderr: {:?}", stop.stderr);
    assert_eq!(
        std::fs::read(repo.path().join("ci-marker")).expect("CI marker reads"),
        ci.as_os_str().as_bytes(),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sibling_workspace_root_selection_reuses_only_touched_workspace_evidence() {
    let repo = TempRepo::new();
    repo.write("workspace/app2/src/app.rs", "pub fn value() -> u8 { 1 }\n");

    let selected_command_marker = repo.path().join("selected-command-runs");
    let selected_coverage_marker = repo.path().join("selected-coverage-runs");
    let other_command_marker = repo.path().join("other-command-runs");
    let other_coverage_marker = repo.path().join("other-coverage-runs");
    for root in ["app", "app2"] {
        repo.write(
            &format!("workspace/{root}/checks/check"),
            "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
        );
        repo.write(
            &format!("workspace/{root}/coverage/report"),
            "#!/bin/sh\nprintf x >> \"$1\"\necho 'line coverage: 100% branch coverage: 100%'\n",
        );
        for path in [
            repo.path().join(format!("workspace/{root}/checks/check")),
            repo.path()
                .join(format!("workspace/{root}/coverage/report")),
        ] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("sibling fixture executable");
        }
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [
                {
                    "id": "app",
                    "language": "shell",
                    "root": "workspace/app",
                    "commands": [{
                        "argv": ["./check", selected_command_marker.to_string_lossy()],
                        "cwd": "workspace/app/checks",
                        "timeout_seconds": 30,
                        "tier": "full",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    }],
                    "coverage": [{
                        "argv": ["./report", selected_coverage_marker.to_string_lossy()],
                        "cwd": "workspace/app/coverage",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                },
                {
                    "id": "app2",
                    "language": "shell",
                    "root": "workspace/app2",
                    "commands": [{
                        "argv": ["./check", other_command_marker.to_string_lossy()],
                        "cwd": "workspace/app2/checks",
                        "timeout_seconds": 30,
                        "tier": "full",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    }],
                    "coverage": [{
                        "argv": ["./report", other_coverage_marker.to_string_lossy()],
                        "cwd": "workspace/app2/coverage",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                }
            ],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );

    assert!(
        run_post_tool_use(
            &repo,
            "sibling-workspace-reuse",
            "workspace/app2/src/app.rs"
        )
        .status
        .success()
    );
    let first = run_pre_tool_use_command(&repo, "sibling-workspace-reuse", "git commit -m first");
    assert!(
        first.status.success(),
        "first precommit: {:?}",
        first.stderr
    );
    assert!(
        first.stdout.is_empty(),
        "first stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!repo.exists("selected-command-runs"));
    assert!(!repo.exists("selected-coverage-runs"));
    assert_eq!(repo.read("other-command-runs"), "x");
    assert_eq!(repo.read("other-coverage-runs"), "x");

    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().map(Vec::len), Some(1));
    assert_eq!(record["commands"][0]["workspace_id"], "app2");
    assert_eq!(record["commands"][0]["cwd"], "workspace/app2/checks");
    assert_eq!(record["coverage"].as_array().map(Vec::len), Some(1));
    assert_eq!(record["coverage"][0]["workspace_id"], "app2");
    assert_eq!(record["coverage"][0]["cwd"], "workspace/app2/coverage");

    let second = run_pre_tool_use_command(&repo, "sibling-workspace-reuse", "git commit -m second");
    assert!(
        second.status.success(),
        "second precommit: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty());
    assert!(!repo.exists("selected-command-runs"));
    assert!(!repo.exists("selected-coverage-runs"));
    assert_eq!(repo.read("other-command-runs"), "x");
    assert_eq!(repo.read("other-coverage-runs"), "x");
}

#[test]
fn workspace_root_containment_rejects_root_and_sibling_cwds() {
    let repo = TempRepo::new();
    repo.write("src/app.rs", "pub fn value() -> u8 { 1 }\n");
    let invalid_configs = [
        json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["true"], "cwd": ".", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        }),
        json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [],
                "coverage": [{"argv": ["true"], "cwd": "other", "timeout_seconds": 30,
                    "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        }),
    ];
    for config in invalid_configs {
        repo.write(".lgtm/config.json", &config.to_string());
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["config", "validate"])
            .current_dir(repo.path())
            .output()
            .expect("config validation starts");
        assert!(!output.status.success());
        let diagnostic = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
        assert!(
            diagnostic.contains("cwd must equal or descend"),
            "diagnostic: {diagnostic}"
        );
    }
}

#[cfg(unix)]
#[cfg(target_os = "linux")]
#[test]
fn config_doctor_checks_commands_from_their_effective_cwd() {
    let repo = TempRepo::new();
    repo.write("workspace/src/tool", "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(
        repo.path().join("workspace/src/tool"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("doctor fixture executable");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["./tool"], "cwd": "workspace/src", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    assert!(stdout.contains("config doctor: clean"));
    assert!(!stdout.contains("MISSING"));
}

#[cfg(target_os = "linux")]
#[test]
fn searchable_only_cwd_passes_doctor_and_supervised_stop() {
    let repo = TempRepo::new();
    repo.write("workspace/app.rs", "fn app() {}\n");
    std::fs::create_dir_all(repo.path().join("workspace/target/cwd"))
        .expect("searchable cwd exists");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["/bin/true"], "cwd": "workspace/target/cwd", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    std::fs::set_permissions(
        repo.path().join("workspace/target/cwd"),
        std::fs::Permissions::from_mode(0o111),
    )
    .expect("searchable cwd permissions");

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));

    assert!(
        run_post_tool_use(&repo, "searchable-only-cwd", "workspace/app.rs")
            .status
            .success()
    );
    let stop = run_full_stop(&repo, "searchable-only-cwd", false);
    assert!(
        stop.status.success(),
        "stop stderr: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"][0]["exit_code"], 0);
    assert!(record["commands"][0]["cwd_identity"].as_str().is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn config_doctor_accepts_executable_symlink_runtime_can_run() {
    let repo = TempRepo::new();
    repo.write(
        "workspace/src/real-tool",
        "#!/bin/sh\ntouch runtime-marker\nexit 0\n",
    );
    std::fs::set_permissions(
        repo.path().join("workspace/src/real-tool"),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("doctor executable fixture");
    std::os::unix::fs::symlink(
        repo.path().join("workspace/src/real-tool"),
        repo.path().join("workspace/src/tool"),
    )
    .expect("doctor executable symlink");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["./tool"], "cwd": "workspace/src", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(
        String::from_utf8(doctor.stdout)
            .expect("doctor output is UTF-8")
            .contains("config doctor: clean")
    );
    let stop = run_full_stop(&repo, "doctor-executable-symlink", false);
    assert!(stop.status.success());
    assert!(repo.exists("workspace/src/runtime-marker"));
}

#[cfg(unix)]
#[test]
fn config_doctor_rejects_absolute_and_bare_commands_with_symlinked_cwd() {
    let repo = TempRepo::new();
    let outside = std::env::temp_dir().join(format!(
        "lgtm-outside-doctor-{}",
        repo.path()
            .file_name()
            .expect("temporary repository name")
            .to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir(&outside).expect("outside fixture");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace/cwd-link"))
        .expect("doctor cwd symlink");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [
                    {"argv": ["/bin/true"], "cwd": "workspace/cwd-link", "timeout_seconds": 30,
                        "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"},
                    {"argv": ["true"], "cwd": "workspace/cwd-link", "timeout_seconds": 30,
                        "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}
                ],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    assert_eq!(stdout.matches("MISSING").count(), 2);
    assert!(!stdout.contains("config doctor: clean"));
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(target_os = "linux")]
#[test]
fn doctor_and_stop_resolve_relative_path_from_effective_cwd() {
    let repo = TempRepo::new();
    repo.write(
        "workspace/tests/bin/check",
        "#!/bin/sh\nprintf nested > ../relative-path-marker\nexit 0\n",
    );
    repo.write(
        "bin/check",
        "#!/bin/sh\nprintf decoy > decoy-marker\nexit 0\n",
    );
    for path in [
        repo.path().join("workspace/tests/bin/check"),
        repo.path().join("bin/check"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("relative PATH executable permissions");
    }
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["check"], "cwd": "workspace/tests",
                    "timeout_seconds": 30, "tier": "full", "purpose": "relative PATH",
                    "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .env("PATH", "./bin")
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    assert!(String::from_utf8_lossy(&doctor.stdout).contains("config doctor: clean"));

    let stop = run_full_stop_with_path_and_home(
        &repo,
        "relative-path",
        false,
        Some(std::ffi::OsStr::new("./bin")),
        None,
    );
    assert!(stop.status.success());
    assert_eq!(repo.read("workspace/relative-path-marker"), "nested");
    assert!(!repo.exists("decoy-marker"));
}

#[cfg(unix)]
#[test]
fn config_doctor_does_not_use_process_cwd_for_relative_command_or_coverage_paths() {
    let repo = TempRepo::new();
    repo.write("workspace/checks/command", "#!/bin/sh\nexit 0\n");
    repo.write("workspace/coverage/tool", "#!/bin/sh\nexit 0\n");
    repo.write("workspace/src/command", "decoy\n");
    repo.write("workspace/src/coverage", "decoy\n");
    for path in [
        repo.path().join("workspace/checks/command"),
        repo.path().join("workspace/coverage/tool"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("doctor fixture executable");
    }
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": ["workspace/src/command"], "cwd": "workspace/checks",
                    "timeout_seconds": 30, "tier": "full", "purpose": "test",
                    "source": "fixture", "confidence": "high"}],
                "coverage": [{"argv": ["workspace/src/coverage"], "cwd": "workspace/coverage",
                    "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    assert_eq!(stdout.matches("MISSING").count(), 2);
    assert!(!stdout.contains("config doctor: clean"));
}

#[cfg(target_os = "linux")]
#[test]
fn mode_zero_cwd_is_missing_to_doctor_and_stop() {
    let repo = TempRepo::new();
    let cwd = repo.path().join("workspace/locked");
    std::fs::create_dir_all(&cwd).expect("locked cwd fixture");
    repo.write(
        "workspace/bin/absolute",
        "#!/bin/sh\nprintf x > absolute-marker\nexit 0\n",
    );
    repo.write(
        "workspace/bin/bare",
        "#!/bin/sh\nprintf x > bare-marker\nexit 0\n",
    );
    for path in [
        repo.path().join("workspace/bin/absolute"),
        repo.path().join("workspace/bin/bare"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("locked cwd executable permissions");
    }
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [
                    {"argv": [repo.path().join("workspace/bin/absolute")], "cwd": "workspace/locked",
                        "timeout_seconds": 30, "tier": "full", "purpose": "absolute",
                        "source": "fixture", "confidence": "high"},
                    {"argv": ["bare"], "cwd": "workspace/locked",
                        "timeout_seconds": 30, "tier": "full", "purpose": "bare",
                        "source": "fixture", "confidence": "high"}
                ],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    std::fs::set_permissions(&cwd, std::fs::Permissions::from_mode(0o000))
        .expect("remove locked cwd search permission");

    let doctor = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .env("PATH", repo.path().join("workspace/bin"))
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(doctor.status.success());
    let doctor_stdout = String::from_utf8_lossy(&doctor.stdout);
    assert_eq!(doctor_stdout.matches("MISSING").count(), 2);
    assert!(!doctor_stdout.contains("config doctor: clean"));

    let stop = run_full_stop_with_path_and_home(
        &repo,
        "mode-zero-cwd",
        false,
        Some(repo.path().join("workspace/bin").as_os_str()),
        None,
    );
    assert!(stop.status.success());
    assert!(!repo.exists("absolute-marker"));
    assert!(!repo.exists("bare-marker"));
    std::fs::set_permissions(cwd, std::fs::Permissions::from_mode(0o700))
        .expect("restore locked cwd permissions");
}

#[cfg(target_os = "linux")]
#[test]
fn symlinked_command_and_coverage_cwds_fail_closed_before_outside_execution() {
    let repo = TempRepo::new();
    let outside = std::env::temp_dir().join(format!("lgtm-outside-cwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir(&outside).expect("outside fixture");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write("workspace/bin/command", "#!/bin/sh\ntouch command-marker\n");
    repo.write(
        "workspace/bin/coverage",
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    );
    for path in [
        repo.path().join("workspace/bin/command"),
        repo.path().join("workspace/bin/coverage"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("symlink cwd executable");
    }
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace/command-link"))
        .expect("command cwd symlink");
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace/coverage-link"))
        .expect("coverage cwd symlink");
    let command_marker = outside.join("command-marker");
    let coverage_marker = outside.join("coverage-marker");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [repo.path().join("workspace/bin/command")],
                    "cwd": "workspace/command-link", "timeout_seconds": 30, "tier": "full",
                    "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": [{"argv": [repo.path().join("workspace/bin/coverage")],
                    "cwd": "workspace/coverage-link", "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = run_full_stop(&repo, "symlinked-cwd", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().expect("commands").len(), 1);
    assert_eq!(record["commands"][0]["exit_code"], Value::Null);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(!command_marker.exists());
    assert!(!coverage_marker.exists());
    let messages = record["results"].as_array().expect("results");
    assert!(messages.iter().any(|result| {
        result["message"]
            .as_str()
            .is_some_and(|message| message.contains("containment could not be proven"))
    }));
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(target_os = "linux")]
#[test]
fn symlinked_coverage_cwd_is_unverified_without_running_coverage() {
    let repo = TempRepo::new();
    let outside = std::env::temp_dir().join(format!(
        "lgtm-outside-coverage-{}",
        repo.path()
            .file_name()
            .expect("temporary repository name")
            .to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir(&outside).expect("outside fixture");
    repo.write("workspace/src/app.rs", "fn app() {}\n");
    repo.write(
        "workspace/bin/coverage",
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    );
    let coverage = repo.path().join("workspace/bin/coverage");
    std::fs::set_permissions(&coverage, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace/coverage-link"))
        .expect("coverage cwd symlink");
    let outside_marker = outside.join("coverage-marker");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [],
                "coverage": [{"argv": [coverage], "cwd": "workspace/coverage-link",
                    "timeout_seconds": 30, "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "symlinked-coverage-cwd", "workspace/src/app.rs")
            .status
            .success()
    );

    let output = run_full_stop(&repo, "symlinked-coverage-cwd", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().expect("commands").len(), 0);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(!outside_marker.exists());
    assert!(
        record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("containment"))
            })
        }),
        "coverage evidence must include a containment finding"
    );
    let _ = std::fs::remove_dir_all(outside);
}

#[cfg(target_os = "linux")]
#[test]
fn retargeted_workspace_alias_remains_selected_and_cannot_reuse_evidence() {
    let repo = TempRepo::new();
    for target in ["workspace-a", "workspace-b"] {
        repo.write(&format!("{target}/src/app.rs"), "fn app() {}\n");
    }
    repo.write("workspace-a/bin/command", "#!/bin/sh\nexit 0\n");
    let command = repo.path().join("workspace-a/bin/command");
    std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
        .expect("workspace command executable");
    std::os::unix::fs::symlink(
        repo.path().join("workspace-a"),
        repo.path().join("workspace"),
    )
    .expect("workspace alias points to A");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [command], "cwd": "workspace", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "retargeted-workspace", "workspace/src/app.rs")
            .status
            .success()
    );
    std::fs::remove_file(repo.path().join("workspace")).expect("remove old alias");
    std::os::unix::fs::symlink(
        repo.path().join("workspace-b"),
        repo.path().join("workspace"),
    )
    .expect("workspace alias retargets to B");

    for _ in 0..2 {
        let output = run_full_stop(&repo, "retargeted-workspace", false);
        assert!(output.status.success());
        let record = latest_evidence(&repo);
        assert_eq!(record["commands"].as_array().expect("commands").len(), 1);
        assert_eq!(record["commands"][0]["exit_code"], Value::Null);
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("containment could not be proven"))
            })
        }));
    }
}

#[cfg(unix)]
#[test]
fn config_doctor_rejects_empty_symlinked_workspace_root() {
    let repo = TempRepo::new();
    std::fs::create_dir_all(repo.path().join("workspace-real")).expect("workspace root");
    std::os::unix::fs::symlink(
        repo.path().join("workspace-real"),
        repo.path().join("workspace"),
    )
    .expect("workspace root symlink");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [], "coverage": []
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "doctor"])
        .current_dir(repo.path())
        .output()
        .expect("config doctor starts");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("doctor output is UTF-8");
    assert!(stdout.contains("STALE workspace=workspace root=workspace"));
    assert!(!stdout.contains("config doctor: clean"));
}

#[cfg(target_os = "linux")]
#[test]
fn symlinked_workspace_root_selects_obligations_then_fails_closed() {
    let repo = TempRepo::new();
    repo.write("workspace-real/src/app.rs", "fn app() {}\n");
    repo.write(
        "workspace-real/bin/command",
        "#!/bin/sh\ntouch command-marker\n",
    );
    repo.write(
        "workspace-real/bin/coverage",
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    );
    for path in [
        repo.path().join("workspace-real/bin/command"),
        repo.path().join("workspace-real/bin/coverage"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("workspace fixture executable");
    }
    std::os::unix::fs::symlink(
        repo.path().join("workspace-real"),
        repo.path().join("workspace"),
    )
    .expect("workspace root symlink");
    let command = repo.path().join("workspace-real/bin/command");
    let coverage = repo.path().join("workspace-real/bin/coverage");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [{"argv": [command], "cwd": "workspace", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": [{"argv": [coverage], "cwd": "workspace", "timeout_seconds": 30,
                    "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "symlinked-workspace-root", "workspace/src/app.rs")
            .status
            .success()
    );

    let output = run_full_stop(&repo, "symlinked-workspace-root", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().expect("commands").len(), 1);
    assert_eq!(record["commands"][0]["exit_code"], Value::Null);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(!repo.exists("workspace-real/command-marker"));
    assert!(!repo.exists("workspace-real/coverage-marker"));
    assert!(record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["message"]
                .as_str()
                .is_some_and(|message| message.contains("containment could not be proven"))
        })
    }));
}

#[cfg(target_os = "linux")]
#[test]
fn symlinked_workspace_root_selects_coverage_without_commands() {
    let repo = TempRepo::new();
    repo.write("workspace-real/src/app.rs", "fn app() {}\n");
    repo.write(
        "workspace-real/bin/coverage",
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    );
    let coverage = repo.path().join("workspace-real/bin/coverage");
    std::fs::set_permissions(&coverage, std::fs::Permissions::from_mode(0o700))
        .expect("coverage fixture executable");
    std::os::unix::fs::symlink(
        repo.path().join("workspace-real"),
        repo.path().join("workspace"),
    )
    .expect("workspace root symlink");
    let outside_marker = repo.path().join("workspace-real/coverage-marker");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "workspace", "language": "shell", "root": "workspace",
                "commands": [],
                "coverage": [{"argv": [coverage], "cwd": "workspace", "timeout_seconds": 30,
                    "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(
            &repo,
            "symlinked-workspace-root-coverage",
            "workspace/src/app.rs"
        )
        .status
        .success()
    );

    let output = run_full_stop(&repo, "symlinked-workspace-root-coverage", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().expect("commands").len(), 0);
    assert_eq!(record["coverage"].as_array().expect("coverage").len(), 1);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(!outside_marker.exists());
    assert!(
        record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("containment"))
            })
        }),
        "coverage containment result: {record}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn outside_workspace_root_alias_is_selected_and_not_reusable() {
    let repo = TempRepo::new();
    let outside = std::env::temp_dir().join(format!(
        "lgtm-outside-workspace-root-{}",
        repo.path()
            .file_name()
            .expect("temporary repository name")
            .to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(outside.join("src")).expect("outside workspace fixture");
    std::fs::write(outside.join("src/app.rs"), "fn app() {}\n").expect("outside source");
    std::fs::write(
        outside.join("command"),
        "#!/bin/sh\ntouch command-marker\nexit 0\n",
    )
    .expect("outside command");
    std::fs::write(
        outside.join("coverage"),
        "#!/bin/sh\ntouch coverage-marker\necho 'line coverage: 100% branch coverage: 100%'\n",
    )
    .expect("outside coverage");
    for path in [outside.join("command"), outside.join("coverage")] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("outside executable");
    }
    std::fs::create_dir(repo.path().join("workspace")).expect("workspace alias parent");
    std::fs::remove_dir(repo.path().join("workspace")).expect("workspace alias placeholder");
    std::os::unix::fs::symlink(&outside, repo.path().join("workspace"))
        .expect("outside workspace root symlink");
    repo.write("src/app.rs", "fn touched() {}\n");
    let command = outside.join("command");
    let coverage = outside.join("coverage");
    let command_marker = outside.join("command-marker");
    let coverage_marker = outside.join("coverage-marker");
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2", "profile": "default", "workspaces": [{
                "id": "outside", "language": "shell", "root": "workspace",
                "commands": [{"argv": [command], "cwd": "workspace", "timeout_seconds": 30,
                    "tier": "full", "purpose": "test", "source": "fixture", "confidence": "high"}],
                "coverage": [{"argv": [coverage], "cwd": "workspace", "timeout_seconds": 30,
                    "scope": "unit"}]
            }], "disabled_rules": [], "severity_overrides": {}
        })
        .to_string(),
    );
    assert!(
        run_post_tool_use(&repo, "outside-workspace-root", "src/app.rs")
            .status
            .success()
    );

    let output = run_full_stop(&repo, "outside-workspace-root", false);
    assert!(output.status.success());
    let record = latest_evidence(&repo);
    assert_eq!(record["commands"].as_array().expect("commands").len(), 1);
    assert_eq!(record["commands"][0]["exit_code"], Value::Null);
    assert_eq!(record["coverage"].as_array().expect("coverage").len(), 1);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert!(!command_marker.exists());
    assert!(!coverage_marker.exists());
    assert!(record["results"].as_array().is_some_and(|results| {
        results.iter().any(|result| {
            result["message"]
                .as_str()
                .is_some_and(|message| message.contains("containment could not be proven"))
        })
    }));
    let second = run_pre_tool_use_command(&repo, "outside-workspace-root", "git commit -m retry");
    assert!(second.status.success());
    assert!(
        !second.stdout.is_empty(),
        "failed evidence must not authorize reuse"
    );
    let _ = std::fs::remove_dir_all(outside);
}

#[test]
fn missing_coverage_executable_is_unverified_and_does_not_fail_stop() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 100% branch coverage: 100%", 80, 80);
    let missing = repo.path().join("bin/missing-coverage");
    let mut config: Value =
        serde_json::from_str(&repo.read(".lgtm/config.json")).expect("coverage config JSON");
    config["workspaces"][0]["coverage"][0]["argv"][0] = json!(missing);
    repo.write(".lgtm/config.json", &config.to_string());

    let output = run_full_stop(&repo, "coverage-missing", false);

    assert!(
        output.status.success(),
        "missing coverage executable must allow Stop"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(stdout.contains("UNVERIFIED required-repository-commands"));
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "unverified");
    assert_eq!(
        projected_coverage_result(&record, "unverified")["status"],
        "unverified"
    );
    assert_eq!(record["rules"]["failed"], 0);
}

#[test]
fn downgraded_coverage_failure_remains_actionable() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);
    let mut config: Value =
        serde_json::from_str(&repo.read(".lgtm/config.json")).expect("coverage config JSON");
    config["profile"] = json!("prototype");
    repo.write(".lgtm/config.json", &config.to_string());

    let output = run_full_check(&repo);

    assert!(
        output.status.success(),
        "warning-severity profile must not block"
    );
    let summary = String::from_utf8(output.stdout).expect("summary is UTF-8");
    assert!(summary.contains("REVIEW required-repository-commands"));
    assert!(summary.contains("workspace=coverage scope=unit tool="));
    assert!(summary.contains("raise coverage and rerun"));
}

#[test]
fn active_stop_hook_summarizes_failed_coverage_instead_of_blocking() {
    let repo = TempRepo::new();
    write_coverage_fixture(&repo, "line coverage: 50% branch coverage: 50%", 80, 80);

    let output = run_full_stop(&repo, "coverage-active", true);

    assert!(
        output.status.success(),
        "active Stop hook must return a summary"
    );
    assert!(
        output.stderr.is_empty(),
        "summary path must not emit a block"
    );
    let stdout = String::from_utf8(output.stdout).expect("Stop stdout is UTF-8");
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|line| line.contains("failed=1"))
    );
    let record = latest_evidence(&repo);
    assert_eq!(record["coverage"][0]["status"], "failed");
}
