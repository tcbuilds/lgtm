use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

/// Run one PreToolUse hook request and return LGTM's permission response.
///
/// The response is JSON null when LGTM stays silent, which is the expected
/// result on every path now that the automatic hook never answers the host
/// agent's permission decision. A failed process or a failed parse must not
/// masquerade as that silent allow, so both are asserted here.
fn hook_response(payload: serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("exits");
    assert!(
        output.status.success(),
        "hook must exit successfully: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&output.stdout).expect("JSON response")
    }
}

/// Send an Edit or Write PreToolUse payload and return the permission response.
fn run(root: &std::path::Path, tool: &str, file: &str) -> serde_json::Value {
    hook_response(json!({"cwd": root, "session_id": "test-session",
        "tool_name": tool, "tool_input": {"file_path": file}}))
}

/// Send a Bash PreToolUse payload and return the permission response.
fn run_bash(root: &std::path::Path, command: &str) -> serde_json::Value {
    hook_response(json!({"cwd": root, "session_id": "test-session",
        "tool_name": "Bash", "tool_input": {"command": command}}))
}

fn temp_repo(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-pre-{}-{name}", std::process::id()));
    std::fs::create_dir_all(root.join(".lgtm")).expect("dirs");
    std::fs::write(root.join(".lgtm/config.json"), "{}").expect("config");
    root
}

#[test]
fn allows_new_file_and_captures_session_baseline() {
    let root = temp_repo("baseline");
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    assert!(
        root.join(".lgtm/evidence/current-task.baseline.json")
            .is_file()
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn first_session_diff_baseline_is_not_overwritten() {
    let root = temp_repo("first-diff");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(root.join("tracked.py"), "value = 1\n").expect("tracked file");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "tracked.py"])
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args([
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-qm",
                "initial"
            ])
            .status()
            .expect("git commit")
            .success()
    );
    std::fs::write(root.join("before.txt"), "user work\n").expect("preexisting diff");
    assert_eq!(run(&root, "Write", "src/one.py"), json!(null));
    std::fs::write(root.join("after.txt"), "new work\n").expect("later diff");
    assert_eq!(run(&root, "Write", "src/two.py"), json!(null));
    let baseline: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".lgtm/evidence/current-task.baseline.json"))
            .expect("baseline readable"),
    )
    .expect("baseline JSON");
    let files = baseline["diff_files_before"]
        .as_array()
        .expect("diff baseline array");
    assert!(files.contains(&json!("before.txt")));
    assert!(!files.contains(&json!("after.txt")));
    std::fs::remove_dir_all(root).ok();
}

/// Repository path policy is advisory for the automatic hook: traversal,
/// absolute outside paths, and configured prohibited targets must not produce
/// a permission denial.
#[test]
fn traversal_and_prohibited_targets_are_not_denied() {
    let root = temp_repo("deny");
    assert_eq!(run(&root, "Edit", "../outside.py"), json!(null));
    assert_eq!(run(&root, "Edit", "/tmp/outside.py"), json!(null));
    std::fs::write(
        root.join(".lgtm/config.json"),
        r#"{"prohibited_paths":["secrets/**"]}"#,
    )
    .expect("config");
    assert_eq!(run(&root, "Write", "secrets/key.py"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

/// A malformed config must not become a denial; LGTM records the baseline as
/// unverified on stderr and lets the edit proceed.
#[test]
fn malformed_policy_does_not_deny_edit() {
    let root = temp_repo("malformed");
    std::fs::write(root.join(".lgtm/config.json"), "{").expect("config");
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

/// A config that prohibits every path must not produce a veto from the
/// automatic hook.
#[test]
fn all_path_prohibited_policy_does_not_deny_edit() {
    let root = temp_repo("deny-all");
    std::fs::write(
        root.join(".lgtm/config.json"),
        r#"{"prohibited_paths":["*"]}"#,
    )
    .expect("config");
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn non_edit_tool_is_true_noop() {
    let root = temp_repo("noop");
    assert_eq!(run(&root, "Read", "../outside.py"), json!(null));
    assert!(!root.join(".lgtm/evidence").exists());
    std::fs::remove_dir_all(root).ok();
}

/// Claude Code routes shell calls through PreToolUse, and the automatic hook
/// leaves the permission decision to the host agent even when a command is
/// named in `prohibited_commands`.
#[test]
fn prohibited_bash_commands_are_not_denied() {
    let root = temp_repo("bash-deny");
    std::fs::write(
        root.join(".lgtm/execpolicy.json"),
        r#"{"prohibited_commands":[["rm","-rf"],["git","push","--force"]]}"#,
    )
    .expect("execpolicy");
    for command in ["rm -rf /", "rm -rf build/", "git push --force origin main"] {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must pass through without a permission response"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// Commands outside the configured policy pass through untouched, and a shell
/// payload without call identity records an unverified shell-tracking issue
/// instead of a baseline.
#[test]
fn allows_benign_bash_commands_and_safer_variants() {
    let root = temp_repo("bash-allow");
    std::fs::write(
        root.join(".lgtm/execpolicy.json"),
        r#"{"prohibited_commands":[["rm","-rf"],["git","push","--force"]]}"#,
    )
    .expect("execpolicy");
    for command in [
        "ls -la",
        "cargo test",
        "rm build/artifact.o",
        "git push --force-with-lease origin main",
        "git push origin main",
    ] {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must be allowed"
        );
    }
    assert!(
        !root
            .join(".lgtm/evidence/current-task.baseline.json")
            .exists(),
        "a shell payload without call identity must not establish a baseline"
    );
    let evidence = std::fs::read_to_string(root.join(".lgtm/evidence/current-task.results.jsonl"))
        .expect("missing shell identities are recorded as unverified");
    assert!(evidence.contains("shell-change-tracking"));
    assert!(evidence.contains("\"status\":\"unverified\""));
    std::fs::remove_dir_all(root).ok();
}

/// Flag order, long spellings, and privilege wrappers no longer feed a
/// permission veto, so none of these forms may produce a response.
#[test]
fn wrapped_and_reordered_commands_are_not_denied() {
    let root = temp_repo("bash-normalized");
    std::fs::write(
        root.join(".lgtm/execpolicy.json"),
        r#"{"prohibited_commands":[["rm","-rf"],["chmod","-R","777"],["git","push","--force"]]}"#,
    )
    .expect("execpolicy");
    for command in [
        "rm -r -f /tmp/x",
        "rm --recursive --force /tmp/x",
        "rm -fr /tmp/x",
        "chmod 777 -R /tmp/x",
        "env rm -rf /tmp/x",
        "git push origin main --force",
        "sudo -u root rm -rf /tmp/x",
    ] {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must pass through without a permission response"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// Safe variants, bare wrappers, and operands written after `--` stay silent
/// because the matcher is no longer consulted for a decision here.
#[test]
fn allows_safe_variants_bare_wrappers_and_operands_after_end_of_options() {
    let root = temp_repo("bash-exclusions");
    std::fs::write(
        root.join(".lgtm/execpolicy.json"),
        r#"{"prohibited_commands":[["rm","-rf"],["git","push","--force"],["git","clean","-fdx"]]}"#,
    )
    .expect("execpolicy");
    for command in [
        "git push --force-with-lease origin main",
        "sudo git push --force-with-lease origin main",
        "git clean -fd",
        "git clean -ffd",
        "rm -- -rf",
        "sudo",
        "sudo -u root",
        "env FOO=1 cargo test",
        "sudo systemctl restart nginx",
    ] {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must be allowed"
        );
    }
    std::fs::remove_dir_all(root).ok();
}

/// A repository without any policy must not fail closed: shell commands and
/// edits pass through with no permission response.
#[test]
fn missing_policy_does_not_deny_shell_or_edits() {
    let root = temp_repo("no-policy");
    std::fs::remove_file(root.join(".lgtm/config.json")).expect("remove config");
    for command in ["rm -rf /", "git commit -m fixture"] {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must pass through without a permission response"
        );
    }
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

/// A malformed exec policy must not degrade into a denial of every shell call.
#[test]
fn malformed_execpolicy_does_not_deny_bash() {
    let root = temp_repo("bash-malformed");
    std::fs::write(root.join(".lgtm/execpolicy.json"), "{").expect("execpolicy");
    assert_eq!(run_bash(&root, "ls -la"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

/// A symlink whose target sits outside the repository must not produce a veto
/// from the automatic hook.
#[cfg(unix)]
#[test]
fn symlink_target_is_not_denied() {
    let root = temp_repo("symlink");
    std::os::unix::fs::symlink("/tmp", root.join("escape")).expect("symlink");
    assert_eq!(run(&root, "Write", "escape/new.py"), json!(null));
    std::fs::remove_dir_all(root).ok();
}

/// Ordinary commit forms — direct, compound, and wrapped or nested-shell forms —
/// must reach the host agent with no LGTM response. A separate marker payload
/// proves that the hook does not execute requested shell commands.
#[test]
fn direct_compound_and_wrapped_git_commits_stay_permitted() {
    let root = temp_repo("commits");
    let marker = root.join("requested-command-ran.marker");
    let commands = [
        "git commit -m fixture".to_string(),
        format!(
            "git add . && git commit -m fixture && touch {}",
            marker.display()
        ),
        format!(
            "env GIT_AUTHOR_NAME=fixture git commit -m fixture && touch {}",
            marker.display()
        ),
        format!(
            "sh -c 'git commit -m fixture && touch {}'",
            marker.display()
        ),
    ];
    for command in &commands {
        assert_eq!(
            run_bash(&root, command),
            json!(null),
            "{command} must pass through without a permission response"
        );
    }
    assert_eq!(
        run_bash(&root, &format!("touch {}", marker.display())),
        json!(null)
    );
    assert!(
        !marker.exists(),
        "the hook must not execute the requested command"
    );
    std::fs::remove_dir_all(root).ok();
}

/// A repository with a configured full-tier command must not see that command
/// run when a commit is requested. The marker script would touch the marker if
/// the hook invoked it, so an absent marker proves non-execution.
#[cfg(unix)]
#[test]
fn commit_does_not_invoke_configured_pre_commit_commands() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_repo("pre-commit");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status()
            .expect("git init")
            .success()
    );
    std::fs::create_dir_all(root.join("src")).expect("src dir");
    std::fs::write(root.join("src/app.rs"), "pub fn value() -> u8 { 1 }\n").expect("source");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "src/app.rs"])
            .status()
            .expect("git add")
            .success()
    );
    std::fs::write(
        root.join(".lgtm/execpolicy.json"),
        r#"{"prohibited_commands":[]}"#,
    )
    .expect("execpolicy");

    let marker = root.join("configured-command-ran.marker");
    let script = root.join("bin/verify-marker");
    std::fs::create_dir_all(script.parent().expect("script parent")).expect("bin dir");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch \"{}\"\n", marker.display()),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("executable");
    std::fs::write(
        root.join(".lgtm/config.json"),
        json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "verify",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [script.to_string_lossy()],
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
    )
    .expect("config");

    assert_eq!(run_bash(&root, "git commit -m fixture"), json!(null));
    assert!(
        !marker.exists(),
        "the automatic hook must not run configured verification commands"
    );
    std::fs::remove_dir_all(root).ok();
}

/// When baseline storage cannot be written, the edit still passes through with
/// no permission response, and the blocking file is left untouched.
#[test]
fn baseline_storage_failure_does_not_deny_edit() {
    let root = temp_repo("baseline-failure");
    let evidence = root.join(".lgtm/evidence");
    std::fs::write(&evidence, "blocks directory creation\n").expect("blocking file");
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    assert!(
        evidence.is_file(),
        "the hook must not replace the blocking file"
    );
    std::fs::remove_dir_all(root).ok();
}
