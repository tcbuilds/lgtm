//! Integration tests for `lgtm init`.
//!
//! Each test runs the compiled binary inside a throwaway temporary directory so
//! filesystem effects are exercised end to end without touching the repo. The
//! temp directory is created with a process- and counter-unique name and removed
//! on drop so tests stay isolated and leave no residue.

use std::process::Command;

use serde_json::Value;

mod common;
use common::TempRepo;

/// Run `lgtm init` with the temp directory as its working directory.
fn run_init(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("init")
        .current_dir(repo.path())
        .output()
        .expect("lgtm binary should execute")
}

#[test]
fn fresh_python_repo_creates_all_files() {
    let repo = TempRepo::new();
    repo.write(
        "pyproject.toml",
        "[tool.ruff]\nline-length = 88\n\n[tool.pytest.ini_options]\nminversion = \"7.0\"\n",
    );

    let output = run_init(&repo);
    assert!(output.status.success(), "init must succeed on a fresh repo");

    assert!(repo.exists(".lgtm/config.json"), "config must be written");
    assert!(repo.exists(".lgtm/evidence"), "evidence dir must exist");
    assert!(repo.exists(".gitignore"), "gitignore must exist");
    assert!(
        repo.exists(".claude/settings.json"),
        "settings must be written"
    );

    let config = repo.read_json(".lgtm/config.json");
    assert_eq!(config["profile"], "default");
    assert_eq!(config["version"], "1");
    assert_eq!(config["languages"], serde_json::json!(["python"]));
    let commands = &config["required_commands"]["python"];
    assert!(
        commands
            .as_array()
            .expect("commands array")
            .contains(&Value::String("ruff check .".to_string())),
        "detected ruff config must yield a ruff command"
    );

    let gitignore = repo.read(".gitignore");
    assert!(
        gitignore.contains(".lgtm/evidence/"),
        "evidence dir must be gitignored"
    );

    let settings = repo.read_json(".claude/settings.json");
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "Stop",
    ] {
        assert!(
            settings["hooks"][event].is_array(),
            "settings must wire {event}"
        );
    }
}

#[test]
fn uv_repo_gets_uv_pytest_while_plain_repo_gets_bare_pytest() {
    let uv_repo = TempRepo::new();
    uv_repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");
    uv_repo.write("uv.lock", "version = 1\n");
    assert!(run_init(&uv_repo).status.success());
    assert_eq!(
        uv_repo.read_json(".lgtm/config.json")["required_commands"]["python"],
        serde_json::json!(["uv run pytest"])
    );

    let plain_repo = TempRepo::new();
    plain_repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");
    assert!(run_init(&plain_repo).status.success());
    assert_eq!(
        plain_repo.read_json(".lgtm/config.json")["required_commands"]["python"],
        serde_json::json!(["pytest"])
    );
}

#[test]
fn merge_preserves_existing_unrelated_hook() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(
        ".claude/settings.json",
        r#"{
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "echo existing"}]}
    ]
  }
}"#,
    );

    let output = run_init(&repo);
    assert!(output.status.success(), "init must succeed when merging");

    let settings = repo.read_json(".claude/settings.json");
    assert_eq!(
        settings["permissions"]["allow"],
        serde_json::json!(["Bash(ls:*)"]),
        "unrelated settings must be preserved"
    );

    let session_start = settings["hooks"]["SessionStart"]
        .as_array()
        .expect("SessionStart array");
    assert_eq!(
        session_start.len(),
        2,
        "pre-existing hook kept and lgtm entry added"
    );
    let commands: Vec<&str> = session_start
        .iter()
        .filter_map(|entry| entry["hooks"][0]["command"].as_str())
        .collect();
    assert!(commands.contains(&"echo existing"));
    assert!(commands.contains(&"lgtm hook session-start"));
}

#[test]
fn double_init_does_not_duplicate_entries() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");

    assert!(run_init(&repo).status.success(), "first init must succeed");
    let first_settings = repo.read(".claude/settings.json");
    let first_gitignore = repo.read(".gitignore");

    assert!(run_init(&repo).status.success(), "second init must succeed");
    let second_settings = repo.read(".claude/settings.json");
    let second_gitignore = repo.read(".gitignore");

    assert_eq!(
        first_settings, second_settings,
        "re-running init must not change settings.json"
    );
    assert_eq!(
        first_gitignore, second_gitignore,
        "re-running init must not duplicate gitignore lines"
    );

    let settings = repo.read_json(".claude/settings.json");
    assert_eq!(
        settings["hooks"]["SessionStart"]
            .as_array()
            .expect("array")
            .len(),
        1,
        "idempotent merge must leave exactly one lgtm SessionStart entry"
    );
}

#[test]
fn malformed_settings_are_refused_and_untouched() {
    let repo = TempRepo::new();
    let malformed = "{ this is not valid json ]";
    repo.write(".claude/settings.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "malformed settings must cause a non-zero exit"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("malformed"),
        "stderr must explain the malformed settings, got: {stderr}"
    );
    assert_eq!(
        repo.read(".claude/settings.json"),
        malformed,
        "malformed settings must not be overwritten"
    );
}

#[test]
fn settings_root_non_object_is_refused() {
    let repo = TempRepo::new();
    let non_object = "[1, 2, 3]";
    repo.write(".claude/settings.json", non_object);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-object settings root must cause a non-zero exit"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("not a JSON object"),
        "stderr must explain the non-object settings, got: {stderr}"
    );
    assert_eq!(
        repo.read(".claude/settings.json"),
        non_object,
        "refused settings must not be overwritten"
    );
    assert!(
        !repo.exists(".lgtm/config.json"),
        "no writes may occur when settings validation fails"
    );
}

#[test]
fn settings_hooks_wrong_type_is_refused() {
    let repo = TempRepo::new();
    let bad_hooks = r#"{"hooks": "not an object"}"#;
    repo.write(".claude/settings.json", bad_hooks);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-object hooks value must cause a non-zero exit"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("hooks"),
        "stderr must explain the malformed hooks value, got: {stderr}"
    );
    assert_eq!(
        repo.read(".claude/settings.json"),
        bad_hooks,
        "refused settings must not be overwritten"
    );
    assert!(
        !repo.exists(".lgtm/config.json"),
        "no writes may occur when settings validation fails"
    );
}

#[test]
fn settings_event_value_wrong_type_is_refused() {
    let repo = TempRepo::new();
    let bad_event = r#"{"hooks": {"SessionStart": "not an array"}}"#;
    repo.write(".claude/settings.json", bad_event);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-array event value must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".claude/settings.json"),
        bad_event,
        "refused settings must not be overwritten"
    );
    assert!(
        !repo.exists(".lgtm/config.json"),
        "no writes may occur when settings validation fails"
    );
}

#[test]
fn existing_lgtm_entry_with_wrong_matcher_is_corrected() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(
        ".claude/settings.json",
        r#"{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "lgtm hook pre-tool-use"}]}
    ]
  }
}"#,
    );

    let output = run_init(&repo);
    assert!(
        output.status.success(),
        "init must succeed while correcting"
    );

    let settings = repo.read_json(".claude/settings.json");
    let entries = settings["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse array");
    assert_eq!(
        entries.len(),
        1,
        "the existing lgtm entry must be corrected in place, not duplicated"
    );
    assert_eq!(
        entries[0]["matcher"],
        serde_json::json!("Edit|Write"),
        "the wrong matcher must be corrected to the expected value"
    );
}

#[test]
fn existing_path_qualified_lgtm_command_is_not_duplicated() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(
        ".claude/settings.json",
        r#"{
  "hooks": {
    "Stop": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/lgtm hook stop"}]}
    ]
  }
}"#,
    );

    let output = run_init(&repo);
    assert!(output.status.success(), "init must succeed");

    let settings = repo.read_json(".claude/settings.json");
    let entries = settings["hooks"]["Stop"].as_array().expect("Stop array");
    assert_eq!(
        entries.len(),
        1,
        "a path-qualified lgtm command must be recognized and not duplicated"
    );
    assert_eq!(
        entries[0]["hooks"][0]["command"],
        serde_json::json!("/usr/local/bin/lgtm hook stop"),
        "the already-correct path-qualified entry must be left as authored"
    );
}

#[test]
fn gitignore_without_trailing_newline_gets_clean_append() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(".gitignore", "target/");

    let output = run_init(&repo);
    assert!(
        output.status.success(),
        "init must succeed appending gitignore"
    );

    let gitignore = repo.read(".gitignore");
    assert_eq!(
        gitignore, "target/\n.lgtm/evidence/\n",
        "the evidence line must be appended on its own line after a missing newline"
    );
}

#[test]
fn claude_existing_as_file_errors_without_panic() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(".claude", "this is a file, not a directory");

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "init must fail cleanly when .claude is a file, not panic"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr utf-8");
    assert!(
        stderr.contains("init failed"),
        "stderr must report a typed init failure, got: {stderr}"
    );
}

#[test]
fn config_is_preserved_on_reinit() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");

    assert!(run_init(&repo).status.success(), "first init must succeed");

    let mut config = repo.read_json(".lgtm/config.json");
    config["disabled_rules"] = serde_json::json!(["PY-NO-BARE-EXCEPT"]);
    config["severity_overrides"] = serde_json::json!({"PY-LINE-LENGTH": "warning"});
    repo.write(
        ".lgtm/config.json",
        &serde_json::to_string_pretty(&config).expect("config serializes"),
    );

    let output = run_init(&repo);
    assert!(output.status.success(), "re-init must succeed");

    let after = repo.read_json(".lgtm/config.json");
    assert_eq!(
        after["disabled_rules"],
        serde_json::json!(["PY-NO-BARE-EXCEPT"]),
        "user-edited disabled_rules must be preserved across re-init"
    );
    assert_eq!(
        after["severity_overrides"],
        serde_json::json!({"PY-LINE-LENGTH": "warning"}),
        "user-edited severity_overrides must be preserved across re-init"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    assert!(
        stdout.contains("preserved existing .lgtm/config.json"),
        "summary must report that config was preserved, got: {stdout}"
    );
}

#[test]
fn reinit_adds_missing_version_but_refuses_mismatch() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"profile":"strict","languages":[],"required_commands":{}}"#,
    );
    assert!(run_init(&repo).status.success());
    let migrated = repo.read_json(".lgtm/config.json");
    assert_eq!(migrated["version"], "1");
    assert_eq!(migrated["profile"], "strict");

    repo.write(".lgtm/config.json", r#"{"version":"2","profile":"strict"}"#);
    let before = repo.read(".lgtm/config.json");
    let output = run_init(&repo);
    assert!(!output.status.success());
    assert_eq!(repo.read(".lgtm/config.json"), before);
    assert!(
        String::from_utf8(output.stderr)
            .expect("UTF-8 stderr")
            .contains("config version mismatch")
    );
}

#[test]
fn malformed_config_is_refused_and_untouched() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = "{ not valid json";
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "malformed config must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "malformed config must not be overwritten"
    );
}

#[test]
fn config_with_wrong_typed_languages_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"languages": "python", "profile": "default"}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a wrong-typed languages field must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_non_string_language_element_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"languages": [1, 2]}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a languages array with non-string elements must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_wrong_typed_profile_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"profile": ["default"]}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-string profile must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_wrong_typed_disabled_rules_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"disabled_rules": "PY-NO-BARE-EXCEPT"}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-array disabled_rules must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_non_string_disabled_rule_element_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"disabled_rules": ["ok", 7]}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-string disabled_rules element must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_wrong_typed_severity_overrides_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"severity_overrides": ["PY-LINE-LENGTH"]}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-object severity_overrides must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_non_string_severity_value_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"severity_overrides": {"PY-LINE-LENGTH": 3}}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-string severity value must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_non_object_required_commands_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"required_commands": ["ruff check ."]}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a non-object required_commands must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_required_commands_non_array_value_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"required_commands": {"python": "ruff check ."}}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a required_commands value that is not an array must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[test]
fn config_with_required_commands_non_string_element_is_refused() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let malformed = r#"{"required_commands": {"python": ["ruff check .", 9]}}"#;
    repo.write(".lgtm/config.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "a required_commands array with a non-string element must cause a non-zero exit"
    );
    assert_eq!(
        repo.read(".lgtm/config.json"),
        malformed,
        "a refused config must not be overwritten"
    );
}

#[cfg(unix)]
#[test]
fn reinit_preserves_existing_settings_file_mode() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");

    assert!(run_init(&repo).status.success(), "first init must succeed");

    let settings_path = repo.path().join(".claude").join("settings.json");
    std::fs::set_permissions(&settings_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600 must succeed");

    repo.write(
        ".claude/settings.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({
                "permissions": {"allow": ["Bash(ls:*)"]}
            }))
            .expect("settings serialize")
        ),
    );
    std::fs::set_permissions(&settings_path, std::fs::Permissions::from_mode(0o600))
        .expect("re-chmod 0600 must succeed");

    let output = run_init(&repo);
    assert!(output.status.success(), "re-init must succeed and rewrite");

    let mode = std::fs::metadata(&settings_path)
        .expect("settings metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o600,
        "re-init must preserve the existing 0600 mode across the atomic rewrite"
    );
}

#[test]
fn negated_evidence_gitignore_rule_triggers_append() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    repo.write(".gitignore", ".lgtm/\n!.lgtm/evidence/\n");

    let output = run_init(&repo);
    assert!(
        output.status.success(),
        "init must succeed appending the evidence rule"
    );

    let gitignore = repo.read(".gitignore");
    assert_eq!(
        gitignore, ".lgtm/\n!.lgtm/evidence/\n.lgtm/evidence/\n",
        "a wholesale ignore later negated for evidence must get an explicit re-ignore appended"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_config_target_is_refused() {
    use std::os::unix::fs::symlink;

    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");

    let outside = repo.path().join("outside-config.json");
    std::fs::write(&outside, "{}").expect("outside file writable");
    std::fs::create_dir_all(repo.path().join(".lgtm")).expect(".lgtm dir creatable");
    symlink(&outside, repo.path().join(".lgtm").join("config.json"))
        .expect("symlink should be creatable");

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "init must refuse to write through a symlinked config target"
    );
    assert_eq!(
        std::fs::read_to_string(&outside).expect("outside readable"),
        "{}",
        "the symlink target outside the intended path must be untouched"
    );
    assert!(
        !repo.exists(".gitignore"),
        "no scaffolding may be created when a target is a symlink"
    );
}

#[test]
fn repo_with_no_language_still_scaffolds() {
    let repo = TempRepo::new();

    let output = run_init(&repo);
    assert!(
        output.status.success(),
        "init must succeed with no language"
    );

    let config = repo.read_json(".lgtm/config.json");
    assert_eq!(config["languages"], serde_json::json!([]));
    assert_eq!(config["required_commands"], serde_json::json!({}));
    assert!(repo.exists(".claude/settings.json"), "hooks still wired");
}
