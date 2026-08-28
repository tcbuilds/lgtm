//! Integration tests for `lgtm init`.
//!
//! Each test runs the compiled binary inside a throwaway temporary directory so
//! filesystem effects are exercised end to end without touching the repo. The
//! temp directory is created with a process- and counter-unique name and removed
//! on drop so tests stay isolated and leave no residue.

use std::process::Command;

use serde_json::json;

mod common;
use common::TempRepo;

/// Run `lgtm init` with the temp directory as its working directory.
fn run_init(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--accept-guesses"])
        .current_dir(repo.path())
        .output()
        .expect("lgtm binary should execute")
}

fn run_init_dry_run(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--dry-run"])
        .current_dir(repo.path())
        .output()
        .expect("lgtm init dry-run should execute")
}

fn run_init_codex(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "codex", "--accept-guesses"])
        .current_dir(repo.path())
        .output()
        .expect("Codex init should execute")
}

fn run_init_pi(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--accept-guesses"])
        .current_dir(repo.path())
        .output()
        .expect("Pi init should execute")
}

fn run_init_pi_dry_run(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", "pi", "--dry-run"])
        .current_dir(repo.path())
        .output()
        .expect("Pi dry-run should execute")
}

fn run_migrate(repo: &TempRepo, dry_run: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.arg("init").arg("--migrate-config");
    if dry_run {
        command.arg("--dry-run");
    }
    command
        .current_dir(repo.path())
        .output()
        .expect("lgtm config migration should execute")
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
    assert_eq!(config["version"], "2");
    let python = config["workspaces"]
        .as_array()
        .expect("workspaces")
        .iter()
        .find(|workspace| workspace["language"] == "python")
        .expect("python workspace");
    let commands = python["commands"].as_array().expect("commands");
    assert!(
        commands
            .iter()
            .any(|command| command["argv"] == serde_json::json!(["ruff", "check"])),
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
    assert_eq!(
        settings["enabledPlugins"]["rust-analyzer-lsp@claude-plugins-official"],
        json!(true)
    );
    assert!(
        settings["permissions"]["deny"]
            .as_array()
            .expect("deny permissions")
            .contains(&json!("Write(**/settings.local.json)"))
    );
}

#[cfg(unix)]
#[test]
fn fresh_init_creates_private_evidence_ancestry() {
    use std::os::unix::fs::PermissionsExt;

    let repo = TempRepo::new();
    assert!(run_init(&repo).status.success(), "init must succeed");

    for path in [".lgtm", ".lgtm/evidence"] {
        let mode = std::fs::metadata(repo.path().join(path))
            .expect("evidence ancestry metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{path} must be private");
    }
}

/// A fresh repository must ship destructive-command protection. Without a
/// seeded `.lgtm/execpolicy.json` the prohibited-command gate has an empty list
/// and enforces nothing.
#[test]
fn fresh_init_seeds_a_default_execpolicy() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");

    let output = run_init(&repo);
    assert!(output.status.success(), "init must succeed on a fresh repo");
    assert!(
        repo.exists(".lgtm/execpolicy.json"),
        "a fresh repo must get destructive-command protection"
    );

    let policy = repo.read_json(".lgtm/execpolicy.json");
    let commands = policy["prohibited_commands"]
        .as_array()
        .expect("prohibited_commands array");
    assert!(commands.contains(&json!(["rm", "-rf"])));
    assert!(commands.contains(&json!(["git", "push", "--force"])));
    assert!(commands.contains(&json!(["git", "reset", "--hard"])));

    let settings = repo.read_json(".claude/settings.json");
    assert_eq!(
        settings["hooks"]["PreToolUse"][0]["matcher"], "Bash|Edit|Write",
        "Bash must reach the gate or the seeded policy is dead code"
    );
}

/// Re-init must never clobber or reorder a hand-authored command policy, the
/// same guarantee `.lgtm/config.json` already carries.
#[test]
fn existing_execpolicy_is_preserved_on_reinit() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");
    let authored = "{\"prohibited_commands\":[[\"terraform\",\"destroy\"]]}\n";
    repo.write(".lgtm/execpolicy.json", authored);

    let output = run_init(&repo);
    assert!(output.status.success(), "init must succeed");
    assert_eq!(
        repo.read(".lgtm/execpolicy.json"),
        authored,
        "a user-authored execpolicy must survive byte-for-byte"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("preserved existing .lgtm/execpolicy.json")
    );
}

/// The seeded policy must compile into the Codex rules file during the same run
/// that creates it, not only on a second init.
#[test]
fn codex_init_compiles_the_seeded_execpolicy_in_the_same_run() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "httpx\n");

    let output = run_init_codex(&repo);
    assert!(output.status.success(), "Codex init must succeed");
    assert!(repo.exists(".lgtm/execpolicy.json"));
    let rules = repo.read(".codex/rules/lgtm.rules");
    assert!(rules.contains("prefix_rule(pattern=[\"rm\",\"-rf\"]"));
}

#[test]
fn codex_init_creates_and_idempotently_merges_project_hooks() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[project]\nname = \"fixture\"\n");
    repo.write(
        ".codex/hooks.json",
        &serde_json::to_string_pretty(&json!({
            "permissions": {"allow": ["Bash"]},
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "other"}]}]
            }
        }))
        .expect("fixture serializes"),
    );

    let first = run_init_codex(&repo);
    assert!(first.status.success(), "Codex init must succeed");
    let hooks = repo.read_json(".codex/hooks.json");
    assert_eq!(hooks["permissions"], json!({"allow": ["Bash"]}));
    assert_eq!(
        hooks["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "lgtm hook pre-tool-use --adapter codex"
    );
    assert_eq!(
        hooks["hooks"]["PreToolUse"][0]["matcher"],
        "^(apply_patch|Edit|Write|exec_command|unified_exec|Bash)$"
    );
    assert_eq!(
        hooks["hooks"]["PermissionRequest"][0]["hooks"][0]["command"],
        "lgtm hook permission-request --adapter codex"
    );
    assert_eq!(
        hooks["hooks"]["SubagentStart"][0]["hooks"][0]["command"],
        "lgtm hook subagent-start --adapter codex"
    );
    let first_bytes = repo.read(".codex/hooks.json");

    let second = run_init_codex(&repo);
    assert!(second.status.success(), "second Codex init must succeed");
    assert_eq!(repo.read(".codex/hooks.json"), first_bytes);
}

#[test]
fn codex_init_generates_optional_execpolicy_rules_without_overclaiming_paths() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/execpolicy.json",
        r#"{"prohibited_commands":[["git","reset","--hard"]],"prohibited_paths":["secrets/**"]}"#,
    );
    let output = run_init_codex(&repo);
    assert!(output.status.success(), "Codex init must succeed");
    let rules = repo.read(".codex/rules/lgtm.rules");
    assert!(rules.contains("prefix_rule(pattern=[\"git\",\"reset\",\"--hard\"]"));
    assert!(rules.contains("hook-enforced"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("defense-in-depth"));
}

#[test]
fn codex_init_clears_stale_generated_rules_when_last_command_is_removed() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/execpolicy.json",
        r#"{"prohibited_commands":[["git","reset","--hard"]],"prohibited_paths":["secrets/**"]}"#,
    );

    let first = run_init_codex(&repo);
    assert!(first.status.success(), "initial Codex init must succeed");
    assert!(
        repo.read(".codex/rules/lgtm.rules")
            .contains("prefix_rule(")
    );

    repo.write(
        ".lgtm/execpolicy.json",
        r#"{"prohibited_commands":[],"prohibited_paths":["secrets/**"]}"#,
    );
    let cleared = run_init_codex(&repo);
    assert!(
        cleared.status.success(),
        "empty-command re-init must succeed"
    );
    let cleared_rules = repo.read(".codex/rules/lgtm.rules");
    assert!(!cleared_rules.contains("prefix_rule("));
    assert!(cleared_rules.contains("# lgtm path rule (hook-enforced): secrets/**"));
    let cleared_stdout = String::from_utf8_lossy(&cleared.stdout);
    assert!(cleared_stdout.contains("regenerating "));
    assert!(cleared_stdout.contains(".codex/rules/lgtm.rules"));

    let stable_rules = cleared_rules.clone();
    let stable = run_init_codex(&repo);
    assert!(
        stable.status.success(),
        "idempotent Codex re-init must succeed"
    );
    assert_eq!(repo.read(".codex/rules/lgtm.rules"), stable_rules);
    assert!(
        !String::from_utf8_lossy(&stable.stdout).contains("regenerating .codex/rules/lgtm.rules")
    );
}

#[test]
fn codex_init_preserves_user_written_rules_byte_for_byte() {
    let repo = TempRepo::new();
    let authored = "# user-owned Codex rules\nprefix_rule(pattern=[\"ls\"], decision=\"allow\")\n";
    repo.write(
        ".lgtm/execpolicy.json",
        r#"{"prohibited_commands":[["git","reset","--hard"]]}"#,
    );
    repo.write(".codex/rules/lgtm.rules", authored);

    let output = run_init_codex(&repo);
    assert!(
        output.status.success(),
        "Codex init must preserve user rules"
    );
    assert_eq!(repo.read(".codex/rules/lgtm.rules"), authored);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("preserving existing "));
    assert!(stdout.contains(".codex/rules/lgtm.rules"));
    assert!(!stdout.contains("regenerating "));
}

#[test]
fn codex_hook_command_runs_from_subdirectory_without_path_lookup() {
    let repo = TempRepo::new();
    repo.write("nested/.keep", "fixture\n");
    let binary = env!("CARGO_BIN_EXE_lgtm");
    let output = Command::new(binary)
        .args(["init", "--agent", "codex", "--accept-guesses"])
        .env("LGTM_HOOK_BINARY", binary)
        .current_dir(repo.path())
        .output()
        .expect("Codex init should execute");
    assert!(output.status.success(), "Codex init must succeed");

    let hooks = repo.read_json(".codex/hooks.json");
    let command = hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"]
        .as_str()
        .expect("session hook command");
    let argv = shlex::split(command).expect("hook command quoting");
    let mut hook = Command::new(&argv[0]);
    hook.args(&argv[1..])
        .current_dir(repo.path().join("nested"))
        .env("PATH", "/nonexistent")
        .env("HOME", repo.path());
    let mut child = hook
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("absolute hook command should launch");
    std::io::Write::write_all(
        &mut child.stdin.take().expect("hook stdin"),
        br#"{"hookEventName":"SessionStart","cwd":"."}"#,
    )
    .expect("hook payload writes");
    let result = child.wait_with_output().expect("hook completes");
    assert!(result.status.success());
    assert!(
        !result.stdout.is_empty(),
        "session hook should emit context"
    );
}

#[test]
fn init_dry_run_reports_plan_without_writing_files() {
    let repo = TempRepo::new();
    repo.write("backend/pyproject.toml", "[tool.ruff]\n");
    let output = run_init_dry_run(&repo);
    assert!(output.status.success(), "dry-run must succeed");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("dry-run: no files changed"));
    assert!(text.contains(
        "files: .lgtm/config.json, .lgtm/execpolicy.json, .gitignore, .claude/settings.json"
    ));
    assert!(!repo.exists(".lgtm/config.json"));
    assert!(!repo.exists(".lgtm/execpolicy.json"));
    assert!(!repo.exists(".claude/settings.json"));
}

#[test]
fn init_accepts_declared_pytest_without_guessing_other_tools() {
    let repo = TempRepo::new();
    repo.write("requirements.txt", "pytest\n");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("init")
        .current_dir(repo.path())
        .output()
        .expect("init executes");
    assert!(
        output.status.success(),
        "declared pytest should be accepted"
    );
    let config = repo.read_json(".lgtm/config.json");
    assert_eq!(
        config["workspaces"][0]["commands"][0]["argv"],
        json!(["pytest"])
    );
}

#[test]
fn migrate_config_backs_up_v1_and_writes_validated_v2() {
    let repo = TempRepo::new();
    let original = r#"{
  "version": "1",
  "profile": "strict",
  "languages": ["python"],
  "required_commands": {"python": ["uv run pytest"]},
  "disabled_rules": ["example"],
  "severity_overrides": {"example": "warning"}
}"#;
    repo.write(".lgtm/config.json", original);
    let output = run_migrate(&repo, false);
    assert!(output.status.success(), "migration must succeed");
    assert_eq!(repo.read(".lgtm/config.v1.bak.json"), original);
    let config = repo.read_json(".lgtm/config.json");
    assert_eq!(config["version"], "2");
    assert_eq!(
        config["workspaces"][0]["commands"][0]["argv"],
        serde_json::json!(["uv", "run", "pytest"])
    );
    assert_eq!(config["disabled_rules"], serde_json::json!(["example"]));
}

#[test]
fn migrate_config_dry_run_preserves_v1_bytes() {
    let repo = TempRepo::new();
    let original = r#"{"version":"1","required_commands":{"python":["pytest"]}}"#;
    repo.write(".lgtm/config.json", original);
    let output = run_migrate(&repo, true);
    assert!(output.status.success(), "migration dry-run must succeed");
    assert_eq!(repo.read(".lgtm/config.json"), original);
    assert!(!repo.exists(".lgtm/config.v1.bak.json"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("dry-run: no files changed"));
}

#[test]
fn init_reports_nested_workspaces_without_executing_commands() {
    let repo = TempRepo::new();
    repo.write("backend/pyproject.toml", "[tool.ruff]\n");
    repo.write(
        "frontend/package.json",
        "{\"scripts\":{\"lint\":\"eslint .\"}}\n",
    );

    let output = run_init(&repo);
    assert!(
        output.status.success(),
        "init must discover nested workspaces"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("workspaces: 2"));
    assert!(text.contains("backend (python) cwd=backend"));
    assert!(text.contains("frontend (typescript) cwd=frontend"));
}

#[test]
fn uv_repo_gets_uv_pytest_while_plain_repo_gets_bare_pytest() {
    let uv_repo = TempRepo::new();
    uv_repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");
    uv_repo.write("uv.lock", "version = 1\n");
    assert!(run_init(&uv_repo).status.success());
    assert_eq!(
        uv_repo.read_json(".lgtm/config.json")["workspaces"][0]["commands"][0]["argv"],
        serde_json::json!(["uv", "run", "pytest"])
    );

    let plain_repo = TempRepo::new();
    plain_repo.write("pyproject.toml", "[tool.pytest.ini_options]\n");
    assert!(run_init(&plain_repo).status.success());
    assert_eq!(
        plain_repo.read_json(".lgtm/config.json")["workspaces"][0]["commands"][0]["argv"],
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
      {"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "lgtm hook pre-tool-use"}]}
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
        serde_json::json!("Bash|Edit|Write"),
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
        gitignore, "target/\n**/.lgtm/evidence/\n",
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
    assert!(
        after.get("languages").is_none(),
        "V2 re-init must not add legacy languages"
    );
    assert!(
        after.get("required_commands").is_none(),
        "V2 re-init must not add legacy required_commands"
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf-8");
    assert!(
        stdout.contains("preserved existing .lgtm/config.json"),
        "summary must report that config was preserved, got: {stdout}"
    );
}

#[test]
fn v2_config_with_legacy_fields_is_repaired() {
    let repo = TempRepo::new();
    let config = r#"{
        "version": "2",
        "profile": "default",
        "workspaces": [],
        "disabled_rules": [],
        "severity_overrides": {},
        "languages": ["python"],
        "required_commands": {"python": ["pytest"]}
    }"#;
    repo.write(".lgtm/config.json", config);

    let output = run_init(&repo);
    assert!(output.status.success());
    let repaired = repo.read_json(".lgtm/config.json");
    assert!(repaired.get("languages").is_none());
    assert!(repaired.get("required_commands").is_none());
    assert!(
        String::from_utf8(output.stdout)
            .expect("stderr utf-8")
            .contains("removed obsolete V1 languages and required_commands")
    );
}

#[test]
fn v2_config_with_unrelated_unknown_field_is_refused_without_mutation() {
    let repo = TempRepo::new();
    let config = r#"{
        "version": "2",
        "profile": "default",
        "workspaces": [],
        "disabled_rules": [],
        "severity_overrides": {},
        "unexpected": true
    }"#;
    repo.write(".lgtm/config.json", config);

    let output = run_init(&repo);
    assert!(!output.status.success());
    assert_eq!(repo.read(".lgtm/config.json"), config);
    assert!(
        String::from_utf8(output.stderr)
            .expect("stderr utf-8")
            .contains("Additional properties are not allowed")
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
    assert_eq!(migrated["version"], "2");
    assert_eq!(migrated["profile"], "strict");

    repo.write(".lgtm/config.json", r#"{"version":"3","profile":"strict"}"#);
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
        gitignore, ".lgtm/\n!.lgtm/evidence/\n**/.lgtm/evidence/\n",
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
    assert_eq!(config["workspaces"], serde_json::json!([]));
    assert!(repo.exists(".claude/settings.json"), "hooks still wired");
}

/// Run `lgtm init --rules-only` for one agent inside the temp repo.
fn run_init_rules_only(repo: &TempRepo, agent: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--rules-only", "--agent", agent])
        .current_dir(repo.path())
        .output()
        .expect("rules-only init should execute")
}

/// Codex does not read `.claude/rules/`, so writing only there was a silent
/// no-op dressed up as success. It must get an `AGENTS.md` it actually loads.
#[test]
fn codex_rules_only_writes_agents_md_instead_of_claude_rules() {
    let repo = TempRepo::new();

    let output = run_init_rules_only(&repo, "codex");
    assert!(output.status.success(), "rules-only init must succeed");
    assert!(
        repo.exists("AGENTS.md"),
        "Codex guidance must land in the file Codex reads"
    );
    assert!(
        !repo.exists(".claude/rules"),
        "Codex must not be given a directory it never reads"
    );

    let agents = repo.read("AGENTS.md");
    assert!(
        !agents.starts_with("---"),
        "Claude-specific paths frontmatter must be stripped"
    );
    assert!(
        !agents.contains("\npaths:\n"),
        "no template's paths frontmatter may survive concatenation"
    );
    for marker in ["# Rust", "# Python", "# TypeScript"] {
        assert!(
            agents.contains(marker),
            "every standard must be inlined; missing {marker}"
        );
    }

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("no path-scoped rules mechanism"),
        "the lost lazy loading must be stated, not hidden"
    );
    assert!(text.contains("every Codex session"));
}

/// An existing `AGENTS.md` is repository content; rules-only must keep it, the
/// same way it keeps a locally edited rules file.
#[test]
fn codex_rules_only_keeps_an_existing_agents_md() {
    let repo = TempRepo::new();
    repo.write("AGENTS.md", "# House rules\n");

    let output = run_init_rules_only(&repo, "codex");
    assert!(output.status.success(), "rules-only init must succeed");
    assert_eq!(
        repo.read("AGENTS.md"),
        "# House rules\n",
        "a hand-authored AGENTS.md must never be clobbered"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("kept (locally edited): AGENTS.md"));
}

#[test]
fn pi_init_merges_only_compact_guidance_and_is_idempotent() {
    let repo = TempRepo::new();
    repo.write(
        "AGENTS.md",
        "# House rules\r\n\r\nKeep this byte-for-byte.\r\n",
    );

    let first = run_init_pi(&repo);
    assert!(first.status.success(), "Pi init must succeed");
    let first_agents = repo.read("AGENTS.md");
    assert!(first_agents.contains("<!-- lgtm-pi-guidance:start -->"));
    assert!(first_agents.contains("<!-- lgtm-entry-document: standards-v1 -->"));
    assert!(first_agents.contains("# Engineering Standards"));
    assert!(
        !first_agents.contains("# Rust"),
        "Pi must not inline rule bodies"
    );
    assert!(!repo.exists(".claude/settings.json"));
    assert!(!repo.exists(".codex/hooks.json"));
    assert!(first_agents.starts_with("# House rules\r\n\r\nKeep this byte-for-byte.\r\n"));

    let second = run_init_pi(&repo);
    assert!(second.status.success(), "Pi re-init must succeed");
    assert_eq!(repo.read("AGENTS.md"), first_agents);
}

#[test]
fn pi_init_installs_package_and_lsp_configuration_idempotently() {
    let repo = TempRepo::new();

    let first = run_init_pi(&repo);
    assert!(first.status.success(), "Pi init must succeed");
    let settings = repo.read_json(".pi/settings.json");
    assert_eq!(
        settings["packages"],
        json!([
            "npm:@narumitw/pi-lsp@0.49.4",
            "npm:@narumitw/pi-worktree@0.51.1",
            "npm:@the-forge-flow/pi-rules@0.1.0",
            "npm:pi-ask-user@0.14.0",
            "npm:pi-mcp-extension@1.5.0",
            "npm:pi-subagents@0.50.0",
            "npm:rtfd-pi@0.1.1"
        ])
    );
    let lsp = repo.read_json(".pi/pi-lsp.json");
    assert_eq!(lsp["timeout"], json!(30000));
    assert!(lsp["servers"]["rust-analyzer"].is_object());
    assert!(lsp["servers"]["typescript-language-server"].is_object());

    let settings_bytes = repo.read(".pi/settings.json");
    let lsp_bytes = repo.read(".pi/pi-lsp.json");
    let second = run_init_pi(&repo);
    assert!(second.status.success(), "Pi re-init must succeed");
    assert_eq!(repo.read(".pi/settings.json"), settings_bytes);
    assert_eq!(repo.read(".pi/pi-lsp.json"), lsp_bytes);
}

#[test]
fn pi_init_merges_existing_package_and_lsp_configuration() {
    let repo = TempRepo::new();
    repo.write(
        ".pi/settings.json",
        r#"{"theme":"dark","packages":["npm:@narumitw/pi-lsp@0.49.6","custom-package"]}"#,
    );
    repo.write(
        ".pi/pi-lsp.json",
        r#"{"timeout":12345,"servers":{"custom":{"command":["custom-lsp"],"extensions":[".custom"]},"rust-analyzer":{"command":["rustup","run","stable","rust-analyzer"],"extensions":[".rs"]}}}"#,
    );

    let output = run_init_pi(&repo);
    assert!(output.status.success(), "Pi init must succeed");
    let settings = repo.read_json(".pi/settings.json");
    assert_eq!(settings["theme"], json!("dark"));
    assert_eq!(
        settings["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .filter(|package| package.to_string().contains("@narumitw/pi-lsp"))
            .count(),
        1
    );
    let lsp = repo.read_json(".pi/pi-lsp.json");
    assert_eq!(lsp["timeout"], json!(12345));
    assert_eq!(lsp["servers"]["custom"]["command"], json!(["custom-lsp"]));
    assert_eq!(
        lsp["servers"]["rust-analyzer"]["command"],
        json!(["rustup", "run", "stable", "rust-analyzer"])
    );
    assert!(lsp["servers"]["pyright"].is_object());
}

#[test]
fn malformed_pi_settings_abort_before_any_init_write() {
    let repo = TempRepo::new();
    let malformed = r#"{"packages":{}}"#;
    repo.write(".pi/settings.json", malformed);

    let output = run_init_pi(&repo);
    assert!(!output.status.success(), "malformed Pi settings must fail");
    assert_eq!(repo.read(".pi/settings.json"), malformed);
    assert!(!repo.exists(".pi/pi-lsp.json"));
    assert!(!repo.exists(".pi/extensions/lgtm.ts"));
    assert!(!repo.exists(".lgtm/config.json"));
}

#[test]
fn malformed_pi_lsp_config_aborts_before_any_init_write() {
    let repo = TempRepo::new();
    let malformed =
        r#"{"servers":{"rust-analyzer":{"command":"rust-analyzer","extensions":[".rs"]}}}"#;
    repo.write(".pi/pi-lsp.json", malformed);

    let output = run_init_pi(&repo);
    assert!(
        !output.status.success(),
        "malformed Pi LSP config must fail"
    );
    assert_eq!(repo.read(".pi/pi-lsp.json"), malformed);
    assert!(!repo.exists(".pi/settings.json"));
    assert!(!repo.exists(".pi/extensions/lgtm.ts"));
    assert!(!repo.exists(".lgtm/config.json"));
}

#[test]
fn malformed_claude_plugin_settings_abort_before_any_init_write() {
    let repo = TempRepo::new();
    let malformed = r#"{"enabledPlugins":[]}"#;
    repo.write(".claude/settings.json", malformed);

    let output = run_init(&repo);
    assert!(
        !output.status.success(),
        "malformed Claude settings must fail"
    );
    assert_eq!(repo.read(".claude/settings.json"), malformed);
    assert!(!repo.exists(".lgtm/config.json"));
}

#[test]
fn pi_dry_run_reports_configuration_without_writing_files() {
    let repo = TempRepo::new();

    let output = run_init_pi_dry_run(&repo);
    assert!(output.status.success(), "Pi dry-run must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dry-run: no files changed"));
    assert!(stdout.contains(".pi/settings.json"));
    assert!(stdout.contains(".pi/pi-lsp.json"));
    assert!(!repo.exists("AGENTS.md"));
    assert!(!repo.exists(".lgtm/config.json"));
    assert!(!repo.exists(".claude/settings.json"));
    assert!(!repo.exists(".pi/settings.json"));
    assert!(!repo.exists(".pi/pi-lsp.json"));
}

#[test]
fn pi_init_reports_agents_override_precedence_in_normal_dry_run_and_rules_only_modes() {
    let repo = TempRepo::new();
    repo.write("AGENTS.override.md", "# higher priority guidance\n");
    let dry_run = run_init_pi_dry_run(&repo);
    assert!(
        String::from_utf8_lossy(&dry_run.stdout).contains("AGENTS.override.md takes precedence")
    );
    let rules_only = run_init_rules_only(&repo, "pi");
    assert!(rules_only.status.success());
    assert!(
        String::from_utf8_lossy(&rules_only.stdout).contains("AGENTS.override.md takes precedence")
    );
    let normal = run_init_pi(&repo);
    assert!(normal.status.success());
    assert!(
        String::from_utf8_lossy(&normal.stdout).contains("AGENTS.override.md takes precedence")
    );
}

#[test]
fn pi_rules_only_rejects_malformed_guidance_before_writing() {
    let cases = [
        "# User\n<!-- lgtm-pi-guidance:start -->\n",
        "<!-- lgtm-pi-guidance:start -->\n<!-- lgtm-pi-guidance:end -->\n<!-- lgtm-pi-guidance:start -->\n<!-- lgtm-pi-guidance:end -->\n",
    ];
    for malformed in cases {
        let repo = TempRepo::new();
        repo.write("AGENTS.md", malformed);

        let output = run_init_rules_only(&repo, "pi");
        assert!(!output.status.success(), "malformed Pi guidance must fail");
        assert_eq!(repo.read("AGENTS.md"), malformed);
    }
}

/// The Claude path is unchanged: rules land under `.claude/rules/` and no
/// `AGENTS.md` is created.
#[test]
fn claude_rules_only_still_writes_claude_rules_and_no_agents_md() {
    let repo = TempRepo::new();

    let output = run_init_rules_only(&repo, "claude");
    assert!(output.status.success(), "rules-only init must succeed");
    assert!(repo.exists(".claude/rules/standards.md"));
    assert!(repo.exists(".claude/rules/patterns/core.md"));
    assert!(
        !repo.exists("AGENTS.md"),
        "the Claude path must not create an AGENTS.md"
    );
}

/// Rules-only mode registers no hooks for either agent.
#[test]
fn rules_only_registers_no_hooks_for_codex() {
    let repo = TempRepo::new();

    let output = run_init_rules_only(&repo, "codex");
    assert!(output.status.success(), "rules-only init must succeed");
    assert!(!repo.exists(".codex/hooks.json"));
    assert!(!repo.exists(".lgtm/config.json"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("no hooks registered"));
}
