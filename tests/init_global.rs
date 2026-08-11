//! End-to-end coverage for home-scoped multi-harness initialization.

use std::process::{Command, Output};

mod common;
use common::TempRepo;

fn run_global(home: &TempRepo, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(args)
        .current_dir(home.path())
        .env("HOME", home.path())
        .output()
        .expect("global init should execute")
}

#[test]
fn global_init_installs_every_supported_harness_under_home() {
    let home = TempRepo::new();

    let first = run_global(&home, &["init", "-g"]);
    assert!(
        first.status.success(),
        "global init failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(home.exists(".claude/settings.json"));
    assert!(home.exists(".claude/rules/standards.md"));
    assert!(home.exists(".claude/rules/patterns/core.md"));
    assert!(home.exists(".codex/hooks.json"));
    assert!(home.exists(".codex/AGENTS.md"));
    assert!(!home.exists(".lgtm/config.json"));

    let claude = home.read_json(".claude/settings.json");
    assert!(claude["hooks"]["SessionStart"].is_array());
    assert!(claude["hooks"]["Stop"].is_array());
    let codex = home.read_json(".codex/hooks.json");
    assert!(codex["hooks"]["PermissionRequest"].is_array());
    assert!(codex["hooks"]["SubagentStop"].is_array());
    let agents = home.read(".codex/AGENTS.md");
    assert!(agents.contains("<!-- lgtm-global-guidance:start -->"));
    assert!(agents.contains("# Engineering Standards"));

    let settings_before = home.read(".claude/settings.json");
    let hooks_before = home.read(".codex/hooks.json");
    let agents_before = agents;
    let second = run_global(&home, &["init", "--global"]);
    assert!(second.status.success(), "global re-init must succeed");
    assert_eq!(settings_before, home.read(".claude/settings.json"));
    assert_eq!(hooks_before, home.read(".codex/hooks.json"));
    assert_eq!(agents_before, home.read(".codex/AGENTS.md"));
}

#[test]
fn global_init_preserves_existing_hooks_and_instruction_text() {
    let home = TempRepo::new();
    home.write(
        ".claude/settings.json",
        r#"{"permissions":{"allow":["Read"]}}"#,
    );
    home.write(
        ".codex/hooks.json",
        r#"{"description":"keep me","hooks":{"Stop":[{"hooks":[{"type":"command","command":"other"}]}]}}"#,
    );
    home.write(
        ".codex/AGENTS.md",
        "# Personal defaults\n\n- Keep this exact.\n",
    );

    let output = run_global(&home, &["init", "-g"]);
    assert!(output.status.success(), "global merge must succeed");
    assert_eq!(
        home.read_json(".claude/settings.json")["permissions"]["allow"],
        serde_json::json!(["Read"])
    );
    assert_eq!(
        home.read_json(".codex/hooks.json")["description"],
        "keep me"
    );
    let agents = home.read(".codex/AGENTS.md");
    assert!(agents.starts_with("# Personal defaults\n\n- Keep this exact.\n"));
    assert_eq!(agents.matches("lgtm-global-guidance:start").count(), 1);
}

#[test]
fn global_dry_run_reports_everything_without_writing() {
    let home = TempRepo::new();

    let output = run_global(&home, &["init", "-g", "--dry-run"]);
    assert!(output.status.success(), "global dry-run must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lgtm global init complete"));
    assert!(stdout.contains("files planned:"));
    assert!(stdout.contains(".claude/settings.json"));
    assert!(stdout.contains(".codex/hooks.json"));
    assert!(stdout.contains(".codex/AGENTS.md"));
    assert!(!home.exists(".claude"));
    assert!(!home.exists(".codex"));
}

#[test]
fn global_init_rejects_agent_selection() {
    let home = TempRepo::new();
    let output = run_global(&home, &["init", "-g", "--agent", "codex"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    assert!(!home.exists(".codex"));
}

#[test]
fn global_init_requires_home() {
    let root = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "-g"])
        .current_dir(root.path())
        .env_remove("HOME")
        .output()
        .expect("global init should execute");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("HOME is missing or empty"));
}
