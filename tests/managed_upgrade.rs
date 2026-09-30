//! Upgrade all installed managed output while preserving owner policy and opt-outs.

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn init(repo: &TempRepo, home: &Path, agent: &str, rules_only: bool) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.args(["init", "--agent", agent]);
    if rules_only {
        command.arg("--rules-only");
    } else {
        command.arg("--accept-guesses");
    }
    let output = command
        .env("HOME", home)
        .current_dir(repo.path())
        .output()
        .expect("init runs");
    assert!(output.status.success(), "{output:?}");
}

fn refresh(home: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("refresh")
        .env("HOME", home)
        .output()
        .expect("refresh runs");
    assert!(output.status.success(), "{output:?}");
}

fn corrupt_matcher_preserving_owner_settings(path: &Path) -> String {
    let mut settings: Value =
        serde_json::from_str(&fs::read_to_string(path).expect("hooks")).expect("settings JSON");
    settings["ownerSetting"] = json!({"keep": true});
    settings["hooks"]["PreToolUse"][0]["matcher"] = json!("WrongMatcher");
    settings["hooks"]["PreToolUse"]
        .as_array_mut()
        .expect("entries")
        .push(json!({
            "matcher": "OwnerTool", "hooks": [{"type":"command", "command":"owner-hook"}]
        }));
    settings["hooks"]
        .as_object_mut()
        .expect("hooks map")
        .remove("Stop");
    let serialized = serde_json::to_string_pretty(&settings).expect("serialize settings");
    fs::write(path, &serialized).expect("settings changes");
    serialized
}

fn assert_hooks_refreshed_without_restoring_disabled_event(path: &Path) {
    let settings: Value =
        serde_json::from_str(&fs::read_to_string(path).expect("hooks")).expect("JSON");
    assert_ne!(
        settings["hooks"]["PreToolUse"][0]["matcher"],
        "WrongMatcher"
    );
    assert_eq!(settings["ownerSetting"], json!({"keep":true}));
    assert_eq!(
        settings["hooks"]["PreToolUse"][1]["hooks"][0]["command"],
        "owner-hook"
    );
    assert!(settings["hooks"].get("Stop").is_none());
}

#[test]
fn project_refresh_updates_rules_and_hooks_without_changing_policy_or_owner_content() {
    for agent in ["claude", "codex", "pi"] {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        init(&repo, home.path(), agent, false);
        let policy = repo.read(".lgtm/config.json");
        let execpolicy = repo.read(".lgtm/execpolicy.json");
        let hook_path = match agent {
            "claude" => Some(repo.path().join(".claude/settings.json")),
            "codex" => Some(repo.path().join(".codex/hooks.json")),
            _ => None,
        };
        if let Some(path) = &hook_path {
            corrupt_matcher_preserving_owner_settings(path);
        }
        let rule = repo.path().join(".claude/rules/standards.md");
        let expected_rule = fs::read_to_string(&rule).ok();
        if expected_rule.is_some() {
            fs::write(&rule, "owner-edited shipped rule").expect("modify shipped rule");
            repo.write(".claude/rules/custom-owner.md", "owner rule");
            fs::remove_file(repo.path().join(".claude/rules/rust.md")).expect("disable one rule");
        }
        if agent == "pi" {
            let guidance = repo
                .read("AGENTS.md")
                .replace("# Engineering Standards", "# Old Managed Standards");
            repo.write(
                "AGENTS.md",
                &format!("Owner prefix\n{guidance}\nOwner suffix\n"),
            );
            fs::remove_file(repo.path().join(".pi/extensions/lgtm.ts")).expect("disable Pi hook");
        }
        refresh(home.path());
        assert_eq!(repo.read(".lgtm/config.json"), policy, "{agent}");
        assert_eq!(repo.read(".lgtm/execpolicy.json"), execpolicy, "{agent}");
        if let Some(path) = &hook_path {
            assert_hooks_refreshed_without_restoring_disabled_event(path);
        }
        if let Some(expected) = expected_rule {
            assert_eq!(fs::read_to_string(&rule).expect("refreshed rule"), expected);
            assert_eq!(repo.read(".claude/rules/custom-owner.md"), "owner rule");
            assert!(!repo.exists(".claude/rules/rust.md"));
            let backups: Vec<_> = fs::read_dir(rule.parent().expect("parent"))
                .expect("rule directory")
                .map(|entry| entry.expect("entry").path())
                .filter(|path| {
                    path.file_name()
                        .expect("name")
                        .to_string_lossy()
                        .starts_with("standards.md.")
                })
                .collect();
            assert_eq!(backups.len(), 1);
            assert_eq!(
                fs::read_to_string(&backups[0]).expect("backup"),
                "owner-edited shipped rule"
            );
        }
        if agent == "pi" {
            assert!(!repo.exists(".pi/extensions/lgtm.ts"));
            let guidance = repo.read("AGENTS.md");
            assert!(guidance.starts_with("Owner prefix\n") && guidance.ends_with("Owner suffix\n"));
            assert!(!guidance.contains("# Old Managed Standards"));
        }
        refresh(home.path());
    }
}

#[test]
fn global_refresh_updates_rules_and_both_hook_formats_without_reenabling_pi() {
    let home = TempRepo::new();
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--global"])
        .env("HOME", home.path())
        .output()
        .expect("global init");
    assert!(output.status.success(), "{output:?}");
    let claude = home.path().join(".claude/settings.json");
    let codex = home.path().join(".codex/hooks.json");
    corrupt_matcher_preserving_owner_settings(&claude);
    corrupt_matcher_preserving_owner_settings(&codex);
    let rule = home.path().join(".claude/rules/standards.md");
    let desired = fs::read_to_string(&rule).expect("original rule");
    fs::write(&rule, "old shipped rule").expect("old rule");
    fs::remove_file(home.path().join(".pi/agent/extensions/lgtm.ts")).expect("disable global Pi");
    refresh(home.path());
    assert_hooks_refreshed_without_restoring_disabled_event(&claude);
    assert_hooks_refreshed_without_restoring_disabled_event(&codex);
    assert_eq!(fs::read_to_string(rule).expect("new rule"), desired);
    assert!(!home.exists(".pi/agent/extensions/lgtm.ts"));
    assert!(!home.exists(".lgtm/config.json"));
}

#[test]
fn codex_refresh_updates_registered_generated_guidance_and_execpolicy_but_preserves_edits() {
    use sha2::{Digest, Sha256};

    let home = TempRepo::new();
    let repo = TempRepo::new();
    init(&repo, home.path(), "codex", false);
    let desired_guidance = repo.read("AGENTS.md");
    let desired_rules = repo.read(".codex/rules/lgtm.rules");
    let old_guidance = "previous generated Codex guidance\n";
    repo.write("AGENTS.md", old_guidance);
    repo.write(
        ".codex/rules/lgtm.rules",
        "# Generated by lgtm from .lgtm/execpolicy.json\noutdated generated output\n",
    );
    let registry = home.path().join(".local/state/lgtm/pi-installations");
    let record = fs::read_dir(registry)
        .expect("registry")
        .next()
        .expect("entry")
        .expect("record")
        .path();
    let mut registration: Value =
        serde_json::from_str(&fs::read_to_string(&record).expect("record")).expect("JSON");
    registration["managed"]["codex_digest"] =
        json!(format!("{:x}", Sha256::digest(old_guidance.as_bytes())));
    fs::write(
        record,
        serde_json::to_vec(&registration).expect("registration JSON"),
    )
    .expect("old version registration");
    refresh(home.path());
    assert_eq!(repo.read("AGENTS.md"), desired_guidance);
    assert_eq!(repo.read(".codex/rules/lgtm.rules"), desired_rules);
    repo.write("AGENTS.md", "owner-edited guidance");
    repo.write(".codex/rules/lgtm.rules", "owner execpolicy rules");
    refresh(home.path());
    assert_eq!(repo.read("AGENTS.md"), "owner-edited guidance");
    assert_eq!(
        repo.read(".codex/rules/lgtm.rules"),
        "owner execpolicy rules"
    );
}

#[test]
fn adapters_sharing_guidance_do_not_overwrite_each_others_registration() {
    let home = TempRepo::new();
    let repo = TempRepo::new();
    init(&repo, home.path(), "pi", true);
    init(&repo, home.path(), "codex", true);
    repo.write(".claude/rules/standards.md", "old shared rule");
    assert_eq!(
        fs::read_dir(home.path().join(".local/state/lgtm/pi-installations"))
            .expect("registry")
            .count(),
        2
    );
    refresh(home.path());
    assert_ne!(repo.read(".claude/rules/standards.md"), "old shared rule");
}

#[test]
fn rules_only_refresh_never_installs_hooks_or_repo_policy() {
    for agent in ["claude", "codex", "pi"] {
        let home = TempRepo::new();
        let repo = TempRepo::new();
        init(&repo, home.path(), agent, true);
        if agent != "codex" {
            repo.write(".claude/rules/standards.md", "old rule");
        }
        refresh(home.path());
        assert!(!repo.exists(".lgtm/config.json"));
        assert!(!repo.exists(".claude/settings.json"));
        assert!(!repo.exists(".codex/hooks.json"));
        assert!(!repo.exists(".pi/extensions/lgtm.ts"));
        if agent != "codex" {
            assert_ne!(repo.read(".claude/rules/standards.md"), "old rule");
        }
    }
}
