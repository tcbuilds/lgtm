//! Scope and upgrade coverage for the state-and-concurrency guidance.

#[path = "support/codex_v0_15_1.rs"]
mod codex_v0_15_1;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use codex_v0_15_1::{
    ADDED_SINCE_V0_15_1, CHANGED_SINCE_V0_15_1, V0_15_1_CODEX_DIGEST, current_rule,
    v0_15_1_codex_document,
};
use common::TempRepo;
use lgtm::path_injection::{PathInjectionRequest, select_rule_bodies};
use serde_json::Value;
use sha2::{Digest, Sha256};

const STATE_SOURCE: &str = "templates/claude-rules/rules/state-and-concurrency.md";

// Keep positive and negative path hints together so scope drift is visible.
#[test]
fn state_guidance_is_injected_only_for_state_and_concurrency_path_hints() {
    let cases = [
        ("src/workers/billing.py", true),
        ("app/jobs/nightly_report.py", true),
        ("services/orders/order_state.py", true),
        ("src/main/java/shop/OrderStatusService.java", true),
        ("internal/lease/fencing.go", true),
        ("src/webhooks/stripe.ts", true),
        ("pkg/queue/consumer.go", true),
        ("src/payment_retry.rs", true),
        ("tests/test_order_state.py", true),
        ("src/coordination/distributed_lock.py", true),
        ("src/DistributedLock.kt", true),
        ("src/events/handler.ts", true),
        ("src/poller.py", true),
        ("lock.py", true),
        ("src/locks.rs", true),
        ("src/lock_manager.py", true),
        ("src/sync/mutex.rs", true),
        ("internal/lease.go", true),
        ("app/lease_manager.py", true),
        ("cluster/leader_election.go", true),
        ("src/locks/registry.py", true),
        ("internal/lease/store.go", true),
        ("native/lock-free/queue.cpp", true),
        ("src/service.py", false),
        ("src/components/Button.tsx", false),
        ("src/app/models/user.py", false),
        ("src/blockchain/block.rs", false),
        ("src/blocks/Hero.tsx", false),
        ("tools/release.py", false),
        ("src/ReleaseNotes.ts", false),
        ("src/releases/notes.py", false),
        ("src/unlock_button.tsx", false),
        ("bios/x.c", false),
        ("src/leaderboard.tsx", false),
        ("app/models/order.rb", false),
        ("src/clock.py", false),
        ("src/async_utils.py", false),
        ("docs/state.md", false),
        ("README.md", false),
    ];
    for (path, expected) in cases {
        let result = select_rule_bodies(&PathInjectionRequest::new(vec![path.into()], None));
        assert!(
            result.diagnostics.is_empty(),
            "{path}: {:?}",
            result.diagnostics
        );
        let selected = result
            .bodies
            .iter()
            .find(|document| document.source_path == STATE_SOURCE);
        assert_eq!(selected.is_some(), expected, "state guidance for {path}");
        if let Some(selected) = selected {
            assert!(!selected.body.contains("\npaths:\n"));
            assert!(selected.body.contains("Apply only to code that owns state"));
        }
    }
}

#[test]
fn v0_15_1_codex_document_is_recognized_upgraded_and_then_unchanged() {
    let repo = TempRepo::new();
    lgtm::init::install_agents(repo.path()).expect("current Codex install");
    let current = repo.read("AGENTS.md");
    let previous = v0_15_1_codex_document(&current);
    assert_eq!(
        format!("{:x}", Sha256::digest(previous.as_bytes())),
        V0_15_1_CODEX_DIGEST,
        "reconstruction must match the released v0.15.1 document"
    );

    repo.write("AGENTS.md", &previous);
    let upgrade = lgtm::init::install_agents(repo.path()).expect("upgrade v0.15.1 document");
    assert_eq!(upgrade.updated, ["AGENTS.md"]);
    assert_eq!(repo.read("AGENTS.md"), current);
    let repeat = lgtm::init::install_agents(repo.path()).expect("repeat Codex install");
    assert_eq!(repeat.unchanged, ["AGENTS.md"]);

    repo.write("AGENTS.md", &format!("{previous}\n# House rule\n"));
    let edited = lgtm::init::install_agents(repo.path()).expect("edited Codex document");
    assert_eq!(edited.kept, ["AGENTS.md"]);
    assert!(repo.read("AGENTS.md").ends_with("# House rule\n"));
}

#[test]
fn refresh_upgrades_v0_15_1_rules_installs_state_guidance_and_backs_up_edits() {
    let home = TempRepo::new();
    let repo = TempRepo::new();
    init_rules_only(&repo, home.path(), "claude");
    rewind_registered_guidance(home.path(), None);
    let added = format!(".claude/rules/{ADDED_SINCE_V0_15_1}");
    std::fs::remove_file(repo.path().join(&added)).expect("remove post-v0.15.1 rule");
    for (name, legacy) in CHANGED_SINCE_V0_15_1 {
        repo.write(&format!(".claude/rules/{name}"), legacy);
    }
    let edited = ".claude/rules/testing.md";
    let local = "# Local testing rules\n";
    repo.write(edited, local);

    refresh(home.path());

    assert_eq!(repo.read(&added), current_rule(ADDED_SINCE_V0_15_1));
    for (name, legacy) in CHANGED_SINCE_V0_15_1 {
        assert_eq!(
            repo.read(&format!(".claude/rules/{name}")),
            current_rule(name)
        );
        if name != "testing.md" {
            assert_eq!(repo.read(&backup_path(name, legacy)), legacy, "{name}");
        }
    }
    assert_eq!(repo.read(&backup_path("testing.md", local)), local);

    std::fs::remove_file(repo.path().join(&added)).expect("owner removes new rule");
    refresh(home.path());
    assert!(!repo.exists(&added), "a removed rule must stay removed");
}

#[test]
fn refresh_upgrades_an_unchanged_v0_15_1_codex_document() {
    let home = TempRepo::new();
    let repo = TempRepo::new();
    init_rules_only(&repo, home.path(), "codex");
    let current = repo.read("AGENTS.md");
    rewind_registered_guidance(home.path(), Some(V0_15_1_CODEX_DIGEST));
    repo.write("AGENTS.md", &v0_15_1_codex_document(&current));

    refresh(home.path());

    assert_eq!(repo.read("AGENTS.md"), current);
}

fn init_rules_only(repo: &TempRepo, home: &Path, agent: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--agent", agent, "--rules-only"])
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

/// Make the registered installation look like one recorded by v0.15.1.
fn rewind_registered_guidance(home: &Path, codex_digest: Option<&str>) {
    let record = single_installation_record(home);
    let mut installation: Value =
        serde_json::from_str(&std::fs::read_to_string(&record).expect("read installation"))
            .expect("installation JSON");
    let managed = installation["managed"]
        .as_object_mut()
        .expect("managed installation");
    let guidance = managed["guidance"].as_array_mut().expect("guidance paths");
    guidance.retain(|path| {
        !path
            .as_str()
            .is_some_and(|path| path.ends_with(ADDED_SINCE_V0_15_1))
    });
    if let Some(digest) = codex_digest {
        managed.insert("codex_digest".to_string(), Value::from(digest));
    }
    std::fs::write(
        &record,
        serde_json::to_vec(&installation).expect("serialize installation"),
    )
    .expect("write installation");
}

fn single_installation_record(home: &Path) -> PathBuf {
    let directory = home.join(".local/state/lgtm/pi-installations");
    let records: Vec<PathBuf> = std::fs::read_dir(&directory)
        .expect("installation registry")
        .map(|entry| entry.expect("registry entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    assert_eq!(records.len(), 1, "{records:?}");
    records.into_iter().next().expect("one installation")
}

fn backup_path(name: &str, contents: &str) -> String {
    format!(
        ".claude/rules/{name}.{:x}.bak",
        Sha256::digest(contents.as_bytes())
    )
}
