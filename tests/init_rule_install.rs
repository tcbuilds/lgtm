//! End-to-end coverage for the complete plain-init rules installation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;
use common::TempRepo;

fn run_init(repo: &TempRepo, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(args)
        .current_dir(repo.path())
        .output()
        .expect("lgtm init should execute")
}

fn rule_files(repo: &TempRepo) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    collect_files(
        &repo.path().join(".claude/rules"),
        Path::new(""),
        &mut files,
    );
    files
}

fn collect_files(root: &Path, relative: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(directory).expect("rules directory should be readable") {
        let entry = entry.expect("rules entry should be readable");
        let path = relative.join(entry.file_name());
        if entry
            .file_type()
            .expect("rules entry type should be readable")
            .is_dir()
        {
            collect_files(root, &path, files);
        } else {
            files.insert(
                path,
                std::fs::read(root.join(relative).join(entry.file_name()))
                    .expect("rule file should be readable"),
            );
        }
    }
}

#[test]
fn plain_init_installs_complete_rules_and_hooks_idempotently() {
    let plain = TempRepo::new();
    plain.write("requirements.txt", "pytest\n");

    let first = run_init(&plain, &["init", "--accept-guesses"]);
    assert!(first.status.success(), "plain init must succeed");
    assert!(
        plain.exists(".claude/settings.json"),
        "hooks must be registered"
    );
    let first_rules = rule_files(&plain);
    assert!(first_rules.contains_key(Path::new("standards.md")));
    assert!(first_rules.contains_key(Path::new("patterns/core.md")));
    assert!(
        first_rules.len() > 2,
        "all rule and pattern files must land"
    );
    for (path, contents) in &first_rules {
        let contents = std::str::from_utf8(contents).expect("rule template must be UTF-8");
        let frontmatter = contents
            .strip_prefix("---\n")
            .and_then(|contents| contents.split_once("\n---\n"))
            .map(|(frontmatter, _)| frontmatter)
            .expect("installed rule must have frontmatter");
        assert!(
            frontmatter
                .lines()
                .any(|line| line.starts_with("description: ")),
            "{} must have a loader-compatible description",
            path.display()
        );
    }
    let first_text = String::from_utf8_lossy(&first.stdout);
    assert!(first_text.contains("rule files: written"));
    assert!(first_text.contains(".claude/rules/standards.md"));
    assert!(first_text.contains(".claude/rules/patterns/core.md"));

    let second = run_init(&plain, &["init", "--accept-guesses"]);
    assert!(
        second.status.success(),
        "re-running plain init must succeed"
    );
    assert_eq!(
        first_rules,
        rule_files(&plain),
        "plain init must be byte-idempotent"
    );

    let rules_only = TempRepo::new();
    let rules_only_output = run_init(&rules_only, &["init", "--rules-only"]);
    assert!(
        rules_only_output.status.success(),
        "rules-only init must succeed"
    );
    assert!(!rules_only.exists(".claude/settings.json"));
    assert!(
        rule_files(&rules_only)
            .keys()
            .all(|path| first_rules.contains_key(path))
    );
}

#[test]
fn plain_init_dry_run_reports_rules_without_writing() {
    let repo = TempRepo::new();
    let output = run_init(&repo, &["init", "--dry-run"]);
    assert!(output.status.success(), "dry-run init must succeed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("rule files: planned"));
    assert!(!repo.exists(".claude/rules"));
    assert!(!repo.exists(".claude/settings.json"));
}

#[test]
fn plain_init_dry_run_classifies_existing_rule_files() {
    let repo = TempRepo::new();
    let fresh = run_init(&repo, &["init", "--dry-run"]);
    let fresh_text = String::from_utf8_lossy(&fresh.stdout);
    assert!(fresh.status.success(), "fresh dry-run must succeed");
    assert!(fresh_text.contains("rule files: planned 30"));

    let installed = run_init(&repo, &["init", "--accept-guesses"]);
    assert!(installed.status.success(), "initial init must succeed");

    let unchanged = run_init(&repo, &["init", "--dry-run"]);
    let unchanged_text = String::from_utf8_lossy(&unchanged.stdout);
    assert!(unchanged.status.success(), "unchanged dry-run must succeed");
    assert!(unchanged_text.contains("rule files: planned 0"));
    assert!(unchanged_text.contains("rule files unchanged: 30"));
    assert!(!unchanged_text.contains("rule kept (locally edited):"));

    repo.write(".claude/rules/patterns/core.md", "locally edited\n");
    let edited = run_init(&repo, &["init", "--dry-run"]);
    let edited_text = String::from_utf8_lossy(&edited.stdout);
    assert!(edited.status.success(), "edited dry-run must succeed");
    assert!(edited_text.contains("rule files: planned 0"));
    assert!(edited_text.contains("rule files unchanged: 29"));
    assert!(edited_text.contains("rule kept (locally edited): .claude/rules/patterns/core.md"));
}

/// A symlinked rules directory must be rejected before init creates any file.
#[cfg(unix)]
#[test]
fn plain_init_rejects_a_symlinked_rules_directory_without_external_writes() {
    let repo = TempRepo::new();
    let outside = TempRepo::new();
    std::fs::create_dir_all(repo.path().join(".claude")).expect("Claude directory");
    std::os::unix::fs::symlink(outside.path(), repo.path().join(".claude/rules"))
        .expect("rules symlink");

    let output = run_init(&repo, &["init"]);
    assert!(!output.status.success(), "symlinked rules must fail init");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("symlink"),
        "failure must explain the symlink refusal"
    );
    assert!(!repo.exists(".lgtm/config.json"));
    assert!(!repo.exists(".claude/settings.json"));
    assert!(!outside.exists("standards.md"));
}

/// An unwritable rule destination must fail preflight before config or hooks commit.
#[test]
fn plain_init_rejects_a_non_file_rule_destination_without_partial_init() {
    let repo = TempRepo::new();
    std::fs::create_dir_all(repo.path().join(".claude/rules/standards.md"))
        .expect("rule destination directory");

    let output = run_init(&repo, &["init"]);
    assert!(
        !output.status.success(),
        "invalid rule destination must fail init"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not writable"),
        "failure must explain the destination type"
    );
    assert!(!repo.exists(".lgtm/config.json"));
    assert!(!repo.exists(".claude/settings.json"));
}
