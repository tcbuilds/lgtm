use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use super::association::{
    behavior_association_message, bug_association_message, classify_changes_with_patch,
};
use super::inline_tests::PatchIndex;
use super::{Status, evaluate};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn repo() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lgtm-diff-drift-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("repo directory");
    git(&path, &["init", "-q"]);
    git(
        &path,
        &[
            "config",
            "user.email",
            "254259785+tcbuilds@users.noreply.github.com",
        ],
    );
    git(&path, &["config", "user.name", "lgtm drift test"]);
    std::fs::write(path.join("app.py"), "value = 1\n").expect("source fixture");
    git(&path, &["add", "app.py"]);
    git(&path, &["commit", "-qm", "initial"]);
    path
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .expect("git");
    assert!(status.success(), "git command failed: {args:?}");
}

fn empty_baseline() -> BTreeSet<String> {
    BTreeSet::new()
}

#[test]
fn documented_association_limits_stay_in_sync() {
    let docs = include_str!("../../../doc/test-association-gate.md");
    assert!(docs.contains("## Known false-pass paths and enforcement limit"));
    for phrase in [
        "staged as modified or added and then deleted",
        "source path of a rename is never excluded",
        "diff header that cannot be parsed",
        "outer attribute between `#[cfg(test)]` and `mod`",
    ] {
        assert!(docs.contains(phrase), "documented limit missing: {phrase}");
    }
    assert!(docs.contains("reports `unverified` rather than blocking"));
    assert!(docs.contains("redesign of the evidence model"));

    staged_deleted_test_is_still_accepted();
    renamed_test_source_is_still_accepted();
    malformed_header_still_accepts_inline_tests();
    outer_attribute_still_hides_inline_test_evidence();
}

fn staged_deleted_test_is_still_accepted() {
    let root = repo();
    std::fs::create_dir_all(root.join("tests")).expect("test directory");
    std::fs::write(root.join("tests/value.py"), "def test_value(): pass\n").expect("test fixture");
    git(&root, &["add", "tests/value.py"]);
    git(&root, &["commit", "-qm", "test fixture"]);
    std::fs::write(root.join("app.py"), "value = 2\n").expect("source change");
    std::fs::write(
        root.join("tests/value.py"),
        "def test_value(): assert value == 2\n",
    )
    .expect("test change");
    git(&root, &["add", "tests/value.py"]);
    std::fs::remove_file(root.join("tests/value.py")).expect("test deletion");
    let results = evaluate(
        &root,
        &BTreeSet::from(["app.py".to_string(), "tests/value.py".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(results[1].status, Status::Passed);
    assert!(
        results[1]
            .evidence
            .finding_descriptions
            .iter()
            .any(|item| item == "test_paths=tests/value.py")
    );
    std::fs::remove_dir_all(root).expect("repo removable");
}

fn renamed_test_source_is_still_accepted() {
    let root = repo();
    std::fs::create_dir_all(root.join("tests")).expect("test directory");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(root.join("tests/value.py"), "def test_value(): pass\n").expect("test fixture");
    git(&root, &["add", "tests/value.py"]);
    git(&root, &["commit", "-qm", "test fixture"]);
    git(&root, &["mv", "tests/value.py", "src/value.py"]);
    let results = evaluate(
        &root,
        &BTreeSet::from(["src/value.py".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(results[1].status, Status::Passed);
    assert!(
        results[1]
            .evidence
            .finding_descriptions
            .iter()
            .any(|item| item == "test_paths=tests/value.py")
    );
    std::fs::remove_dir_all(root).expect("repo removable");
}

fn malformed_header_still_accepts_inline_tests() {
    let root = repo();
    let file = "lib value.rs";
    std::fs::write(
        root.join(file),
        "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n",
    )
    .expect("Rust source fixture");
    let patch = "diff --git a/lib value.rs b/lib value.rs\n--- a/lib value.rs\n+++ b/lib value.rs\n@@ -1 +1 @@\n-pub fn value() -> u8 { 1 }\n+pub fn value() -> u8 { 2 }\n";
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from([file.to_string()]),
        &BTreeSet::new(),
        patch,
    );
    assert!(association.missing_sources.is_empty());
    assert!(association.tests.iter().any(|item| item.file == file));
    std::fs::remove_dir_all(root).expect("repo removable");
}

fn outer_attribute_still_hides_inline_test_evidence() {
    let root = repo();
    let file = "lib.rs";
    std::fs::write(
        root.join(file),
        "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n",
    )
    .expect("Rust source fixture");
    let patch = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -7 +7 @@\n-        assert_eq!(value(), 1);\n+        assert_eq!(value(), 2);\n";
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from([file.to_string()]),
        &BTreeSet::new(),
        patch,
    );
    assert_eq!(association.missing_sources, [file]);
    assert!(association.tests.is_empty());
    for message in [
        behavior_association_message(Status::Unverified, &association),
        bug_association_message(Status::Unverified, &association),
    ] {
        let lower = message.to_ascii_lowercase();
        assert!(lower.contains("review signal"));
        assert!(lower.contains("not proof that a test is absent"));
        assert!(!lower.contains("test is missing"));
    }
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn association_messages_match_status_and_evidence() {
    let not_applicable_root = repo();
    std::fs::write(not_applicable_root.join("app.py"), "value = 2\n").expect("source change");
    let not_applicable = evaluate(
        &not_applicable_root,
        &BTreeSet::from(["app.py".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(not_applicable[0].status, Status::NotApplicable);
    assert_eq!(
        not_applicable[0].message,
        "Regression-test association is not applicable to this diff."
    );
    assert!(!not_applicable[0].message.contains("missing"));
    std::fs::remove_dir_all(not_applicable_root).expect("repo removable");

    let passed_root = repo();
    std::fs::create_dir_all(passed_root.join("tests")).expect("test directory");
    std::fs::write(passed_root.join("app.py"), "value = 2\n").expect("source change");
    std::fs::write(
        passed_root.join("tests/test_app.py"),
        "def test_value():\n    assert value == 2\n",
    )
    .expect("test change");
    let passed = evaluate(
        &passed_root,
        &BTreeSet::from(["app.py".to_string(), "tests/test_app.py".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(passed[1].status, Status::Passed);
    assert_eq!(
        passed[1].message,
        "Changed source files have plausible associated test file changes; this does not prove behavioral coverage."
    );
    std::fs::remove_dir_all(passed_root).expect("repo removable");

    let no_source_root = repo();
    std::fs::write(no_source_root.join("README.md"), "documentation\n")
        .expect("documentation change");
    let no_source = evaluate(
        &no_source_root,
        &BTreeSet::from(["README.md".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(no_source[1].status, Status::Passed);
    assert_eq!(
        no_source[1].message,
        "No changed source files require behavior-test association; coverage is not proven."
    );
    assert!(!no_source[1].message.contains("have plausible associated"));
    std::fs::remove_dir_all(no_source_root).expect("repo removable");

    let unverified_root = repo();
    std::fs::write(unverified_root.join("app.py"), "value = 2\n").expect("source change");
    let unverified = evaluate(
        &unverified_root,
        &BTreeSet::from(["app.py".to_string()]),
        Some(&empty_baseline()),
        Some("feature"),
    );
    assert_eq!(unverified[1].status, Status::Unverified);
    assert!(
        unverified[1]
            .message
            .contains("no associated test file change")
    );
    assert!(unverified[1].message.contains("app.py"));
    std::fs::remove_dir_all(unverified_root).expect("repo removable");
}

#[test]
fn patch_is_indexed_once_for_multiple_rust_files() {
    let root = repo();
    let source = "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n";
    std::fs::write(root.join("one.rs"), source).expect("first Rust source");
    std::fs::write(root.join("two.rs"), source).expect("second Rust source");
    let patch = "diff --git a/one.rs b/one.rs\n--- a/one.rs\n+++ b/one.rs\n@@ -7 +7 @@\n-        assert_eq!(value(), 1);\n+        assert_eq!(value(), 2);\ndiff --git a/two.rs b/two.rs\n--- a/two.rs\n+++ b/two.rs\n@@ -7 +7 @@\n-        assert_eq!(value(), 1);\n+        assert_eq!(value(), 2);\n";
    let files = BTreeSet::from(["one.rs".to_string(), "two.rs".to_string()]);
    PatchIndex::reset_parse_count();
    let association = classify_changes_with_patch(&root, &files, &BTreeSet::new(), patch);
    assert_eq!(PatchIndex::parse_count(), 1);
    assert_eq!(association.tests.len(), 2);
    assert!(association.missing_sources.is_empty());
    std::fs::remove_dir_all(root).expect("repo removable");
}
