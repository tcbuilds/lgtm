use std::sync::atomic::{AtomicU32, Ordering};

use super::association::{
    classify_changes, classify_changes_with_patch, language_pack_policy_languages,
    language_pack_scope_patterns,
};
use super::*;

static COUNTER: AtomicU32 = AtomicU32::new(0);
fn repo() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lgtm-diff-{}-{}",
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
    git(&path, &["config", "user.name", "lgtm test"]);
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
    assert!(status.success());
}
fn git_output(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("git output");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("git output is UTF-8")
}

#[test]
fn filename_markers_are_anchored_and_integration_context_is_required() {
    let root = repo();
    let files = BTreeSet::from([
        "contest.py",
        "latest_value.py",
        "attest.rs",
        "protest_handler.go",
        "test_foo.py",
        "foo_test.go",
        "foo.test.ts",
        "foo.spec.ts",
        "src/integrations/stripe.rs",
        "tests/integration/api_test.rs",
    ])
    .into_iter()
    .map(str::to_string)
    .collect();
    let association = classify_changes(&root, &files);
    for source in [
        "contest.py",
        "latest_value.py",
        "attest.rs",
        "protest_handler.go",
        "src/integrations/stripe.rs",
    ] {
        assert!(association.sources.iter().any(|item| item.file == source));
        assert!(!association.tests.iter().any(|item| item.file == source));
    }
    for test in [
        "test_foo.py",
        "foo_test.go",
        "foo.test.ts",
        "foo.spec.ts",
        "tests/integration/api_test.rs",
    ] {
        assert!(association.tests.iter().any(|item| item.file == test));
    }
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn code_configuration_filenames_are_ignored_but_helpers_are_sources() {
    let root = repo();
    let files = BTreeSet::from([
        "vite.config.ts".to_string(),
        "eslint.config.js".to_string(),
        "src/vite_helper.ts".to_string(),
    ]);
    let association = classify_changes(&root, &files);
    assert!(
        association
            .sources
            .iter()
            .any(|item| item.file == "src/vite_helper.ts")
    );
    assert!(
        !association
            .sources
            .iter()
            .any(|item| item.file == "vite.config.ts" || item.file == "eslint.config.js")
    );
    assert!(association.tests.is_empty());
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn inline_rust_test_hunks_associate_their_source_file() {
    let root = repo();
    let source = "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n";
    std::fs::write(root.join("lib.rs"), source).expect("Rust source fixture");
    let files = BTreeSet::from(["lib.rs".to_string()]);
    let production_only_patch = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-pub fn value() -> u8 { 1 }\n+pub fn value() -> u8 { 2 }\n";
    let production_only =
        classify_changes_with_patch(&root, &files, &BTreeSet::new(), production_only_patch);
    assert_eq!(production_only.missing_sources, ["lib.rs"]);
    let mixed_patch = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -1 +1 @@\n-pub fn value() -> u8 { 1 }\n+pub fn value() -> u8 { 2 }\n@@ -5,0 +6,3 @@\n+    #[test]\n+    fn value_is_two() {\n+        assert_eq!(value(), 2);\n";
    let mixed = classify_changes_with_patch(&root, &files, &BTreeSet::new(), mixed_patch);
    assert!(mixed.missing_sources.is_empty());
    assert!(mixed.tests.iter().any(|item| item.file == "lib.rs"));
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn cfg_test_module_declaration_does_not_hide_production_hunks() {
    let root = repo();
    std::fs::write(
        root.join("lib.rs"),
        "#[cfg(test)] mod tests;\n\npub fn value() -> u8 { 2 }\n",
    )
    .expect("Rust source fixture");
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from(["lib.rs".to_string()]),
        &BTreeSet::new(),
        "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -3 +3 @@\n-pub fn value() -> u8 { 1 }\n+pub fn value() -> u8 { 2 }\n",
    );
    assert_eq!(association.missing_sources, ["lib.rs"]);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn inline_cfg_test_module_body_hunk_counts_as_test_evidence() {
    let root = repo();
    std::fs::write(
        root.join("lib.rs"),
        "pub fn value() -> u8 { 1 }\n\n#[cfg(test)] mod tests {\n    #[test]\n    fn value_is_two() {\n        assert_eq!(value(), 2);\n    }\n}\n",
    )
    .expect("Rust source fixture");
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from(["lib.rs".to_string()]),
        &BTreeSet::new(),
        "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -5 +5 @@\n-        assert_eq!(value(), 1);\n+        assert_eq!(value(), 2);\n",
    );
    assert!(association.missing_sources.is_empty());
    assert!(association.tests.iter().any(|item| item.file == "lib.rs"));
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn braces_in_strings_and_comments_do_not_extend_inline_test_range() {
    let root = repo();
    std::fs::write(
        root.join("lib.rs"),
        "#[cfg(test)]\nmod tests {\n    const OPEN_IN_STRING: &str = \"{\";\n    // }\n    /* {\n     */\n    #[test]\n    fn value_is_one() {\n        assert_eq!(1, 1);\n    }\n}\npub fn value() -> u8 { 2 }\n",
    )
    .expect("Rust source fixture");
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from(["lib.rs".to_string()]),
        &BTreeSet::new(),
        "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n@@ -12 +12 @@\n-pub fn value() -> u8 { 1 }\n+pub fn value() -> u8 { 2 }\n",
    );
    assert_eq!(association.missing_sources, ["lib.rs"]);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn quoted_non_ascii_diff_header_scans_the_tracked_destination() {
    let root = repo();
    let file = "lib-é.rs";
    let source = "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n";
    std::fs::write(root.join(file), source).expect("Rust source fixture");
    git(&root, &["config", "core.quotePath", "true"]);
    git(&root, &["add", file]);
    git(&root, &["commit", "-qm", "Rust fixture"]);
    std::fs::write(root.join(file), source.replace("{ 1 }", "{ 2 }")).expect("source changed");
    let patch = git_output(&root, &["diff", "--no-ext-diff", "--unified=0", "HEAD"]);
    assert!(
        patch
            .lines()
            .any(|line| line.starts_with("diff --git \"a/"))
    );
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from([file.to_string()]),
        &BTreeSet::new(),
        &patch,
    );
    assert_eq!(association.missing_sources, [file]);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn renamed_rust_destination_scans_inline_test_hunks() {
    let root = repo();
    let source = "pub fn value() -> u8 { 1 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_one() {\n        assert_eq!(value(), 1);\n    }\n}\n";
    std::fs::write(root.join("old.rs"), source).expect("Rust source fixture");
    git(&root, &["add", "old.rs"]);
    git(&root, &["commit", "-qm", "Rust fixture"]);
    git(&root, &["mv", "old.rs", "new.rs"]);
    std::fs::write(root.join("new.rs"), source.replace("{ 1 }", "{ 2 }")).expect("source changed");
    let patch = git_output(&root, &["diff", "--no-ext-diff", "--unified=0", "HEAD"]);
    assert!(
        patch
            .lines()
            .any(|line| line == "diff --git a/old.rs b/new.rs")
    );
    let association = classify_changes_with_patch(
        &root,
        &BTreeSet::from(["new.rs".to_string()]),
        &BTreeSet::new(),
        &patch,
    );
    assert_eq!(association.missing_sources, ["new.rs"]);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn deleted_test_paths_do_not_prove_association_but_modified_tests_do() {
    let deleted_root = repo();
    std::fs::create_dir_all(deleted_root.join("tests")).expect("test directory");
    std::fs::write(
        deleted_root.join("tests/test_app.py"),
        "def test_value(): pass\n",
    )
    .expect("test fixture");
    git(&deleted_root, &["add", "tests/test_app.py"]);
    git(&deleted_root, &["commit", "-qm", "test fixture"]);
    std::fs::write(deleted_root.join("app.py"), "value = 2\n").expect("source changed");
    git(&deleted_root, &["rm", "-q", "tests/test_app.py"]);
    let deleted_results = evaluate(
        &deleted_root,
        &BTreeSet::from(["app.py".to_string()]),
        Some(&BTreeSet::new()),
        Some("feature"),
    );
    assert_eq!(deleted_results[1].status, Status::Unverified);
    std::fs::remove_dir_all(deleted_root).expect("repo removable");

    let modified_root = repo();
    std::fs::create_dir_all(modified_root.join("tests")).expect("test directory");
    std::fs::write(
        modified_root.join("tests/test_app.py"),
        "def test_value(): pass\n",
    )
    .expect("test fixture");
    git(&modified_root, &["add", "tests/test_app.py"]);
    git(&modified_root, &["commit", "-qm", "test fixture"]);
    std::fs::write(modified_root.join("app.py"), "value = 2\n").expect("source changed");
    std::fs::write(
        modified_root.join("tests/test_app.py"),
        "def test_value(): assert value == 2\n",
    )
    .expect("test changed");
    let modified_results = evaluate(
        &modified_root,
        &BTreeSet::from(["app.py".to_string(), "tests/test_app.py".to_string()]),
        Some(&BTreeSet::new()),
        Some("feature"),
    );
    assert_eq!(modified_results[1].status, Status::Passed);
    std::fs::remove_dir_all(modified_root).expect("repo removable");
}

#[test]
fn recreated_test_after_staged_deletion_restores_association_evidence() {
    let root = repo();
    std::fs::create_dir_all(root.join("tests")).expect("test directory");
    std::fs::write(
        root.join("tests/test_app.py"),
        "def test_value():\n    assert value == 1\n",
    )
    .expect("test fixture");
    git(&root, &["add", "tests/test_app.py"]);
    git(&root, &["commit", "-qm", "test fixture"]);
    std::fs::write(root.join("app.py"), "value = 2\n").expect("source changed");
    git(&root, &["rm", "-q", "tests/test_app.py"]);
    std::fs::create_dir_all(root.join("tests")).expect("test directory recreated");
    std::fs::write(
        root.join("tests/test_app.py"),
        "def test_value():\n    assert value == 2\n",
    )
    .expect("test recreated");
    let results = evaluate(
        &root,
        &BTreeSet::from(["app.py".to_string(), "tests/test_app.py".to_string()]),
        Some(&BTreeSet::new()),
        Some("feature"),
    );
    assert_eq!(results[1].status, Status::Passed);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn unsupported_language_is_outside_test_association_scope() {
    let root = repo();
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(root.join("src/app.rb"), "def value; 1; end\n").expect("unsupported source");
    let results = evaluate(
        &root,
        &BTreeSet::from(["src/app.rb".to_string()]),
        Some(&BTreeSet::new()),
        Some("bug-fix"),
    );
    assert_eq!(results[0].status, Status::NotApplicable);
    assert_eq!(results[1].status, Status::NotApplicable);
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn enforced_rule_scope_matches_every_language_pack() {
    let rules = crate::policy::load_embedded_registry().expect("policy validates");
    let expected_languages = language_pack_policy_languages();
    let expected_patterns = language_pack_scope_patterns();
    for rule_id in ["regression-test-required", "new-behavior-tests-required"] {
        let rule = rules
            .iter()
            .find(|rule| rule.id == rule_id)
            .expect("enforced rule present");
        let languages: BTreeSet<String> = rule.applies_to.languages.iter().cloned().collect();
        let patterns: BTreeSet<String> = rule.applies_to.file_patterns.iter().cloned().collect();
        assert_eq!(
            languages, expected_languages,
            "language scope for {rule_id}"
        );
        assert_eq!(patterns, expected_patterns, "file scope for {rule_id}");
    }
}

#[test]
fn supported_language_packs_associate_root_and_name_conventions() {
    let root = repo();
    for (source, test) in [
        ("src/app.py", "tests/test_app.py"),
        ("src/lib.rs", "tests/lib_test.rs"),
        ("src/App.tsx", "src/App.test.tsx"),
        ("src/app.js", "__tests__/app.spec.js"),
        ("internal/app.go", "internal/app_test.go"),
        ("src/main/java/App.java", "src/test/java/AppTest.java"),
        ("src/main/kotlin/App.kt", "src/test/kotlin/AppTest.kt"),
        ("src/App.cs", "tests/AppTests.cs"),
        ("src/app.c", "tests/app_test.c"),
        ("src/app.cpp", "tests/app_test.cpp"),
    ] {
        let files = BTreeSet::from([source.to_string(), test.to_string()]);
        let association = classify_changes(&root, &files);
        assert!(association.missing_sources.is_empty() && association.unverified.is_empty());
    }
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn workspace_metadata_keeps_mixed_monorepo_associations_in_scope() {
    let root = repo();
    std::fs::create_dir_all(root.join("backend")).expect("backend");
    std::fs::create_dir_all(root.join("frontend")).expect("frontend");
    std::fs::write(
        root.join("backend/Cargo.toml"),
        "[package]\nname='backend'\n",
    )
    .expect("Rust metadata");
    std::fs::write(root.join("frontend/package.json"), "{}\n").expect("frontend metadata");
    let files = BTreeSet::from([
        "backend/src/lib.rs".to_string(),
        "frontend/src/App.tsx".to_string(),
        "frontend/src/App.test.tsx".to_string(),
    ]);
    let association = classify_changes(&root, &files);
    assert_eq!(association.missing_sources, ["backend/src/lib.rs"]);
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn real_git_diff_reports_missing_tests_as_unverified_for_bug_fix() {
    let root = repo();
    std::fs::write(root.join("app.py"), "value = 2\n").expect("source changed");
    let touched = BTreeSet::from(["app.py".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("bug-fix"));
    assert_eq!(results[0].status, Status::Unverified);
    assert_eq!(results[1].status, Status::Unverified);
    assert_eq!(results[2].status, Status::Passed);
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn real_staged_manifest_and_auth_changes_warn() {
    let root = repo();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='x'\nversion='0.1.0'\n",
    )
    .expect("manifest");
    std::fs::write(root.join("auth.py"), "token = 'value'\n").expect("auth fixture");
    git(&root, &["add", "Cargo.toml", "auth.py"]);
    let touched = BTreeSet::from(["Cargo.toml".to_string(), "auth.py".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(results[3].status, Status::Warning);
    assert_eq!(results[4].status, Status::Warning);
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn untracked_source_without_tests_is_unverified() {
    let root = repo();
    std::fs::write(root.join("new.py"), "value = 1\n").expect("untracked source");
    let touched = BTreeSet::from(["new.py".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(results[1].status, Status::Unverified);
    assert!(
        results[1]
            .locations
            .iter()
            .any(|location| location.file == "new.py")
    );
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn supported_non_python_source_without_test_is_unverified() {
    let root = repo();
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n")
        .expect("Rust source fixture");
    let touched = BTreeSet::from(["lib.rs".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(results[1].status, Status::Unverified);
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn preexisting_unrelated_diff_is_allowed_but_new_unrecorded_diff_fails() {
    let root = repo();
    std::fs::write(root.join("old.txt"), "user work\n").expect("preexisting file");
    let baseline = changed_files(&root).expect("baseline collected");
    std::fs::write(root.join("app.py"), "value = 2\n").expect("task edit");
    let touched = BTreeSet::from(["app.py".to_string()]);
    let allowed = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(allowed[2].status, Status::Passed);
    std::fs::write(root.join("surprise.txt"), "new unrelated\n").expect("surprise file");
    let failed = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(failed[2].status, Status::Failed);
    assert!(failed[2].message.contains("surprise.txt"));
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn anti_slop_diff_review_flags_new_debug_output() {
    let root = repo();
    std::fs::write(root.join("app.py"), "value = 2\nprint(value)\n").expect("debug diff");
    let touched = BTreeSet::from(["app.py".to_string()]);
    let results = evaluate(&root, &touched, Some(&BTreeSet::new()), Some("feature"));
    assert_eq!(results[5].rule_id, "anti-slop-checklist");
    assert_eq!(results[5].status, Status::Warning);
    std::fs::remove_dir_all(root).expect("repo removable");
}
#[test]
fn boundary_error_contract_review_distinguishes_structured_failures() {
    assert!(contains_error_contract_signal(
        "+ eprintln!(\"request failed\");"
    ));
    assert!(!contains_error_contract_signal(
        "+ eprintln!(\"request failed: entity=request reason=timeout retryable=true\");"
    ));
}
#[test]
fn behavior_test_review_flags_only_trivial_assertions() {
    assert!(contains_trivial_test_signal(
        "+ fn test_smoke() { assert!(true); }"
    ));
    assert!(!contains_trivial_test_signal(
        "+ fn test_value() { assert_eq!(value(), 2); }"
    ));
}
