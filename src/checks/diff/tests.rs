use std::sync::atomic::{AtomicU32, Ordering};

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
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("git runs")
            .success()
    );
}

#[test]
fn real_git_diff_requires_tests_for_bug_fix() {
    let root = repo();
    std::fs::write(root.join("app.py"), "value = 2\n").expect("source changed");
    let touched = BTreeSet::from(["app.py".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("bug-fix"));
    assert_eq!(results[0].status, Status::Failed);
    assert_eq!(results[1].status, Status::Failed);
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
fn untracked_source_without_tests_fails() {
    let root = repo();
    std::fs::write(root.join("new.py"), "value = 1\n").expect("untracked source");
    let touched = BTreeSet::from(["new.py".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("feature"));
    assert_eq!(results[1].status, Status::Failed);
    assert!(
        results[1]
            .locations
            .iter()
            .any(|location| location.file == "new.py")
    );
    std::fs::remove_dir_all(root).expect("repo removable");
}

#[test]
fn non_python_source_is_out_of_scope_for_mvp_test_rule() {
    let root = repo();
    std::fs::write(root.join("lib.rs"), "pub fn value() -> u8 { 1 }\n")
        .expect("Rust source fixture");
    let touched = BTreeSet::from(["lib.rs".to_string()]);
    let baseline = BTreeSet::new();
    let results = evaluate(&root, &touched, Some(&baseline), Some("feature"));

    assert_eq!(results[1].status, Status::Passed);
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
