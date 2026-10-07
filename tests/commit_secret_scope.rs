//! End-to-end coverage for direct staged-index commit assessment.

use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempRepo {
    path: std::path::PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lgtm-commit-scope-{}-{suffix}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temporary repository directory");
        run_git(&path, &["init", "-q"]);
        run_git(&path, &["config", "user.email", "test@example.com"]);
        run_git(&path, &["config", "user.name", "lgtm test"]);
        Self { path }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent");
        }
        std::fs::write(path, contents).expect("fixture file");
    }

    fn commit_initial_file(&self) {
        self.write("a.txt", "base\n");
        run_git(&self.path, &["add", "a.txt"]);
        run_git(&self.path, &["commit", "-qm", "initial"]);
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run_git(repo: &std::path::Path, arguments: &[&str]) -> Output {
    let output = Command::new("git")
        .current_dir(repo)
        .args(arguments)
        .output()
        .expect("git starts");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn gitleaks_available() -> bool {
    Command::new("gitleaks")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn aws_key() -> String {
    ["AKIA", "Z3ROBME2X7HGKLMN"].concat()
}

fn run_pre_tool_use(repo: &TempRepo, command: &str) -> Output {
    let payload = json!({
        "cwd": repo.path,
        "session_id": "commit-scope-test",
        "tool_name": "Bash",
        "tool_input": {"command": command}
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command
        .current_dir(std::env::temp_dir())
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output_with_input(payload.to_string())
}

trait OutputWithInput {
    fn output_with_input(self, input: String) -> Output;
}

impl OutputWithInput for Command {
    fn output_with_input(mut self, input: String) -> Output {
        let mut child = self.spawn().expect("PreToolUse starts");
        std::io::Write::write_all(
            &mut child.stdin.take().expect("hook stdin available"),
            input.as_bytes(),
        )
        .expect("hook payload writes");
        child.wait_with_output().expect("PreToolUse exits")
    }
}

fn denied(output: &Output) -> bool {
    if output.stdout.is_empty() {
        return false;
    }
    let body: Value = serde_json::from_slice(&output.stdout).expect("hook emits JSON on denial");
    body["hookSpecificOutput"]["permissionDecision"] == "deny"
}

fn skip_without_gitleaks() -> bool {
    if gitleaks_available() {
        return false;
    }
    eprintln!("skipping staged commit test: gitleaks is not installed");
    true
}

#[test]
fn staged_secret_is_denied_even_when_worktree_is_clean() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.commit_initial_file();
    repo.write("a.txt", &format!("key={}\n", aws_key()));
    run_git(&repo.path, &["add", "a.txt"]);
    repo.write("a.txt", "clean working tree\n");

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(denied(&output));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&aws_key()));
}

#[test]
fn unstaged_secret_does_not_block_a_clean_staged_commit() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.commit_initial_file();
    repo.write("a.txt", "safe staged content\n");
    run_git(&repo.path, &["add", "a.txt"]);
    repo.write("a.txt", &format!("key={}\n", aws_key()));

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(
        !denied(&output),
        "unstaged content blocked commit: {output:?}"
    );
}

#[test]
fn missing_worktree_file_uses_the_staged_index_bytes() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.commit_initial_file();
    repo.write("a.txt", &format!("key={}\n", aws_key()));
    run_git(&repo.path, &["add", "a.txt"]);
    std::fs::remove_file(repo.path.join("a.txt")).expect("working-tree file removed");

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(denied(&output));
}

#[test]
fn ignored_untracked_secret_does_not_block_the_staged_scope() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.write(".gitignore", "runtime.txt\n");
    repo.commit_initial_file();
    run_git(&repo.path, &["add", ".gitignore"]);
    repo.write("a.txt", "safe staged content\n");
    run_git(&repo.path, &["add", "a.txt"]);
    repo.write("runtime.txt", &format!("key={}\n", aws_key()));

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(!denied(&output));
}

#[test]
fn root_config_is_used_when_hook_process_runs_outside_repository() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.commit_initial_file();
    repo.write(".gitleaks.toml", "[allowlist]\npaths = ['''a\\.txt$''']\n");
    repo.write("a.txt", &format!("key={}\n", aws_key()));
    run_git(&repo.path, &["add", "a.txt"]);

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(!denied(&output), "root config was not applied: {output:?}");
}

#[test]
fn staged_deletion_does_not_scan_the_deleted_worktree_content() {
    if skip_without_gitleaks() {
        return;
    }
    let repo = TempRepo::new();
    repo.commit_initial_file();
    repo.write("secret.txt", &format!("key={}\n", aws_key()));
    run_git(&repo.path, &["add", "secret.txt"]);
    run_git(&repo.path, &["commit", "-qm", "fixture"]);
    run_git(&repo.path, &["rm", "-q", "secret.txt"]);

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(!denied(&output), "staged deletion was blocked: {output:?}");
}

#[test]
fn empty_or_unborn_index_can_be_assessed() {
    if skip_without_gitleaks() {
        return;
    }
    let path = std::env::temp_dir().join(format!(
        "lgtm-empty-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).expect("empty repository directory");
    run_git(&path, &["init", "-q"]);
    let repo = TempRepo { path };

    let output = run_pre_tool_use(&repo, "git commit -m message");

    assert!(!denied(&output), "empty index was blocked: {output:?}");
}
