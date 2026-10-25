use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

mod common;
use common::TempRepo;

fn git(repo: &TempRepo, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(repo.path())
        .args(args)
        .status()
        .unwrap();
    assert!(status.success());
}

fn setup() -> TempRepo {
    let repo = TempRepo::new();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "user.email", "test@example.invalid"]);
    git(&repo, &["config", "user.name", "Test"]);
    repo.write("README.md", "fixture\n");
    git(&repo, &["add", "README.md"]);
    git(&repo, &["commit", "-qm", "fixture"]);
    repo.write(".lgtm/config.json", r#"{"required_commands":{}}"#);
    repo
}

fn hook(repo: &TempRepo, event: &str, file: Option<&str>) -> std::process::Output {
    let mut payload = json!({"cwd":repo.path(),"session_id":"stage-test"});
    if let Some(file) = file {
        payload["tool_name"] = json!("Write");
        payload["tool_input"] = json!({"file_path":file});
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    write!(child.stdin.take().unwrap(), "{payload}").unwrap();
    child.wait_with_output().unwrap()
}

fn check(repo: &TempRepo) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["check", "--tier", "full"])
        .current_dir(repo.path())
        .output()
        .expect("explicit check completes")
}

#[test]
fn source_first_post_and_explicit_check_report_missing_test_as_unverified() {
    let repo = setup();
    repo.write("src/app.py", "value = 1\n");
    let post = hook(&repo, "post-tool-use", Some("src/app.py"));
    assert!(post.status.success());
    assert!(
        post.stdout.is_empty(),
        "Post must not block a cumulative test rule"
    );
    let check = check(&repo);
    assert!(check.status.success());
    let check_stdout = String::from_utf8_lossy(&check.stdout);
    let check_stderr = String::from_utf8_lossy(&check.stderr);
    assert!(
        check_stdout.contains("UNVERIFIED new-behavior-tests-required")
            || check_stderr.contains("UNVERIFIED new-behavior-tests-required"),
        "Check stdout: {check_stdout}\nCheck stderr: {check_stderr}"
    );
}

#[test]
fn source_then_test_does_not_fail_explicit_check() {
    let repo = setup();
    repo.write("src/app.py", "value = 1\n");
    assert!(
        hook(&repo, "post-tool-use", Some("src/app.py"))
            .stdout
            .is_empty()
    );
    repo.write(
        "tests/test_app.py",
        "def test_value():\n    assert 1 == 1\n",
    );
    assert!(
        hook(&repo, "post-tool-use", Some("tests/test_app.py"))
            .stdout
            .is_empty()
    );
    let check = check(&repo);
    assert!(
        check.status.success(),
        "Check stderr: {}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn missing_rust_test_reports_unverified_without_blocking_with_association_evidence() {
    let repo = setup();
    repo.write("backend/Cargo.toml", "[package]\nname='backend'\n");
    repo.write("backend/src/lib.rs", "pub fn value() -> u8 { 1 }\n");
    let post = hook(&repo, "post-tool-use", Some("backend/src/lib.rs"));
    assert!(post.status.success());
    let post_stderr = String::from_utf8_lossy(&post.stderr);
    assert!(post_stderr.contains("new-behavior-tests-required"));
    let evidence = repo
        .read(".lgtm/evidence/current-task.results.jsonl")
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|record| record["result"]["rule_id"] == "new-behavior-tests-required")
        .expect("association evidence record");
    let descriptions = evidence["result"]["evidence"]["finding_descriptions"]
        .as_array()
        .expect("association evidence descriptions");
    let message = evidence["result"]["message"]
        .as_str()
        .expect("association result message");
    let message_lower = message.to_ascii_lowercase();
    assert!(
        message_lower.contains("review signal"),
        "message: {message}"
    );
    assert!(
        message_lower.contains("not proof that a test is absent"),
        "message: {message}"
    );
    assert_eq!(
        descriptions,
        json!([
            "source_paths=backend/src/lib.rs",
            "test_paths=",
            "missing_test_source_paths=backend/src/lib.rs",
            "test_file_changed=false",
            "coverage_proven=false",
            "detection_basis=workspace-metadata:backend;language-pack:rust;source-extension",
        ])
        .as_array()
        .expect("golden association evidence")
    );
    let check = check(&repo);
    assert!(check.status.success());
    let check_stdout = String::from_utf8_lossy(&check.stdout);
    let check_stderr = String::from_utf8_lossy(&check.stderr);
    assert!(
        check_stdout.contains("UNVERIFIED new-behavior-tests-required")
            || check_stderr.contains("UNVERIFIED new-behavior-tests-required"),
        "Check stdout: {check_stdout}\nCheck stderr: {check_stderr}"
    );
}

#[test]
fn unsupported_language_does_not_trigger_supported_source_association() {
    let repo = setup();
    repo.write("src/app.rb", "def value; 1; end\n");
    let post = hook(&repo, "post-tool-use", Some("src/app.rb"));
    assert!(post.status.success());
    assert!(!String::from_utf8_lossy(&post.stderr).contains("new-behavior-tests-required"));
}

#[test]
fn mixed_source_and_asset_changes_keep_association_output_actionable() {
    let repo = setup();
    repo.write("src/app.py", "value = 1\n");
    for index in 0..20 {
        repo.write(&format!("screenshots/cycle-{index}.png"), "image fixture\n");
    }
    let post = hook(&repo, "post-tool-use", Some("src/app.py"));
    assert!(post.status.success());

    repo.write(
        ".lgtm/evidence/current-task.intent.json",
        r#"{"session_id":null,"intent":"bug-fix"}"#,
    );
    let check = check(&repo);
    assert!(check.status.success());

    let messages: std::collections::BTreeMap<_, _> = repo
        .read(".lgtm/evidence/current-task.results.jsonl")
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|record| {
            let rule_id = record["result"]["rule_id"].as_str()?.to_string();
            let message = record["result"]["message"].as_str()?.to_string();
            Some((rule_id, message))
        })
        .collect();
    let behavior_message = messages
        .get("new-behavior-tests-required")
        .expect("behavior association result message");
    assert!(
        behavior_message.contains("src/app.py"),
        "message: {behavior_message}"
    );
    assert!(
        !behavior_message.contains("screenshots/"),
        "message: {behavior_message}"
    );
    assert!(
        !behavior_message.contains("Unclassifiable changes:"),
        "message: {behavior_message}"
    );
    let check_output = format!(
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(
        check_output.contains("UNVERIFIED regression-test-required"),
        "Check output: {check_output}"
    );
    assert!(
        check_output.contains("src/app.py") && !check_output.contains("screenshots/"),
        "Check output: {check_output}"
    );
}

#[test]
fn documentation_and_configuration_changes_do_not_require_tests() {
    let repo = setup();
    repo.write("README.md", "documentation\n");
    repo.write("settings.json", "{}\n");
    assert!(
        hook(&repo, "post-tool-use", Some("README.md"))
            .status
            .success()
    );
    assert!(
        hook(&repo, "post-tool-use", Some("settings.json"))
            .status
            .success()
    );
    assert!(check(&repo).status.success());
}
