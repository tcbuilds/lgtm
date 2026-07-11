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

#[test]
fn source_first_post_defers_test_gate_but_stop_blocks_without_test() {
    let repo = setup();
    repo.write("src/app.py", "value = 1\n");
    let post = hook(&repo, "post-tool-use", Some("src/app.py"));
    assert!(post.status.success());
    assert!(
        post.stdout.is_empty(),
        "Post must not block a cumulative test rule"
    );
    let stop = hook(&repo, "stop", None);
    assert_eq!(stop.status.code(), Some(2));
    assert!(
        String::from_utf8(stop.stderr)
            .unwrap()
            .contains("new-behavior-tests-required")
    );
}

#[test]
fn source_then_test_passes_slice_completion_gate() {
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
    let stop = hook(&repo, "stop", None);
    assert!(
        stop.status.success(),
        "Stop stderr: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}
