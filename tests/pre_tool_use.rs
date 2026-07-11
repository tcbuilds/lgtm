use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

fn run(root: &std::path::Path, tool: &str, file: &str) -> serde_json::Value {
    let payload = json!({"cwd": root, "session_id": "test-session",
        "tool_name": tool, "tool_input": {"file_path": file}});
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("starts");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("exits");
    if output.stdout.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&output.stdout).expect("JSON response")
    }
}

fn temp_repo(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-pre-{}-{name}", std::process::id()));
    std::fs::create_dir_all(root.join(".lgtm")).expect("dirs");
    std::fs::write(root.join(".lgtm/config.json"), "{}").expect("config");
    root
}

#[test]
fn allows_new_file_and_captures_session_baseline() {
    let root = temp_repo("baseline");
    assert_eq!(run(&root, "Write", "src/new.py"), json!(null));
    assert!(
        root.join(".lgtm/evidence/current-task.baseline.json")
            .is_file()
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn first_session_diff_baseline_is_not_overwritten() {
    let root = temp_repo("first-diff");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"])
            .status()
            .expect("git init")
            .success()
    );
    std::fs::write(root.join("tracked.py"), "value = 1\n").expect("tracked file");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "tracked.py"])
            .status()
            .expect("git add")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args([
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-qm",
                "initial"
            ])
            .status()
            .expect("git commit")
            .success()
    );
    std::fs::write(root.join("before.txt"), "user work\n").expect("preexisting diff");
    assert_eq!(run(&root, "Write", "src/one.py"), json!(null));
    std::fs::write(root.join("after.txt"), "new work\n").expect("later diff");
    assert_eq!(run(&root, "Write", "src/two.py"), json!(null));
    let baseline: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".lgtm/evidence/current-task.baseline.json"))
            .expect("baseline readable"),
    )
    .expect("baseline JSON");
    let files = baseline["diff_files_before"]
        .as_array()
        .expect("diff baseline array");
    assert!(files.contains(&json!("before.txt")));
    assert!(!files.contains(&json!("after.txt")));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn denies_traversal_and_prohibited_paths() {
    let root = temp_repo("deny");
    assert_eq!(
        run(&root, "Edit", "../outside.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert_eq!(
        run(&root, "Edit", "/tmp/outside.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    std::fs::write(
        root.join(".lgtm/config.json"),
        r#"{"prohibited_paths":["secrets/**"]}"#,
    )
    .expect("config");
    assert_eq!(
        run(&root, "Write", "secrets/key.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn malformed_policy_denies_edit() {
    let root = temp_repo("malformed");
    std::fs::write(root.join(".lgtm/config.json"), "{").expect("config");
    assert_eq!(
        run(&root, "Write", "src/new.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn all_path_policy_denies_every_edit() {
    let root = temp_repo("deny-all");
    std::fs::write(
        root.join(".lgtm/config.json"),
        r#"{"prohibited_paths":["*"]}"#,
    )
    .expect("config");
    assert_eq!(
        run(&root, "Write", "src/new.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn non_edit_tool_is_true_noop() {
    let root = temp_repo("noop");
    assert_eq!(run(&root, "Read", "../outside.py"), json!(null));
    assert!(!root.join(".lgtm/evidence").exists());
    std::fs::remove_dir_all(root).ok();
}

#[cfg(unix)]
#[test]
fn denies_symlink_escape() {
    let root = temp_repo("symlink");
    std::os::unix::fs::symlink("/tmp", root.join("escape")).expect("symlink");
    assert_eq!(
        run(&root, "Write", "escape/new.py")["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    std::fs::remove_dir_all(root).ok();
}
