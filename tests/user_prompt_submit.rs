use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

mod common;
use common::TempRepo;

#[test]
fn cli_emits_user_prompt_submit_context() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[project]\nname = \"fixture\"\n");
    repo.write("src/routes/events.py", "def route():\n    pass\n");
    let root = repo.path();
    let payload = json!({
        "cwd": root,
        "user_prompt": "fix src/routes/events.py using requests.post",
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "user-prompt-submit"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("lgtm binary starts");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload writable");
    let output = child.wait_with_output().expect("hook exits");
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hook emits JSON");

    assert!(output.status.success());
    assert_eq!(
        response["hookSpecificOutput"]["hookEventName"],
        "UserPromptSubmit"
    );
    assert!(
        response["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .is_some_and(|context| context.contains("Detected task intent: bug-fix."))
    );
}

#[test]
fn cli_fallback_scopes_python_bug_fix_guidance() {
    let repo = TempRepo::new();
    repo.write("pyproject.toml", "[project]\nname = \"fixture\"\n");
    repo.write(
        "src/routes/events.py",
        "import requests\n\ndef route():\n    return requests.post(url)\n",
    );
    let payload = json!({
        "cwd": repo.path(),
        "user_prompt": "fix src/routes/events.py using requests.post",
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "user-prompt-submit"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("lgtm binary starts");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload writable");
    let output = child.wait_with_output().expect("hook exits");
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hook emits JSON");
    let context = response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("fallback context string");

    assert!(output.status.success());
    assert!(context.contains("External calls require timeouts"));
    assert!(context.contains("For bug fixes"));
    assert!(context.contains("Do not claim a command or tests passed"));
    assert!(!context.contains("unsafe"));
    assert!(!context.contains("React"));
}

#[test]
fn cli_fallback_scopes_mixed_repository_guidance_to_prompt_files() {
    let repo = TempRepo::new();
    repo.write("src/lib.rs", "pub fn value() -> u32 { 1 }\n");
    repo.write(
        "frontend/src/App.tsx",
        "export function App() { return <main />; }\n",
    );
    let payload = json!({
        "cwd": repo.path(),
        "user_prompt": "fix src/lib.rs and frontend/src/App.tsx",
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "user-prompt-submit"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("lgtm binary starts");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload writable");
    let output = child.wait_with_output().expect("hook exits");
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("hook emits JSON");
    let context = response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("fallback context string");

    assert!(output.status.success());
    assert!(context.contains("unsafe"));
    assert!(context.contains("React"));
    assert!(!context.contains("External calls require timeouts"));
}
