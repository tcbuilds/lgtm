use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::json;

#[test]
fn cli_emits_user_prompt_submit_context() {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python");
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
