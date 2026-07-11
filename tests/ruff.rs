mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use common::TempRepo;
use serde_json::json;

#[test]
fn fake_ruff_blocks_python_edit_and_persists_both_rules() {
    let repo = TempRepo::new();
    repo.write("src/app.py", "try:\n    work()\nexcept:\n    pass\n");
    repo.write(
        "bin/ruff",
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\nprintf '%s' '[{\"code\":\"E722\",\"filename\":\"src/app.py\",\"message\":\"bare except\",\"location\":{\"row\":3}}]'\nexit 1\n",
    );
    let binary = repo.path().join("bin/ruff");
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");

    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", "post-tool-use"])
        .env("PATH", repo.path().join("bin"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook starts");
    let payload = json!({
        "session_id": "ruff-it",
        "cwd": repo.path(),
        "tool_name": "Edit",
        "tool_input": { "file_path": "src/app.py" }
    });
    writeln!(child.stdin.take().expect("stdin available"), "{payload}").expect("payload writable");
    let output = child.wait_with_output().expect("hook completes");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(stdout.contains("no-broad-exception-handling"));
    let ledger = repo.read(".lgtm/evidence/current-task.results.jsonl");
    assert!(ledger.contains("no-swallowed-errors"));
    assert!(ledger.contains("no-broad-exception-handling"));
}
