//! Deterministic full M1 hook loop against the checked-in Python example.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn run_hook(repo: &TempRepo, path: &str, event: &str, tool_name: Option<&str>) -> Output {
    let payload = match tool_name {
        Some(name) => json!({
            "session_id": "m1-e2e",
            "cwd": repo.path(),
            "tool_name": name,
            "tool_input": { "file_path": path },
        }),
        None => json!({ "session_id": "m1-e2e", "cwd": repo.path() }),
    };
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event])
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", repo.path().join("bin").display()),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook spawns");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(payload.to_string().as_bytes())
        .expect("payload writes");
    child.wait_with_output().expect("hook completes")
}

fn install_fake_gitleaks(repo: &TempRepo) {
    let script = r#"#!/bin/sh
if [ "$1" = "version" ]; then echo "test-1.0"; exit 0; fi
report=""; source=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report-path) report="$2"; shift 2 ;;
    --source) source="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if grep -q 'PLANTED_SECRET_MARKER' "$source"; then
  printf '[{"RuleID":"test-secret","Description":"test finding","File":"%s","StartLine":1}]' "$source" > "$report"
  exit 2
fi
printf '[]' > "$report"
exit 0
"#;
    repo.write("bin/gitleaks", script);
    let path = repo.path().join("bin/gitleaks");
    let mut permissions = std::fs::metadata(&path)
        .expect("fake metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("fake executable");
}

#[test]
fn secret_blocks_then_clean_stop_writes_well_formed_evidence() {
    let repo = TempRepo::new();
    install_fake_gitleaks(&repo);
    let example = std::fs::read_to_string("examples/python-service/src/python_service/pricing.py")
        .expect("checked-in example exists");
    repo.write(
        "pyproject.toml",
        &std::fs::read_to_string("examples/python-service/pyproject.toml")
            .expect("example metadata"),
    );
    repo.write(
        "src/python_service/pricing.py",
        &format!("PLANTED_SECRET_MARKER = True\n{example}"),
    );
    let path = repo
        .path()
        .join("src/python_service/pricing.py")
        .to_string_lossy()
        .into_owned();

    let post = run_hook(&repo, &path, "post-tool-use", Some("Write"));
    assert!(post.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&post.stdout).expect("block JSON")["decision"],
        "block"
    );

    let stop = run_hook(&repo, &path, "stop", None);
    assert_eq!(stop.status.code(), Some(2));
    assert!(stop.stdout.is_empty());
    let decision: Value = serde_json::from_slice(&stop.stderr).expect("Stop block JSON on stderr");
    assert_eq!(decision["decision"], "block");
    assert!(
        decision["reason"]
            .as_str()
            .expect("block reason")
            .contains("Repair:")
    );

    repo.write("src/python_service/pricing.py", &example);
    let clean_stop = run_hook(&repo, &path, "stop", None);
    assert!(clean_stop.status.success());
    assert!(String::from_utf8_lossy(&clean_stop.stdout).contains("failed=0"));

    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.lines().count() >= 2);
    for line in evidence.lines() {
        let record: Value = serde_json::from_str(line).expect("each evidence line is JSON");
        assert_eq!(record["task_id"], "m1-e2e");
        assert!(record["rules"].is_object());
        assert!(record["results"].is_array());
    }
}

#[test]
fn missing_gitleaks_is_prominent_but_does_not_block_stop() {
    let repo = TempRepo::new();
    install_fake_gitleaks(&repo);
    repo.write("clean.py", "value = 1\n");
    let path = repo.path().join("clean.py").to_string_lossy().into_owned();
    assert!(
        run_hook(&repo, &path, "post-tool-use", Some("Edit"))
            .status
            .success()
    );

    let fake = repo.path().join("bin/gitleaks");
    let mut permissions = std::fs::metadata(&fake)
        .expect("fake metadata")
        .permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(fake, permissions).expect("disable fake executable");

    let stop = run_hook(&repo, &path, "stop", None);
    assert!(stop.status.success(), "unverified MUST must not hard-block");
    let stdout = String::from_utf8(stop.stdout).expect("UTF-8 stdout");
    assert!(stdout.contains("UNVERIFIED no-committed-secrets"));
    assert!(stdout.contains("UNVERIFIED no-swallowed-errors"));
    assert!(stdout.contains("UNVERIFIED no-broad-exception-handling"));
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence line"))
        .expect("evidence JSON");
    assert_eq!(record["rules"]["unverified"], 3);
    assert_eq!(record["rules"]["failed"], 0);
}
