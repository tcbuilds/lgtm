use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

fn run_hook(repo: &TempRepo, event: &str, file: Option<&str>, path: &str) -> std::process::Output {
    let mut payload = json!({"cwd":repo.path(),"session_id":"waiver-e2e"});
    if let Some(file) = file {
        payload["tool_name"] = json!("Write");
        payload["tool_input"] = json!({"file_path":file});
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["hook", event])
        .env("PATH", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook starts");
    write!(child.stdin.take().expect("stdin"), "{payload}").expect("payload writes");
    child.wait_with_output().expect("hook completes")
}

fn fake_ruff(repo: &TempRepo) -> String {
    let bin = repo.path().join("bin");
    std::fs::create_dir(&bin).expect("bin directory");
    let ruff = bin.join("ruff");
    let filename = repo.path().join("src/app.py");
    let finding = json!([{
        "code":"BLE001","filename":filename,"message":"broad exception",
        "location":{"row":3}
    }]);
    repo.write(
        "bin/ruff",
        &format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff test'; exit 0; fi\nprintf '%s' '{}'\nexit 1\n",
            finding
        ),
    );
    let mut permissions = std::fs::metadata(&ruff)
        .expect("ruff metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&ruff, permissions).expect("ruff executable");
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn creates_and_replaces_a_deterministic_waiver() {
    let repo = TempRepo::new();
    for reason in ["legacy boundary", "approved exception"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args([
                "waive",
                "--rule",
                "no-broad-exception-handling",
                "--reason",
                reason,
                "--owner",
                "platform-team",
                "--expires",
                "2999-12-31",
            ])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let value = repo.read_json(".lgtm/waivers.json");
    assert_eq!(value["waivers"].as_array().unwrap().len(), 1);
    assert_eq!(value["waivers"][0]["reason"], "approved exception");
}

#[test]
fn rejects_protected_unknown_and_expired_waivers() {
    let repo = TempRepo::new();
    for (rule, expiry) in [
        ("no-committed-secrets", "2999-12-31"),
        ("unknown-rule", "2999-12-31"),
        ("no-broad-exception-handling", "2020-01-01"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args([
                "waive",
                "--rule",
                rule,
                "--reason",
                "exception",
                "--owner",
                "owner",
                "--expires",
                expiry,
            ])
            .current_dir(repo.path())
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

#[test]
fn active_waiver_unblocks_violation_and_is_reported() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"1","required_commands":{"test":["true"]}}"#,
    );
    let waive = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args([
            "waive",
            "--rule",
            "no-broad-exception-handling",
            "--reason",
            "approved best-effort boundary",
            "--owner",
            "platform-team",
            "--expires",
            "2999-12-31",
        ])
        .current_dir(repo.path())
        .output()
        .expect("waive runs");
    assert!(waive.status.success());
    repo.write(
        "src/app.py",
        "try:\n    operation()\nexcept Exception:\n    pass\n",
    );
    repo.write("tests/test_app.py", "def test_app():\n    assert True\n");
    let path = fake_ruff(&repo);
    for file in ["src/app.py", "tests/test_app.py"] {
        let output = run_hook(&repo, "post-tool-use", Some(file), &path);
        assert!(output.status.success());
        assert!(output.stdout.is_empty(), "waived Post must not block");
    }
    let stop = run_hook(&repo, "stop", None, &path);
    assert!(
        stop.status.success(),
        "Stop stderr: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(evidence.lines().last().expect("evidence line"))
        .expect("evidence JSON");
    assert_eq!(record["rules"]["waived"], 1);
    assert_eq!(record["waivers"][0]["owner"], "platform-team");
    let report = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .arg("report")
        .current_dir(repo.path())
        .output()
        .expect("report runs");
    let stdout = String::from_utf8(report.stdout).expect("report UTF-8");
    assert!(stdout.contains("no-broad-exception-handling: waived"));
    assert!(stdout.contains("platform-team"));
}

#[test]
fn waiver_store_rejects_symlinked_policy_directory() {
    let repo = TempRepo::new();
    repo.write("outside/.keep", "fixture");
    symlink(repo.path().join("outside"), repo.path().join(".lgtm")).expect("symlink");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args([
            "waive",
            "--rule",
            "no-broad-exception-handling",
            "--reason",
            "approved boundary",
            "--owner",
            "platform-team",
            "--expires",
            "2999-12-31",
        ])
        .current_dir(repo.path())
        .output()
        .expect("waive runs");
    assert!(!output.status.success());
    assert!(!repo.exists("outside/waivers.json"));
}
