//! Registry bounds and missing-project behavior through the public CLI.

use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

mod common;
use common::TempRepo;

const REGISTRY: &str = ".local/state/lgtm/pi-installations";

fn run_cli(home: &TempRepo, arguments: &[&str]) -> Output {
    let workspace = home.path().join("workspace");
    fs::create_dir_all(&workspace).expect("isolated workspace");
    let mut child = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(arguments)
        .env("HOME", home.path())
        .current_dir(workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start CLI");
    let deadline = Instant::now() + Duration::from_secs(45);
    while child.try_wait().expect("observe CLI").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("terminate timed-out CLI");
            child.wait().expect("reap CLI");
            panic!("CLI exceeded 45 seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("collect CLI result")
}

fn registration(root: &Path) -> Value {
    json!({
        "version": 1,
        "target": root.join(".pi/extensions/lgtm.ts"),
        "binary": env!("CARGO_BIN_EXE_lgtm"),
        "global": false,
        "managed": {
            "root": root, "agent": "pi", "rules_only": false,
            "guidance": [], "codex_digest": null
        }
    })
}

fn write_registration(home: &TempRepo, name: &str, record: &Value) {
    home.write(&format!("{REGISTRY}/{name}.json"), &record.to_string());
}

#[test]
fn refresh_reports_deleted_project_without_removing_any_registration_or_owner_hook() {
    let home = TempRepo::new();
    let missing = registration(&home.path().join("deleted-project"));
    let live = registration(home.path());
    write_registration(&home, "missing", &missing);
    write_registration(&home, "live", &live);
    let owner_hook = "export default function ownerHook() {}\n";
    home.write(".pi/extensions/lgtm.ts", owner_hook);
    let output = run_cli(&home, &["refresh"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 stale"),
        "missing-project count absent: {stdout}"
    );
    assert_eq!(home.read_json(&format!("{REGISTRY}/missing.json")), missing);
    assert_eq!(home.read_json(&format!("{REGISTRY}/live.json")), live);
    assert_eq!(home.read(".pi/extensions/lgtm.ts"), owner_hook);
    assert!(!home.path().join("deleted-project").exists());
}

#[test]
fn refresh_does_not_hide_invalid_root_identity_as_a_deleted_project() {
    let home = TempRepo::new();
    let mut record = registration(&home.path().join("missing"));
    record["target"] = json!(home.path().join("outside/.pi/extensions/lgtm.ts"));
    write_registration(&home, "invalid", &record);
    let output = run_cli(&home, &["refresh"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("registered installation root is invalid")
    );
    assert_eq!(home.read_json(&format!("{REGISTRY}/invalid.json")), record);
}

#[test]
fn refresh_rejects_invalid_pi_target_even_when_managed_root_is_missing() {
    for global in [false, true] {
        let home = TempRepo::new();
        let root = home.path().join("missing");
        let mut record = registration(&root);
        record["global"] = json!(global);
        record["target"] = json!(root.join("invalid.ts"));
        write_registration(&home, "invalid-target", &record);
        let output = run_cli(&home, &["refresh"]);
        assert!(
            !output.status.success(),
            "malformed target was skipped: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("not a Pi extension location"));
        assert_eq!(
            home.read_json(&format!("{REGISTRY}/invalid-target.json")),
            record
        );
        assert!(!root.exists());
    }
}

#[cfg(unix)]
#[test]
fn refresh_rejects_a_dangling_root_symlink_instead_of_skipping_it() {
    let home = TempRepo::new();
    let root = home.path().join("linked-project");
    std::os::unix::fs::symlink(home.path().join("missing"), &root).expect("root symlink");
    write_registration(&home, "linked", &registration(&root));
    let output = run_cli(&home, &["refresh"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not a regular directory"));
    assert!(
        fs::symlink_metadata(root)
            .expect("retained symlink")
            .file_type()
            .is_symlink()
    );
}

fn fill_registry(home: &TempRepo, count: usize) {
    let mut record = registration(&home.path().join("deleted-project"));
    record["binary"] = json!(home.path().join("other-binary"));
    for index in 0..count {
        write_registration(home, &format!("record-{index}"), &record);
    }
}

#[test]
fn refresh_distinguishes_record_limit_from_timeout_without_deleting_records() {
    let home = TempRepo::new();
    fill_registry(&home, 4096);
    let at_limit = run_cli(&home, &["refresh"]);
    assert!(
        at_limit.status.success(),
        "4096 records must be allowed: {at_limit:?}"
    );
    write_registration(
        &home,
        "overflow",
        &registration(&home.path().join("deleted-project")),
    );
    let output = run_cli(&home, &["refresh"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("installation registry limit reached"),
        "{stderr}"
    );
    assert!(stderr.contains("4096"), "{stderr}");
    assert!(
        !stderr.contains("timed out"),
        "count limit mislabeled as timeout: {stderr}"
    );
    assert_eq!(
        fs::read_dir(home.path().join(REGISTRY))
            .expect("registry")
            .count(),
        4097
    );
}

#[test]
fn init_reports_registration_limit_instead_of_a_combined_timeout_error() {
    let home = TempRepo::new();
    fill_registry(&home, 4096);
    let output = run_cli(&home, &["init", "--agent", "pi", "--accept-guesses"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("installation registry limit reached"),
        "{stderr}"
    );
    assert!(stderr.contains("4096"), "{stderr}");
    assert!(!stderr.contains("timed out"), "{stderr}");
    assert_eq!(
        fs::read_dir(home.path().join(REGISTRY))
            .expect("registry")
            .count(),
        4096
    );
}
