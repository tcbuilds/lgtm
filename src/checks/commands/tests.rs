use std::os::unix::fs::PermissionsExt;

use crate::checks::Status;

use super::*;

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn create() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("lgtm-commands-{}-{id}", std::process::id()));
        std::fs::create_dir(&root).expect("fixture directory");
        Self { root }
    }

    fn script(&self, name: &str, exit: i32) -> String {
        let path = self.root.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nexit {exit}\n")).expect("script written");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("script executable");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn success_and_failure_record_exit_and_duration() {
    let fixture = Fixture::create();
    let commands = vec![fixture.script("pass", 0), fixture.script("fail", 7)];
    let output = run(&fixture.root, &commands);
    assert_eq!(output.results[0].status, Status::Passed);
    assert_eq!(output.results[1].status, Status::Failed);
    assert_eq!(output.evidence[0].exit_code, Some(0));
    assert_eq!(output.evidence[1].exit_code, Some(7));
    assert!(
        serde_json::to_value(&output.evidence).unwrap()[0]
            .get("duration_ms")
            .is_some()
    );
}

#[test]
fn shell_operators_and_environment_assignments_are_unverified() {
    let fixture = Fixture::create();
    let commands = vec![
        "echo ok; echo bad".to_string(),
        "MODE=test echo ok".to_string(),
        "echo ok # hidden".to_string(),
        "echo ok\necho hidden".to_string(),
    ];
    let output = run(&fixture.root, &commands);
    assert!(
        output
            .results
            .iter()
            .all(|result| result.status == Status::Unverified)
    );
    assert!(output.evidence.iter().all(|item| item.exit_code.is_none()));
}

#[test]
fn config_loads_grouped_commands_and_enforces_cap() {
    let fixture = Fixture::create();
    std::fs::create_dir(fixture.root.join(".lgtm")).expect("config directory");
    std::fs::write(
        fixture.root.join(".lgtm/config.json"),
        r#"{"required_commands":{"python":["ruff check ."],"tests":["cargo test"]}}"#,
    )
    .expect("config");
    assert_eq!(load(&fixture.root).unwrap().len(), 2);
    let too_many = serde_json::json!({"required_commands": {"all": vec!["true"; 65]}});
    std::fs::write(
        fixture.root.join(".lgtm/config.json"),
        serde_json::to_vec(&too_many).unwrap(),
    )
    .expect("oversized config");
    assert!(load(&fixture.root).unwrap_err().contains("exceeds 64"));
}
