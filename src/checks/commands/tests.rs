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
        self.script_body(name, &format!("exit {exit}"))
    }

    fn script_body(&self, name: &str, body: &str) -> String {
        let path = self.root.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script written");
        let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("script executable");
        path.to_string_lossy().into_owned()
    }
}

#[test]
fn configured_duration_terminates_long_command() {
    let fixture = Fixture::create();
    let command = fixture.script_body("slow", "sleep 1");
    let output = run(
        &fixture.root,
        &[command],
        std::time::Duration::from_millis(20),
    );
    assert_eq!(output.results[0].status, Status::Unverified);
    assert_eq!(output.evidence[0].exit_code, None);
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
    let output = run(&fixture.root, &commands, std::time::Duration::from_secs(30));
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
    let output = run(&fixture.root, &commands, std::time::Duration::from_secs(30));
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
    assert_eq!(load(&fixture.root).unwrap().commands.len(), 2);
    let too_many = serde_json::json!({"required_commands": {"all": vec!["true"; 65]}});
    std::fs::write(
        fixture.root.join(".lgtm/config.json"),
        serde_json::to_vec(&too_many).unwrap(),
    )
    .expect("oversized config");
    assert!(load(&fixture.root).unwrap_err().contains("exceeds 64"));
}

#[test]
fn config_v2_loads_structured_argv_and_workspace_cwd() {
    let fixture = Fixture::create();
    std::fs::create_dir(fixture.root.join(".lgtm")).expect("config directory");
    let script = fixture.script("pass-v2", 0);
    let config = serde_json::json!({
        "version": "2",
        "profile": "default",
        "workspaces": [{
            "id": "root",
            "language": "shell",
            "root": ".",
            "commands": [{
                "argv": [script],
                "cwd": ".",
                "timeout_seconds": 30,
                "tier": "full",
                "purpose": "test",
                "source": "fixture",
                "confidence": "high"
            }]
        }],
        "disabled_rules": [],
        "severity_overrides": {}
    });
    std::fs::write(
        fixture.root.join(".lgtm/config.json"),
        serde_json::to_vec(&config).expect("config JSON"),
    )
    .expect("config");
    let settings = load(&fixture.root).expect("V2 config loads");
    assert_eq!(settings.structured.len(), 1);
    let output = run_structured(&fixture.root, &settings.structured);
    assert_eq!(output.results[0].status, Status::Passed);
    let evidence = serde_json::to_value(&output.evidence).expect("evidence JSON");
    assert_eq!(evidence[0]["argv"][0], script);
    assert_eq!(evidence[0]["cwd"], ".");
    assert_eq!(evidence[0]["workspace_id"], "root");
}

#[test]
fn structured_commands_isolate_identically_named_workspace_tools() {
    let fixture = Fixture::create();
    let backend = fixture.root.join("backend");
    let frontend = fixture.root.join("frontend");
    std::fs::create_dir_all(&backend).expect("backend");
    std::fs::create_dir_all(&frontend).expect("frontend");
    let backend_tool = write_workspace_tool(&backend, "backend-tool");
    let frontend_tool = write_workspace_tool(&frontend, "frontend-tool");
    let commands = vec![
        StructuredCommand {
            argv: vec![backend_tool.to_string_lossy().into_owned()],
            cwd: "backend".into(),
            workspace_id: "backend".to_string(),
            tier: "full".to_string(),
            timeout: std::time::Duration::from_secs(30),
        },
        StructuredCommand {
            argv: vec![frontend_tool.to_string_lossy().into_owned()],
            cwd: "frontend".into(),
            workspace_id: "frontend".to_string(),
            tier: "full".to_string(),
            timeout: std::time::Duration::from_secs(30),
        },
    ];
    let output = run_structured(&fixture.root, &commands);
    assert!(
        output
            .results
            .iter()
            .all(|result| result.status == Status::Passed)
    );
    assert_eq!(output.evidence[0].cwd.as_deref(), Some("backend"));
    assert_eq!(output.evidence[1].cwd.as_deref(), Some("frontend"));
    assert_eq!(output.evidence[0].workspace_id.as_deref(), Some("backend"));
    assert_eq!(output.evidence[1].workspace_id.as_deref(), Some("frontend"));
    assert_eq!(output.evidence[0].argv.len(), 1);
    assert_eq!(output.evidence[1].argv.len(), 1);
}

fn write_workspace_tool(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::write(&path, "#!/bin/sh\npwd >/dev/null\nexit 0\n").expect("tool");
    let mut permissions = std::fs::metadata(&path)
        .expect("tool metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("tool executable");
    path
}

#[test]
fn config_uses_default_and_validates_custom_timeout() {
    let fixture = Fixture::create();
    std::fs::create_dir(fixture.root.join(".lgtm")).unwrap();
    std::fs::write(fixture.root.join(".lgtm/config.json"), "{}").unwrap();
    assert_eq!(load(&fixture.root).unwrap().timeout.as_secs(), 30);
    std::fs::write(
        fixture.root.join(".lgtm/config.json"),
        r#"{"command_timeout_seconds":2}"#,
    )
    .unwrap();
    assert_eq!(load(&fixture.root).unwrap().timeout.as_secs(), 2);
    for invalid in ["0", "3601", "\"30\""] {
        std::fs::write(
            fixture.root.join(".lgtm/config.json"),
            format!(r#"{{"command_timeout_seconds":{invalid}}}"#),
        )
        .unwrap();
        assert!(load(&fixture.root).is_err());
    }
}
