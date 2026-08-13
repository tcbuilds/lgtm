use std::os::unix::fs::PermissionsExt;

use crate::checks::Status;
use crate::policy::Severity;

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

#[test]
fn aggregate_budget_stops_structured_and_coverage_in_order() {
    let fixture = Fixture::create();
    let structured_started = fixture.root.join("structured-started");
    let later_structured_started = fixture.root.join("later-structured-started");
    let coverage_started = fixture.root.join("coverage-started");
    let slow = fixture.script_body(
        "slow",
        &format!("touch {}; sleep 1", structured_started.display()),
    );
    let later = fixture.script_body(
        "later",
        &format!("touch {}; exit 0", later_structured_started.display()),
    );
    let coverage_tool = fixture.script_body(
        "coverage",
        &format!(
            "touch {}; echo 'line coverage: 95% branch coverage: 95%'",
            coverage_started.display()
        ),
    );
    let structured = vec![
        StructuredCommand {
            argv: vec![slow],
            cwd: ".".into(),
            workspace_id: "root".to_string(),
            tier: "full".to_string(),
            timeout: std::time::Duration::from_secs(30),
        },
        StructuredCommand {
            argv: vec![later],
            cwd: ".".into(),
            workspace_id: "root".to_string(),
            tier: "full".to_string(),
            timeout: std::time::Duration::from_secs(30),
        },
    ];
    let coverage = vec![CoverageCommand {
        workspace_id: "root".to_string(),
        argv: vec![coverage_tool],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent: Some(80),
        branch_threshold_percent: Some(80),
    }];

    let started = std::time::Instant::now();
    let mut budget = ExecutionBudget::new(std::time::Duration::from_millis(100));
    let structured_output = run_structured_with_budget(&fixture.root, &structured, &mut budget);
    let coverage_output = run_coverage_with_budget(&fixture.root, &coverage, &mut budget);

    assert!(budget.is_exhausted());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(structured_started.exists());
    assert!(!later_structured_started.exists());
    assert_eq!(structured_output.evidence[0].exit_code, None);
    assert_eq!(structured_output.evidence[1].exit_code, None);
    assert!(structured_output.evidence[1].started_at_ms.is_none());
    assert!(
        structured_output
            .results
            .iter()
            .all(|result| result.status == Status::Unverified)
    );
    assert_eq!(coverage_output[0].status, "unverified");
    assert!(coverage_output[0].line_percent.is_none());
    assert!(coverage_output[0].branch_percent.is_none());
    assert!(coverage_output[0].measured_at_ms.is_none());
    assert!(!coverage_started.exists());
}

#[test]
fn coverage_only_cutoff_exhausts_the_aggregate_budget() {
    let fixture = Fixture::create();
    let started = fixture.root.join("coverage-only-started");
    let coverage = CoverageCommand {
        workspace_id: "root".to_string(),
        argv: vec![fixture.script_body(
            "coverage-only",
            &format!("touch {}; sleep 1", started.display()),
        )],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent: Some(80),
        branch_threshold_percent: Some(80),
    };

    let elapsed = std::time::Instant::now();
    let mut budget = ExecutionBudget::new(std::time::Duration::from_millis(100));
    let evidence = run_coverage_with_budget(&fixture.root, &[coverage], &mut budget);

    assert!(started.exists());
    assert!(budget.is_exhausted());
    assert!(elapsed.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(evidence[0].status, "unverified");
    assert!(evidence[0].line_percent.is_none());
    assert!(evidence[0].branch_percent.is_none());
}

#[test]
fn aggregate_budget_preserves_successful_structured_and_coverage_runs() {
    let fixture = Fixture::create();
    let structured = StructuredCommand {
        argv: vec![fixture.script("pass", 0)],
        cwd: ".".into(),
        workspace_id: "root".to_string(),
        tier: "full".to_string(),
        timeout: std::time::Duration::from_secs(30),
    };
    let coverage = CoverageCommand {
        workspace_id: "root".to_string(),
        argv: vec![
            fixture.script_body("coverage", "echo 'line coverage: 95% branch coverage: 95%'"),
        ],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent: Some(80),
        branch_threshold_percent: Some(80),
    };

    let mut budget = ExecutionBudget::new(std::time::Duration::from_secs(2));
    let structured_output = run_structured_with_budget(&fixture.root, &[structured], &mut budget);
    let coverage_output = run_coverage_with_budget(&fixture.root, &[coverage], &mut budget);

    assert!(!budget.is_exhausted());
    assert_eq!(structured_output.results[0].status, Status::Passed);
    assert_eq!(coverage_output[0].status, "passed");
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
    assert_eq!(settings.workspace_ids, ["root"]);
    let output = run_structured(&fixture.root, &settings.structured);
    assert_eq!(output.results[0].status, Status::Passed);
    let evidence = serde_json::to_value(&output.evidence).expect("evidence JSON");
    assert_eq!(evidence[0]["argv"][0], script);
    assert_eq!(evidence[0]["cwd"], ".");
    assert_eq!(evidence[0]["workspace_id"], "root");
    assert!(evidence[0]["started_at_ms"].is_number());
    assert!(evidence[0]["finished_at_ms"].is_number());
}

#[test]
fn config_rejects_world_writable_files() {
    let fixture = Fixture::create();
    std::fs::create_dir(fixture.root.join(".lgtm")).expect("config directory");
    let path = fixture.root.join(".lgtm/config.json");
    std::fs::write(&path, "{}").expect("config");
    let mut permissions = std::fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o666);
    std::fs::set_permissions(&path, permissions).expect("world writable");
    assert!(
        load(&fixture.root)
            .unwrap_err()
            .contains("not world writable")
    );
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

#[test]
fn coverage_without_a_configured_tool_is_not_applicable() {
    let fixture = Fixture::create();
    let evidence = run_coverage(&fixture.root, &[]);
    assert_eq!(evidence[0].workspace_id, "repository");
    assert_eq!(evidence[0].status, "not_applicable");
    assert!(evidence[0].line_percent.is_none());
    assert!(evidence[0].branch_percent.is_none());
}

#[test]
fn configured_coverage_requires_each_configured_metric() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("line-only-coverage", "echo 'line coverage: 95%'");
    let command = CoverageCommand {
        workspace_id: "backend".to_string(),
        argv: vec![tool],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent: Some(80),
        branch_threshold_percent: Some(80),
    };
    let evidence = run_coverage(&fixture.root, &[command]);
    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(evidence[0].line_percent, Some(95.0));
    assert_eq!(evidence[0].branch_percent, None);
}

#[test]
fn configured_coverage_records_metrics_and_threshold_status() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("coverage", "echo 'line coverage: 85% branch coverage: 90%'");
    let command = CoverageCommand {
        workspace_id: "backend".to_string(),
        argv: vec![tool],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent: Some(80),
        branch_threshold_percent: Some(90),
    };
    let evidence = run_coverage(&fixture.root, &[command]);
    assert_eq!(evidence[0].status, "passed");
    assert_eq!(evidence[0].line_percent, Some(85.0));
    assert_eq!(evidence[0].branch_percent, Some(90.0));
}

#[test]
fn coverage_parser_uses_value_immediately_before_percent() {
    assert_eq!(
        super::runner::parse_metric("line coverage: 120/120 100%", "line"),
        Some(100.0)
    );
    assert_eq!(
        super::runner::parse_metric("line coverage: 98/120 81.67%", "line"),
        Some(81.67)
    );
}

#[test]
fn coverage_parser_matches_case_insensitive_semantic_labels_in_any_order() {
    let report = "Baseline coverage: 100%\nBRANCH coverage: 90%; LINE coverage: 50%";
    assert_eq!(super::runner::parse_metric(report, "line"), Some(50.0));
    assert_eq!(super::runner::parse_metric(report, "branch"), Some(90.0));
    assert_eq!(
        super::runner::parse_metric("lineage coverage: 100%\nline coverage: 50%", "line"),
        Some(50.0)
    );
}

#[test]
fn coverage_parser_rejects_malformed_and_out_of_range_percentages() {
    for report in [
        "line coverage: unavailable%",
        "line coverage: -1%",
        "line coverage: 100.1%",
        "line coverage: 1e2%",
        "line coverage: 1..0%",
    ] {
        assert_eq!(
            super::runner::parse_metric(report, "line"),
            None,
            "must reject {report}"
        );
    }
}

#[test]
fn decimal_coverage_is_compared_without_truncation() {
    let fixture = Fixture::create();
    let tool = fixture.script_body(
        "decimal-coverage",
        "echo 'line coverage: 79/100 79.9% branch coverage: 81.25%'",
    );
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(81))]);

    assert_eq!(evidence[0].line_percent, Some(79.9));
    assert_eq!(evidence[0].branch_percent, Some(81.25));
    assert_eq!(evidence[0].status, "failed");
}

#[test]
fn out_of_range_metric_is_unverified_and_not_serialized() {
    let fixture = Fixture::create();
    let tool = fixture.script_body(
        "invalid-coverage",
        "echo 'line coverage: 120% branch coverage: 90%'",
    );
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(80))]);
    let serialized = serde_json::to_value(&evidence).expect("coverage evidence serializes");

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(evidence[0].line_percent, None);
    assert_eq!(evidence[0].branch_percent, Some(90.0));
    assert_eq!(serialized[0]["line_percent"], serde_json::Value::Null);
}

#[test]
fn missing_configured_metric_is_unverified_and_non_blocking() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("partial-coverage", "echo 'branch coverage: 90%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(90))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
}

#[test]
fn below_line_threshold_with_missing_branch_remains_failed() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("line-fail-missing-branch", "echo 'line coverage: 50%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "failed");
    assert_eq!(results[0].status, Status::Failed);
    assert!(results[0].is_failure());
}

#[test]
fn unparseable_line_with_valid_branch_remains_unverified_and_non_blocking() {
    let fixture = Fixture::create();
    let tool = fixture.script_body(
        "partial-coverage",
        "echo 'line coverage: unavailable; branch coverage: 90%'",
    );
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(evidence[0].line_percent, None);
    assert_eq!(evidence[0].branch_percent, Some(90.0));
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
}

#[test]
fn passing_coverage_projects_to_passed_required_repository_command() {
    let results = coverage_results(&[coverage_evidence("passed")]);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Passed);
    assert_eq!(results[0].severity, Severity::Error);
    assert!(
        results[0]
            .message
            .contains("coverage workspace=backend scope=unit tool=coverage")
    );
    assert_eq!(results[0].remediation, None);
}

#[test]
fn below_line_threshold_projects_to_failed_required_repository_command() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("line-fail", "echo 'line coverage: 79%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), None)]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "failed");
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Failed);
    assert_eq!(results[0].severity, Severity::Error);
    assert!(
        results[0]
            .message
            .contains("coverage workspace=backend scope=unit tool=")
    );
    assert!(results[0].message.contains("failed configured thresholds"));
    assert!(
        results[0]
            .remediation
            .as_deref()
            .is_some_and(|message| message.contains("workspace `backend` scope `unit`"))
    );
}

#[test]
fn below_branch_threshold_projects_to_failed_required_repository_command() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("branch-fail", "echo 'branch coverage: 79%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, None, Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "failed");
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Failed);
    assert_eq!(results[0].severity, Severity::Error);
    assert!(
        results[0]
            .message
            .contains("coverage workspace=backend scope=unit tool=")
    );
    assert!(results[0].message.contains("failed configured thresholds"));
}

#[test]
fn branch_only_metric_above_threshold_remains_passing() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("branch-pass", "echo 'branch coverage: 90%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, None, Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "passed");
    assert_eq!(results[0].status, Status::Passed);
    assert!(!results[0].is_failure());
}

#[test]
fn unparseable_coverage_projects_to_unverified_without_failure() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("unverified", "echo 'coverage report unavailable'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(evidence[0].line_percent, None);
    assert_eq!(evidence[0].branch_percent, None);
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
    assert!(
        results[0]
            .message
            .contains("coverage workspace=backend scope=unit tool=")
    );
    assert!(results[0].message.contains("could not verify coverage"));
}

#[test]
fn missing_coverage_executable_projects_to_unverified_without_failure() {
    let fixture = Fixture::create();
    let missing = fixture
        .root
        .join("missing-coverage")
        .to_string_lossy()
        .into_owned();
    let evidence = run_coverage(
        &fixture.root,
        &[coverage_command(missing, Some(80), Some(80))],
    );
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(evidence[0].line_percent, None);
    assert_eq!(evidence[0].branch_percent, None);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
}

#[test]
fn nonzero_coverage_process_projects_to_unverified_without_failure() {
    let fixture = Fixture::create();
    let tool = fixture.script("coverage-nonzero", 9);
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(80))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
}

#[test]
fn timed_out_coverage_process_projects_to_unverified_without_failure() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("coverage-timeout", "sleep 1");
    let mut command = coverage_command(tool, Some(80), Some(80));
    command.timeout = std::time::Duration::from_millis(20);
    let evidence = run_coverage(&fixture.root, &[command]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "unverified");
    assert_eq!(results[0].status, Status::Unverified);
    assert!(!results[0].is_failure());
}

#[test]
fn coverage_results_include_workspace_scope_and_tool_identity() {
    let results = coverage_results(&[CoverageEvidence {
        workspace_id: "api".to_string(),
        status: "failed".to_string(),
        tool: Some("cargo-llvm-cov".to_string()),
        scope: Some("integration".to_string()),
        line_percent: Some(72.0),
        branch_percent: Some(68.0),
        measured_at_ms: Some(0),
    }]);

    assert!(results[0].message.contains("workspace=api"));
    assert!(results[0].message.contains("scope=integration"));
    assert!(results[0].message.contains("tool=cargo-llvm-cov"));
    assert!(
        results[0]
            .remediation
            .as_deref()
            .is_some_and(|message| message.contains("satisfy its configured thresholds"))
    );
}

#[test]
fn no_coverage_not_applicable_remains_evidence_only() {
    let fixture = Fixture::create();
    let evidence = run_coverage(&fixture.root, &[]);

    assert_eq!(evidence[0].status, "not_applicable");
    assert!(coverage_results(&evidence).is_empty());
}

#[test]
fn exact_coverage_threshold_boundary_remains_passing() {
    let fixture = Fixture::create();
    let tool = fixture.script_body("boundary", "echo 'line coverage: 80% branch coverage: 90%'");
    let evidence = run_coverage(&fixture.root, &[coverage_command(tool, Some(80), Some(90))]);
    let results = coverage_results(&evidence);

    assert_eq!(evidence[0].status, "passed");
    assert_eq!(results[0].rule_id, "required-repository-commands");
    assert_eq!(results[0].status, Status::Passed);
    assert!(!results[0].is_failure());
}

fn coverage_evidence(status: &str) -> CoverageEvidence {
    CoverageEvidence {
        workspace_id: "backend".to_string(),
        status: status.to_string(),
        tool: Some("coverage".to_string()),
        scope: Some("unit".to_string()),
        line_percent: None,
        branch_percent: None,
        measured_at_ms: Some(0),
    }
}

fn coverage_command(
    tool: String,
    line_threshold_percent: Option<u8>,
    branch_threshold_percent: Option<u8>,
) -> CoverageCommand {
    CoverageCommand {
        workspace_id: "backend".to_string(),
        argv: vec![tool],
        cwd: ".".into(),
        timeout: std::time::Duration::from_secs(30),
        scope: "unit".to_string(),
        line_threshold_percent,
        branch_threshold_percent,
    }
}
