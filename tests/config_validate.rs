use std::process::{Command, Output};

use lgtm::policy::Severity;
use serde_json::{Value, json};

mod common;
use common::TempRepo;

const UNRELATED_MARKER: &str = "regression-test-required";

struct InvalidCase {
    name: &'static str,
    config: Value,
    cli_marker: &'static str,
    runtime_marker: &'static str,
    rejects_structurally: bool,
}

fn v2_config(profile: &str, disabled_rules: &[&str], severity_overrides: &[(&str, &str)]) -> Value {
    let disabled_rules = disabled_rules.to_vec();
    let severity_overrides = severity_overrides
        .iter()
        .map(|(rule_id, severity)| ((*rule_id).to_string(), json!(*severity)))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "version": "2",
        "profile": profile,
        "workspaces": [],
        "disabled_rules": disabled_rules,
        "severity_overrides": severity_overrides,
    })
}

fn v1_config(v2: &Value) -> Value {
    let mut config = v2.clone();
    let Some(object) = config.as_object_mut() else {
        panic!("V2 fixture must be a JSON object");
    };
    object.remove("version");
    object.insert("required_commands".to_string(), json!({"verify": ["true"]}));
    config
}

fn write_config(repo: &TempRepo, config: &Value) {
    repo.write(".lgtm/config.json", &config.to_string());
}

fn run_validate(repo: &TempRepo) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["config", "validate"])
        .current_dir(repo.path())
        .output()
        .unwrap_or_else(|error| panic!("config validate should execute: {error}"))
}

fn run_migrate(repo: &TempRepo) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["init", "--migrate-config"])
        .current_dir(repo.path())
        .output()
        .unwrap_or_else(|error| panic!("config migration should execute: {error}"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_policy_rejected_by_cli_and_loader(
    repo: &TempRepo,
    case: &InvalidCase,
    diagnostic_marker: &str,
) {
    let runtime_error = match lgtm::policy::load_profiled_registry(repo.path()) {
        Ok(_) => panic!("{} must fail runtime loading", case.name),
        Err(error) => error,
    };
    assert!(
        runtime_error.contains(case.runtime_marker),
        "{} runtime error should contain {}: {runtime_error}",
        case.name,
        case.runtime_marker
    );

    let output = run_validate(repo);
    let diagnostic = stderr(&output);
    assert!(
        !output.status.success(),
        "{} must make config validate fail; stderr: {diagnostic}",
        case.name
    );
    assert!(
        diagnostic.contains(diagnostic_marker),
        "{} diagnostic should contain {}: {diagnostic}",
        case.name,
        diagnostic_marker
    );
    assert!(
        !diagnostic.contains(UNRELATED_MARKER),
        "{} diagnostic must not echo unrelated fixture content: {diagnostic}",
        case.name
    );
}

fn invalid_cases() -> [InvalidCase; 5] {
    [
        InvalidCase {
            name: "unknown profile",
            config: v2_config("missing-profile", &[], &[(UNRELATED_MARKER, "warning")]),
            cli_marker: "missing-profile",
            runtime_marker: "missing-profile",
            rejects_structurally: false,
        },
        InvalidCase {
            name: "invalid severity",
            config: v2_config(
                "default",
                &[],
                &[
                    ("new-behavior-tests-required", "critical"),
                    (UNRELATED_MARKER, "warning"),
                ],
            ),
            cli_marker: "severity_overrides",
            runtime_marker: "critical",
            rejects_structurally: true,
        },
        InvalidCase {
            name: "unknown rule ID",
            config: v2_config(
                "default",
                &["unknown-rule"],
                &[(UNRELATED_MARKER, "warning")],
            ),
            cli_marker: "unknown-rule",
            runtime_marker: "unknown-rule",
            rejects_structurally: false,
        },
        InvalidCase {
            name: "disabled and severity-overridden conflict",
            config: v2_config(
                "default",
                &["new-behavior-tests-required"],
                &[
                    ("new-behavior-tests-required", "warning"),
                    (UNRELATED_MARKER, "warning"),
                ],
            ),
            cli_marker: "new-behavior-tests-required",
            runtime_marker: "new-behavior-tests-required",
            rejects_structurally: false,
        },
        InvalidCase {
            name: "non-overridable rule",
            config: v2_config(
                "default",
                &["no-committed-secrets"],
                &[(UNRELATED_MARKER, "warning")],
            ),
            cli_marker: "no-committed-secrets",
            runtime_marker: "no-committed-secrets",
            rejects_structurally: false,
        },
    ]
}

#[test]
fn invalid_runtime_policy_classes_are_rejected_by_cli_and_loader() {
    for case in invalid_cases() {
        let repo = TempRepo::new();
        write_config(&repo, &case.config);

        if case.rejects_structurally {
            let parse_error = lgtm::config_v2::parse(&case.config);
            assert!(
                parse_error.is_err(),
                "{} must fail V2 structural parsing",
                case.name
            );
        } else {
            let parse_result = lgtm::config_v2::parse(&case.config);
            assert!(
                parse_result.is_ok(),
                "{} must pass V2 structural parsing before runtime rejection",
                case.name
            );
        }

        assert_policy_rejected_by_cli_and_loader(&repo, &case, case.cli_marker);
    }
}

#[test]
fn v1_runtime_policy_classes_are_rejected_by_cli_and_loader() {
    for case in invalid_cases() {
        let repo = TempRepo::new();
        write_config(&repo, &v1_config(&case.config));

        let settings = lgtm::checks::commands::load(repo.path())
            .unwrap_or_else(|error| panic!("{} V1 command config must load: {error}", case.name));
        assert_eq!(
            settings.commands,
            vec!["true".to_string()],
            "{} V1 command config must load the valid required command",
            case.name
        );

        assert_policy_rejected_by_cli_and_loader(&repo, &case, case.runtime_marker);
    }
}

#[test]
fn runtime_loader_rejects_representative_v2_preflight_failures() {
    let mut unknown_field = v2_config("default", &[], &[]);
    unknown_field["unexpected"] = json!(true);

    let mut missing_required_field = v2_config("default", &[], &[]);
    missing_required_field
        .as_object_mut()
        .expect("fixture is an object")
        .remove("workspaces");

    let mut invalid_timeout = v2_config("default", &[], &[]);
    invalid_timeout["workspaces"] = json!([{
        "id": "rust",
        "language": "rust",
        "root": ".",
        "commands": [{
            "argv": ["cargo", "test"],
            "cwd": ".",
            "timeout_seconds": 3601,
            "tier": "full",
            "purpose": "test",
            "source": "fixture",
            "confidence": "high"
        }]
    }]);

    let mut parent_path = v2_config("default", &[], &[]);
    parent_path["workspaces"] = json!([{
        "id": "rust",
        "language": "rust",
        "root": "../outside",
        "commands": []
    }]);

    for (name, config) in [
        ("unknown field", unknown_field),
        ("missing required field", missing_required_field),
        ("timeout above schema limit", invalid_timeout),
        ("repository-relative path violation", parent_path),
    ] {
        let parse_error = match lgtm::config_v2::parse(&config) {
            Ok(_) => panic!("{name} must fail config_v2::parse"),
            Err(error) => error,
        };
        let repo = TempRepo::new();
        write_config(&repo, &config);
        let runtime_error = lgtm::policy::load_profiled_registry(repo.path())
            .expect_err("runtime loader must run the same V2 preflight");
        assert!(
            runtime_error.starts_with("config V2 is invalid:"),
            "{name} runtime error should come from V2 preflight: {runtime_error}; parse: {parse_error}"
        );
    }
}

#[test]
fn v1_migration_refuses_unsupported_severity_without_writing() {
    let repo = TempRepo::new();
    let raw = r#"{
  "profile": "default",
  "required_commands": {"rust": ["cargo test"]},
  "severity_overrides": {"regression-test-required": "critical"}
}
"#;
    repo.write(".lgtm/config.json", raw);

    let output = run_migrate(&repo);
    let diagnostic = stderr(&output);
    assert!(
        !output.status.success(),
        "migration must fail: {diagnostic}"
    );
    assert!(diagnostic.contains("severity_overrides values must be one of: error, warning, info"));
    assert_eq!(repo.read(".lgtm/config.json"), raw);
    assert!(!repo.exists(".lgtm/config.v1.bak.json"));
}

#[test]
fn valid_v1_config_keeps_compatibility_mode_and_exact_success_text() {
    let repo = TempRepo::new();
    let config = v1_config(&v2_config(
        "default",
        &[],
        &[("regression-test-required", "info")],
    ));
    write_config(&repo, &config);

    assert!(lgtm::policy::load_profiled_registry(repo.path()).is_ok());
    let output = run_validate(&repo);
    assert!(
        output.status.success(),
        "valid V1 config must pass: {}",
        stderr(&output)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "config valid: V1 compatibility\n"
    );
}

#[test]
fn embedded_profiles_are_accepted_by_cli_and_loader() {
    for profile in ["default", "strict", "prototype", "infrastructure"] {
        let repo = TempRepo::new();
        write_config(&repo, &v2_config(profile, &[], &[]));

        assert!(
            lgtm::policy::load_profiled_registry(repo.path()).is_ok(),
            "{profile} must load through the runtime policy path"
        );
        let output = run_validate(&repo);
        assert!(
            output.status.success(),
            "{profile} must pass config validate; stderr: {}",
            stderr(&output)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "config valid: V2\n",
            "{profile} must keep the exact V2 success text"
        );
    }
}

#[test]
fn valid_override_is_applied_before_cli_acceptance() {
    let repo = TempRepo::new();
    write_config(
        &repo,
        &v2_config("default", &[], &[("regression-test-required", "warning")]),
    );

    let (_, rules, records, _, _, _) = match lgtm::policy::load_profiled_registry(repo.path()) {
        Ok(registry) => registry,
        Err(error) => panic!("valid override must load: {error}"),
    };
    let rule = match rules
        .iter()
        .find(|rule| rule.id == "regression-test-required")
    {
        Some(rule) => rule,
        None => panic!("overridden rule must be present"),
    };
    assert_eq!(rule.severity, Severity::Warning);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].rule_id, "regression-test-required");
    assert_eq!(records[0].action, "severity");
    assert_eq!(records[0].severity, Some(Severity::Warning));

    let output = run_validate(&repo);
    assert!(
        output.status.success(),
        "valid override must pass config validate; stderr: {}",
        stderr(&output)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "config valid: V2\n"
    );
}

#[test]
fn bounds_and_sanitizes_schema_field_path_diagnostic() {
    let long_rule_id = "r".repeat(4096);
    let long_rule_key = format!("\u{0007}{long_rule_id}");
    let config = v2_config(
        "default",
        &[],
        &[
            (long_rule_key.as_str(), "critical"),
            (UNRELATED_MARKER, "warning"),
        ],
    );

    let parse_error = lgtm::config_v2::parse(&config).expect_err("invalid severity must fail");
    let parse_diagnostic = parse_error.to_string();
    assert!(parse_diagnostic.contains("severity_overrides"));
    assert!(!parse_diagnostic.chars().any(char::is_control));
    assert!(!parse_diagnostic.contains(long_rule_id.as_str()));
    assert!(parse_diagnostic.len() <= 2100);

    let repo = TempRepo::new();
    write_config(&repo, &config);
    let output = run_validate(&repo);
    let diagnostic = stderr(&output);
    assert!(!output.status.success());
    assert!(diagnostic.contains("severity_overrides"));
    assert!(!diagnostic.trim_end().chars().any(char::is_control));
    assert!(!diagnostic.contains(UNRELATED_MARKER));
    assert!(diagnostic.len() <= 2200);
}

#[test]
fn malformed_json_keeps_the_existing_cli_prefix_and_uses_safe_reporting() {
    let repo = TempRepo::new();
    let raw = format!(
        "{{\"version\":\"2\",\"profile\":\"default\",\"payload\":\"\u{0007}{}\"}}",
        "not-echoed".repeat(4096)
    );
    repo.write(".lgtm/config.json", &raw);

    let output = run_validate(&repo);
    let diagnostic = stderr(&output);
    assert!(!output.status.success());
    assert!(diagnostic.starts_with("config failed: invalid JSON ("));
    assert!(!diagnostic.trim_end().chars().any(char::is_control));
    assert!(!diagnostic.contains("not-echoed"));
    assert!(diagnostic.len() <= 2200);
}

#[test]
fn many_schema_errors_are_formatted_incrementally_within_the_budget() {
    let mut config = v2_config("default", &[], &[]);
    config["workspaces"] = Value::Array(
        (0..256)
            .map(|index| json!({"id": format!("workspace-{index}")}))
            .collect(),
    );

    let diagnostic = lgtm::config_v2::parse(&config)
        .expect_err("incomplete workspaces must fail")
        .to_string();
    assert!(diagnostic.starts_with("config V2 is invalid:"));
    assert!(diagnostic.len() <= 2100);
    assert!(diagnostic.ends_with('…'));
    assert!(!diagnostic.chars().any(char::is_control));
}

#[test]
fn semantic_policy_diagnostics_are_bounded_and_strip_controls() {
    let rule_prefix = "disabled_rules-";
    let long_rule_id = format!(
        "\u{0007}{rule_prefix}{}",
        "r".repeat(4096 - rule_prefix.len())
    );
    let config = v2_config(
        "default",
        &[long_rule_id.as_str()],
        &[(UNRELATED_MARKER, "warning")],
    );
    assert!(
        lgtm::config_v2::parse(&config).is_ok(),
        "semantic fixture must pass V2 structural parsing"
    );

    let repo = TempRepo::new();
    write_config(&repo, &config);
    let output = run_validate(&repo);
    let diagnostic = stderr(&output);
    assert!(!output.status.success());
    assert!(
        diagnostic.contains("policy override references unknown rule")
            || diagnostic.contains("unknown rule"),
        "diagnostic should identify the unknown rule: {diagnostic}"
    );
    assert!(
        diagnostic.contains("disabled_rules"),
        "diagnostic should identify the disabled_rules field: {diagnostic}"
    );
    assert!(!diagnostic.trim_end().chars().any(char::is_control));
    assert!(!diagnostic.contains(long_rule_id.as_str()));
    assert!(!diagnostic.contains(UNRELATED_MARKER));
    assert!(diagnostic.len() <= 2200);
}
