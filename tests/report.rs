use std::process::Command;

use serde_json::json;

mod common;
use common::TempRepo;

#[test]
fn report_renders_latest_evidence_without_finding_descriptions() {
    let repo = TempRepo::new();
    let result = json!({
        "rule_id":"example-rule","status":"warning","severity":"warning",
        "message":"repo controlled secret-value","locations":[{"file":"src/app.py","line":4}],
        "evidence":{"check":"example.check","finding_descriptions":["secret-value"]}
    });
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"task-1","agent":"claude-code","profile":"default","results":[result],
                "commands":[{"command":"pytest --token secret-command-value","exit_code":0,"duration_ms":12}],
                "overrides":[{"rule_id":"example-rule","action":"severity","severity":"warning"}]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Task: task-1"));
    assert!(stdout.contains("Pi enforcement recorded: stale/unverified scope=none"));
    assert!(stdout.contains("Pi installation current: not-installed scope=none"));
    assert!(stdout.contains("Pi enforcement effective: stale/unverified scope=none"));
    assert!(stdout.contains("src/app.py"));
    assert!(stdout.contains("example-rule: warning"));
    assert!(stdout.contains("pytest: exit=Some(0) duration_ms=12"));
    assert!(!stdout.contains("secret-value"));
    assert!(!stdout.contains("secret-command-value"));
}

#[test]
fn report_never_upgrades_recorded_pi_state_after_extension_deletion() {
    let repo = TempRepo::new();
    let result = json!({
        "rule_id":"example-rule","status":"passed","severity":"info",
        "message":"ok","locations":[],"evidence":{"check":"example.check"}
    });
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"pi-task","agent":"claude-code","harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"attested"},
                "profile":"default","results":[result]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("Pi enforcement recorded: active scope=project"));
    assert!(stdout.contains("Pi installation current: not-installed scope=none"));
    assert!(stdout.contains("Pi enforcement effective: not-installed scope=none"));
}

#[test]
fn report_sanitizes_hostile_recorded_scope() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"hostile-scope","agent":"claude-code","harness":"pi",
                "enforcement":{"state":"active","scope":"../../escape","reason":"recorded"},
                "profile":"default","results":[]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("recorded: active scope=none"));
    assert!(!stdout.contains("escape"));
}

#[test]
fn report_omits_coverage_section_for_legacy_records() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"legacy-task","agent":"claude-code","profile":"default","results":[]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(!stdout.contains("Coverage ("));
}

#[test]
fn report_renders_all_persisted_coverage_statuses_and_nullable_fields() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-task","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"worker","status":"unverified","tool":"coverage.py","scope":"unit","line_percent":null,"branch_percent":null,"measured_at_ms":null},
                    {"workspace_id":"api","status":"passed","tool":"pytest","scope":"src","line_percent":91.5,"branch_percent":88.0,"measured_at_ms":12345},
                    {"workspace_id":"worker","status":"not_applicable","tool":null,"scope":null,"line_percent":null,"branch_percent":null,"measured_at_ms":null},
                    {"workspace_id":"api","status":"failed","tool":null,"scope":null,"line_percent":null,"branch_percent":null,"measured_at_ms":null}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (4):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        "- workspace=api status=failed tool=null scope=null line_percent=null branch_percent=null measured_at_ms=null\n- workspace=api status=passed tool=pytest scope=src line_percent=91.5 branch_percent=88 measured_at_ms=12345\n- workspace=worker status=not_applicable tool=null scope=null line_percent=null branch_percent=null measured_at_ms=null\n- workspace=worker status=unverified tool=coverage.py scope=unit line_percent=null branch_percent=null measured_at_ms=null\n"
    );
}

#[test]
fn report_sanitizes_and_bounds_hostile_coverage_text_and_tool_paths() {
    let repo = TempRepo::new();
    let hostile_workspace = format!(
        "workspace\u{0007}\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{2028}{}",
        "w".repeat(600)
    );
    let hostile_scope = format!("scope\u{000d}\u{2028}\u{2029}\u{2069}{}", "s".repeat(600));
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"hostile-coverage","agent":"claude-code","profile":"default","results":[],
                "coverage":[{
                    "workspace_id":hostile_workspace,
                    "status":"failed",
                    "tool":"/srv/private/coverage/bin/pytest\u{202e}",
                    "scope":hostile_scope,
                    "line_percent":10.5,
                    "branch_percent":null,
                    "measured_at_ms":1
                }]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (1):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    let expected_workspace = format!("workspace{}", "w".repeat(503));
    let expected_scope = format!("scope{}", "s".repeat(507));
    assert_eq!(expected_workspace.chars().count(), 512);
    assert_eq!(expected_scope.chars().count(), 512);
    assert_eq!(
        coverage,
        format!(
            "- workspace={} status=failed tool=pytest scope={} line_percent=10.5 branch_percent=null measured_at_ms=1\n",
            expected_workspace, expected_scope
        )
    );
    assert_eq!(coverage.lines().count(), 1);
    assert!(coverage.contains("tool=pytest"));
    assert!(!stdout.contains("/srv/private/coverage/bin"));
}

#[test]
fn report_hides_cross_platform_coverage_tool_parent_paths() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"windows-tool-path","agent":"claude-code","profile":"default","results":[],
                "coverage":[{
                    "workspace_id":"windows","status":"passed",
                    "tool":"C:\\srv\\private\\coverage\\bin\\pytest",
                    "scope":"unit","line_percent":80.0,"branch_percent":75.0,"measured_at_ms":1
                }]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (1):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        "- workspace=windows status=passed tool=pytest scope=unit line_percent=80 branch_percent=75 measured_at_ms=1\n"
    );
    assert!(!coverage.contains("C:"));
    assert!(!coverage.contains("private"));
}

#[test]
fn report_orders_coverage_by_rendered_projection_not_hidden_raw_text() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"rendered-projection-order","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"zulu","status":"passed","tool":"tool","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"\u{2066}alpha","status":"passed","tool":"tool","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"tool-order","status":"passed","tool":"/a/z-tool","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"tool-order","status":"passed","tool":"/z/a-tool","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"scope-order","status":"passed","tool":"tool","scope":"z-scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"scope-order","status":"passed","tool":"tool","scope":"\u{2066}alpha-scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"null-order","status":"passed","tool":"null","scope":"a-scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1},
                    {"workspace_id":"null-order","status":"passed","tool":null,"scope":"z-scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (8):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=alpha status=passed tool=tool scope=scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=null-order status=passed tool=null scope=a-scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=null-order status=passed tool=null scope=z-scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=scope-order status=passed tool=tool scope=alpha-scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=scope-order status=passed tool=tool scope=z-scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=tool-order status=passed tool=a-tool scope=scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=tool-order status=passed tool=z-tool scope=scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=zulu status=passed tool=tool scope=scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
        )
    );
}

#[test]
fn report_emits_bounded_terminal_safe_schema_diagnostics_without_echoing_coverage_text() {
    let repo = TempRepo::new();
    let mut hostile_coverage = json!({
        "workspace_id":"hostile-workspace","status":"passed","tool":null,"scope":null,
        "line_percent":null,"branch_percent":null,"measured_at_ms":null
    });
    let hostile_key = format!(
        "attacker-field-\n\r\u{001b}[31msecret-marker-{}",
        "x".repeat(4096)
    );
    hostile_coverage
        .as_object_mut()
        .expect("coverage object")
        .insert(hostile_key, json!("attacker-value"));
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n{}\n",
            json!({
                "task_id":"diagnostic-first","agent":"claude-code","profile":"default","results":[]
            }),
            json!({
                "task_id":"diagnostic-hostile","agent":"claude-code","profile":"default","results":[],
                "coverage":[hostile_coverage]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(stderr.contains("malformed evidence line 2 (evidence schema mismatch at column "));
    assert!(!stderr.contains("secret-marker"));
    assert!(!stderr.contains("attacker-field"));
    assert!(stderr.ends_with('\n'));
    assert!(
        stderr[..stderr.len() - 1]
            .bytes()
            .all(|byte| !byte.is_ascii_control())
    );
    assert!(
        stderr.len() <= 256,
        "diagnostic must remain bounded: {stderr}"
    );
}

#[test]
fn report_encodes_coverage_token_separators_without_injecting_fields() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-token-separators","agent":"claude-code","profile":"default","results":[],
                "coverage":[{
                    "workspace_id":"workspace value=part","status":"passed",
                    "tool":"/private/tool value=part","scope":"scope value=part=two",
                    "line_percent":12.5,"branch_percent":null,"measured_at_ms":7
                }]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (1):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    let row = coverage.lines().next().expect("coverage row");
    let tokens: Vec<_> = row.trim_start_matches("- ").split_whitespace().collect();
    assert_eq!(tokens.len(), 7);
    assert_eq!(
        tokens,
        [
            "workspace=workspace_value_part",
            "status=passed",
            "tool=tool_value_part",
            "scope=scope_value_part_two",
            "line_percent=12.5",
            "branch_percent=null",
            "measured_at_ms=7",
        ]
    );
    assert!(tokens.iter().all(|token| token.matches('=').count() == 1));
}

#[test]
fn report_redacts_default_ignorable_or_whitespace_only_coverage_workspaces() {
    let repo = TempRepo::new();
    let default_ignorable_and_whitespace = concat!(
        "\u{00ad}\u{034f}\u{061c}",
        "\u{115f}\u{1160}\u{17b4}\u{17b5}",
        "\u{180b}\u{180f}\u{200b}\u{200f}",
        "\u{202a}\u{202e}\u{2060}\u{206f}",
        "\u{3164}\u{fe00}\u{fe0f}\u{feff}",
        "\u{ffa0}\u{fff0}\u{fff8}",
        "\u{1bca0}\u{1bca3}\u{1d173}\u{1d17a}",
        "\u{e0000}\u{e0fff} \u{2003}\t\n",
    );
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"default-ignorable-workspace","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":default_ignorable_and_whitespace,"status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":1},
                    {"workspace_id":"\u{200b}\u{feff}\u{00ad}\u{2003}","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":2}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (2):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(coverage.matches("workspace=redacted-workspace").count(), 2);
    assert!(!coverage.contains("workspace=__"));
}

#[test]
fn report_strips_windows_drive_relative_coverage_tool_prefix_cross_platform() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"drive-relative-tool","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"drive","status":"passed","tool":"C:","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":3},
                    {"workspace_id":"drive","status":"passed","tool":"d:coverage.exe","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":2},
                    {"workspace_id":"drive","status":"passed","tool":"C:pytest","scope":"scope","line_percent":1.0,"branch_percent":1.0,"measured_at_ms":1}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (3):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=drive status=passed tool=coverage.exe scope=scope line_percent=1 branch_percent=1 measured_at_ms=2\n",
            "- workspace=drive status=passed tool=pytest scope=scope line_percent=1 branch_percent=1 measured_at_ms=1\n",
            "- workspace=drive status=passed tool=tool scope=scope line_percent=1 branch_percent=1 measured_at_ms=3\n",
        )
    );
}

#[test]
fn report_rejects_schema_invalid_coverage_values() {
    let cases = [
        (
            "invalid status",
            json!({
                "workspace_id":"workspace","status":"invalid","tool":null,"scope":null,
                "line_percent":null,"branch_percent":null,"measured_at_ms":null
            }),
            "evidence schema mismatch at column",
        ),
        (
            "empty workspace_id",
            json!({
                "workspace_id":"","status":"passed","tool":null,"scope":null,
                "line_percent":null,"branch_percent":null,"measured_at_ms":null
            }),
            "coverage workspace_id must not be empty",
        ),
        (
            "line below lower bound",
            json!({
                "workspace_id":"workspace","status":"passed","tool":null,"scope":null,
                "line_percent":-0.1,"branch_percent":null,"measured_at_ms":null
            }),
            "coverage line_percent must be finite and between 0 and 100",
        ),
        (
            "line above upper bound",
            json!({
                "workspace_id":"workspace","status":"passed","tool":null,"scope":null,
                "line_percent":100.1,"branch_percent":null,"measured_at_ms":null
            }),
            "coverage line_percent must be finite and between 0 and 100",
        ),
        (
            "branch below lower bound",
            json!({
                "workspace_id":"workspace","status":"passed","tool":null,"scope":null,
                "line_percent":null,"branch_percent":-0.1,"measured_at_ms":null
            }),
            "coverage branch_percent must be finite and between 0 and 100",
        ),
        (
            "branch above upper bound",
            json!({
                "workspace_id":"workspace","status":"passed","tool":null,"scope":null,
                "line_percent":null,"branch_percent":100.1,"measured_at_ms":null
            }),
            "coverage branch_percent must be finite and between 0 and 100",
        ),
    ];

    for (label, coverage, expected_error) in cases {
        let repo = TempRepo::new();
        repo.write(
            ".lgtm/evidence/evidence.jsonl",
            &format!(
                "{}\n",
                json!({
                    "task_id":"invalid-coverage","agent":"claude-code","profile":"default","results":[],
                    "coverage":[coverage]
                })
            ),
        );
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["report", "--evidence"])
            .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
            .output()
            .expect("report runs");
        assert!(!output.status.success(), "{label} coverage must fail");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
        assert!(
            stderr.contains("malformed evidence line 1"),
            "{label} should identify malformed evidence: {stderr}"
        );
        assert!(
            stderr.contains(expected_error),
            "{label} should explain the invalid value: {stderr}"
        );
    }
}

#[test]
fn report_rejects_coverage_rows_missing_required_nullable_fields_and_unknown_properties() {
    let base_coverage = json!({
        "workspace_id":"workspace","status":"passed","tool":null,"scope":null,
        "line_percent":null,"branch_percent":null,"measured_at_ms":null
    });
    let run_report = |coverage: serde_json::Value| {
        let repo = TempRepo::new();
        repo.write(
            ".lgtm/evidence/evidence.jsonl",
            &format!(
                "{}\n",
                json!({
                    "task_id":"invalid-coverage-shape","agent":"claude-code","profile":"default","results":[],
                    "coverage":[coverage]
                })
            ),
        );
        Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["report", "--evidence"])
            .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
            .output()
            .expect("report runs")
    };

    for field in [
        "tool",
        "scope",
        "line_percent",
        "branch_percent",
        "measured_at_ms",
    ] {
        let mut coverage = base_coverage.clone();
        coverage
            .as_object_mut()
            .expect("coverage object")
            .remove(field);
        let output = run_report(coverage);
        assert!(!output.status.success(), "missing {field} must fail");
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
        assert!(
            stderr.contains("malformed evidence line 1"),
            "missing {field} should identify malformed evidence: {stderr}"
        );
        let expected_error = "evidence schema mismatch at column";
        assert!(
            stderr.contains(expected_error),
            "missing {field} should explain the missing field: {stderr}"
        );
    }

    let mut unknown_coverage = base_coverage;
    unknown_coverage
        .as_object_mut()
        .expect("coverage object")
        .insert("unexpected".to_string(), json!("value"));
    let output = run_report(unknown_coverage);
    assert!(
        !output.status.success(),
        "unknown coverage properties must fail"
    );
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(
        stderr.contains("malformed evidence line 1"),
        "unknown properties should identify malformed evidence: {stderr}"
    );
    assert!(
        stderr.contains("evidence schema mismatch at column"),
        "unknown properties should use the fixed schema diagnostic: {stderr}"
    );
}

#[test]
fn report_accepts_optional_coverage_provenance_without_rendering_it() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-provenance","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"a-provenance","status":"passed","tool":"pytest","scope":"unit","line_percent":75.0,"branch_percent":62.5,"measured_at_ms":42,"cwd":"/srv/private/project","cwd_identity":"device:inode-private"},
                    {"workspace_id":"b-provenance","status":"passed","tool":"pytest","scope":"unit","line_percent":75.0,"branch_percent":62.5,"measured_at_ms":42,"cwd":null,"cwd_identity":null},
                    {"workspace_id":"c-provenance","status":"passed","tool":"pytest","scope":"unit","line_percent":75.0,"branch_percent":62.5,"measured_at_ms":42}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (3):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=a-provenance status=passed tool=pytest scope=unit line_percent=75 branch_percent=62.5 measured_at_ms=42\n",
            "- workspace=b-provenance status=passed tool=pytest scope=unit line_percent=75 branch_percent=62.5 measured_at_ms=42\n",
            "- workspace=c-provenance status=passed tool=pytest scope=unit line_percent=75 branch_percent=62.5 measured_at_ms=42\n",
        )
    );
    assert!(!stdout.contains("/srv/private/project"));
    assert!(!stdout.contains("device:inode-private"));
    assert!(!coverage.contains("cwd="));
    assert!(!coverage.contains("cwd_identity="));
}

#[test]
fn report_orders_coverage_by_status_when_other_fields_match() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-status-order","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"same","status":"unverified","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"not_applicable","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"failed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (4):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=same status=failed tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=not_applicable tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=unverified tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
        )
    );
}

#[test]
fn report_accepts_exact_coverage_percentage_endpoints() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-endpoints","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"endpoints","status":"passed","tool":"tool","scope":"scope","line_percent":100.0,"branch_percent":0.0,"measured_at_ms":1},
                    {"workspace_id":"endpoints","status":"passed","tool":"tool","scope":"scope","line_percent":0.0,"branch_percent":100.0,"measured_at_ms":2}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (2):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=endpoints status=passed tool=tool scope=scope line_percent=0 branch_percent=100 measured_at_ms=2\n",
            "- workspace=endpoints status=passed tool=tool scope=scope line_percent=100 branch_percent=0 measured_at_ms=1\n",
        )
    );
}

#[test]
fn report_marks_workspace_redacted_when_sanitization_erases_it() {
    let repo = TempRepo::new();
    let erased_workspace = "\u{061c}\u{200e}\u{200f}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}\u{2028}";
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"redacted-workspace","agent":"claude-code","profile":"default","results":[],
                "coverage":[{
                    "workspace_id":erased_workspace,"status":"passed","tool":"tool","scope":"scope",
                    "line_percent":50.0,"branch_percent":50.0,"measured_at_ms":1
                }]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (1):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        "- workspace=redacted-workspace status=passed tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=1\n"
    );
    assert!(!coverage.contains("workspace= status="));
}

#[test]
fn report_orders_coverage_by_every_canonical_tiebreaker() {
    let repo = TempRepo::new();
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"coverage-order","agent":"claude-code","profile":"default","results":[],
                "coverage":[
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":2},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":1},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":10.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":50.0,"branch_percent":2.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":10.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"scope","line_percent":2.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"beta","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"tool","scope":"alpha","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"beta-tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9},
                    {"workspace_id":"same","status":"passed","tool":"alpha-tool","scope":"scope","line_percent":50.0,"branch_percent":50.0,"measured_at_ms":9}
                ]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let coverage = stdout
        .split_once("Coverage (10):\n")
        .expect("coverage heading")
        .1
        .split_once("Commands (0):\n")
        .expect("commands heading")
        .0;
    assert_eq!(
        coverage,
        concat!(
            "- workspace=same status=passed tool=alpha-tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=beta-tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=alpha line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=beta line_percent=50 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=2 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=10 branch_percent=50 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=50 branch_percent=2 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=50 branch_percent=10 measured_at_ms=9\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=1\n",
            "- workspace=same status=passed tool=tool scope=scope line_percent=50 branch_percent=50 measured_at_ms=2\n",
        )
    );
}

#[test]
fn malformed_evidence_fails_clearly() {
    let repo = TempRepo::new();
    repo.write("bad.jsonl", "not-json\n");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence", "bad.jsonl"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("malformed evidence line 1")
    );
}

#[test]
fn report_does_not_use_current_repository_for_external_evidence() {
    let evidence_repo = TempRepo::new();
    let current_repo = TempRepo::new();
    evidence_repo.write(
        "evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"session-b",
                "agent":"claude-code",
                "harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"recorded"},
                "profile":"default",
                "results":[]
            })
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(evidence_repo.path().join("evidence.jsonl"))
        .current_dir(current_repo.path())
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("current: unavailable"));
    assert!(stdout.contains("recorded-only"));
    assert!(!stdout.contains("Pi installation current: active"));
}

#[cfg(unix)]
#[test]
fn report_rejects_symlinked_evidence_ancestry_for_current_state() {
    use std::os::unix::fs::symlink;

    let target = TempRepo::new();
    target.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({
                "task_id":"symlinked",
                "agent":"claude-code",
                "harness":"pi",
                "enforcement":{"state":"active","scope":"project","reason":"recorded"},
                "profile":"default",
                "results":[]
            })
        ),
    );
    let alias = TempRepo::new();
    symlink(target.path().join(".lgtm"), alias.path().join(".lgtm"))
        .expect("symlink lgtm directory");
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(alias.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("current: unavailable"));
    assert!(stdout.contains("recorded-only"));
}

#[test]
fn report_dedupes_absolute_and_relative_repo_paths() {
    let repo = TempRepo::new();
    let absolute = repo.path().join("src/app.py");
    let outside = std::env::temp_dir().join("outside-report.py");
    let results = [
        json!({"rule_id":"one","status":"passed","severity":"error","message":"ok","locations":[{"file":"src/app.py"}],"evidence":{"check":"x"}}),
        json!({"rule_id":"two","status":"passed","severity":"error","message":"ok","locations":[{"file":absolute},{"file":outside}],"evidence":{"check":"x"}}),
    ];
    repo.write(
        ".lgtm/evidence/evidence.jsonl",
        &format!(
            "{}\n",
            json!({"task_id":"paths","agent":"claude-code","profile":"default","results":results})
        ),
    );
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["report", "--evidence"])
        .arg(repo.path().join(".lgtm/evidence/evidence.jsonl"))
        .output()
        .expect("report runs");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("Files changed (2):"));
    assert_eq!(stdout.matches("- src/app.py").count(), 1);
    assert!(stdout.contains(&outside.to_string_lossy().to_string()));
}
