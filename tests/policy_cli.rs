use std::process::Command;

use serde_json::Value;

#[test]
fn policy_list_exposes_the_embedded_registry() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "list", "--json"])
        .output()
        .expect("policy list starts");
    assert!(output.status.success());
    let rules: Value = serde_json::from_slice(&output.stdout).expect("policy list is JSON");
    assert_eq!(rules.as_array().expect("rule array").len(), 49);
    assert_eq!(rules[0]["id"], "no-committed-secrets");
}

#[test]
fn policy_list_text_includes_capability_columns() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "list"])
        .output()
        .expect("policy list starts");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("MECHANISM\tCONFIDENCE\tSTAGE"));
    assert!(text.contains("no-committed-secrets\tmust\terror\tstatic\tnative\thigh"));
}

#[test]
fn policy_show_reports_unknown_rule_without_panicking() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "show", "not-a-rule"])
        .output()
        .expect("policy show starts");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown rule"));
}

#[test]
fn policy_show_text_exposes_examples_limitations_and_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "show", "external-call-timeout"])
        .output()
        .expect("policy show starts");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("mechanism: native"));
    assert!(
        text.contains("examples: good: satisfy External calls require timeouts; bad: bypass it")
    );
    assert!(text.contains("references: codingStandards.md#non-negotiable-rules"));
}

#[test]
fn policy_explain_is_read_only_and_reports_selection_reasons() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "explain", "--file", "src/main.rs", "--json"])
        .output()
        .expect("policy explain starts");
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).expect("explain is JSON");
    assert_eq!(report["file"], "src/main.rs");
    assert!(
        report["decisions"]
            .as_array()
            .expect("decisions")
            .iter()
            .all(|decision| {
                decision["reason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
            })
    );
    assert!(
        report["packet"]
            .as_str()
            .is_some_and(|packet| packet.contains("Verification required"))
    );
}

#[test]
fn policy_explain_covers_backend_frontend_rust_docs_and_unknown_files() {
    for file in [
        "tests/fixtures/context-fastapi/routes.py",
        "tests/fixtures/context-react/App.tsx",
        "tests/fixtures/context-rust/lib.rs",
        "codingStandards.md",
        "tests/fixtures/unknown-file.txt",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
            .args(["policy", "explain", "--file", file, "--json"])
            .output()
            .expect("policy explain starts");
        assert!(output.status.success(), "explain failed for {file}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("explain JSON");
        assert_eq!(report["file"], file);
        assert!(report["decisions"].is_array());
    }
}

#[test]
fn policy_examples_keeps_full_guidance_out_of_default_context() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args([
            "policy",
            "examples",
            "typescript-no-any",
            "--language",
            "typescript",
        ])
        .output()
        .expect("policy examples starts");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("language: typescript"));
    assert!(text.contains("good: use the supported pattern"));
    assert!(text.contains("limitations:"));
}

#[test]
fn policy_coverage_reports_every_normative_section() {
    let output = Command::new(env!("CARGO_BIN_EXE_lgtm"))
        .args(["policy", "coverage", "--json"])
        .output()
        .expect("policy coverage starts");
    assert!(output.status.success());
    let ledger: Value = serde_json::from_slice(&output.stdout).expect("coverage is JSON");
    let sections = ledger["sections"].as_array().expect("section array");
    assert_eq!(sections.len(), 33);
    assert!(sections.iter().any(|section| {
        section["heading"] == "Non-Negotiable Rules" && section["status"] == "partial"
    }));
}
