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
    assert_eq!(rules.as_array().expect("rule array").len(), 15);
    assert_eq!(rules[0]["id"], "no-committed-secrets");
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
