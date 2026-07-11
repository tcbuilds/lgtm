use super::*;

fn waiver() -> Waiver {
    Waiver {
        rule_id: "no-broad-exception-handling".to_string(),
        reason: "legacy boundary".to_string(),
        owner: "platform".to_string(),
        expires: "2999-12-31".to_string(),
    }
}

fn result(status: Status, remediation: Option<&str>) -> EnforcementResult {
    EnforcementResult {
        rule_id: "no-broad-exception-handling".to_string(),
        status,
        severity: super::super::Severity::Error,
        message: "result".to_string(),
        locations: Vec::new(),
        remediation: remediation.map(str::to_string),
        evidence: crate::checks::ResultEvidence {
            check: "ruff.check".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

#[test]
fn active_waiver_marks_failure_and_clears_remediation() {
    let mut results = vec![result(Status::Failed, Some("fix"))];
    apply(&[waiver()], &mut results);
    assert_eq!(results[0].status, Status::Waived);
    assert!(results[0].remediation.is_none());
}

#[test]
fn active_waiver_does_not_hide_passing_check() {
    let mut results = vec![result(Status::Passed, None)];
    apply(&[waiver()], &mut results);
    assert_eq!(results[0].status, Status::Passed);
}

#[test]
fn calendar_validation_rejects_impossible_dates() {
    assert_eq!(parse_date("1970-01-01"), Ok(0));
    assert!(parse_date("2027-02-29").is_err());
    assert!(parse_date("2028-02-29").is_ok());
}

#[test]
fn store_rejects_duplicate_rule_entries() {
    let item = waiver();
    let store = Store {
        waivers: vec![item.clone(), item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    assert!(validate_store(&store, &rules).is_err());
}
