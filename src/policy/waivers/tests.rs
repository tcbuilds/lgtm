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

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-waivers-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".lgtm")).expect("create temp root");
    root
}

fn write_store(root: &Path, waivers: &[Waiver]) {
    let store = Store {
        waivers: waivers.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&store).expect("serialize store");
    std::fs::write(root.join(".lgtm/waivers.json"), bytes).expect("write store");
}

#[test]
fn elapsed_expiry_does_not_invalidate_the_store() {
    let mut item = waiver();
    item.expires = "2000-01-01".to_string();
    let store = Store {
        waivers: vec![item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    validate_store(&store, &rules).expect("an elapsed expiry must not corrupt the store");
}

#[test]
fn load_active_drops_expired_waivers_and_keeps_current_ones() {
    let root = temp_root("mixed");
    let mut expired = waiver();
    expired.expires = "2000-01-01".to_string();
    let mut active = waiver();
    active.rule_id = "function-size".to_string();
    write_store(&root, &[expired, active]);
    let rules = super::super::load_embedded_registry().expect("registry");
    let loaded = load_active(&root, &rules).expect("an expired waiver must not fail the load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].rule_id, "function-size");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn store_still_rejects_malformed_expiry() {
    let mut item = waiver();
    item.expires = "not-a-date".to_string();
    let store = Store {
        waivers: vec![item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    assert!(validate_store(&store, &rules).is_err());
}

#[test]
fn creating_a_waiver_still_requires_a_future_expiry() {
    assert!(validate_future_date("2000-01-01").is_err());
    assert!(validate_future_date("2999-12-31").is_ok());
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
