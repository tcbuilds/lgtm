use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

static COUNTER: AtomicU32 = AtomicU32::new(0);

#[test]
fn all_four_embedded_profiles_validate() {
    let rules = super::super::load_and_validate(super::super::RULES_JSON).expect("registry valid");
    for name in ["default", "strict", "prototype", "infrastructure"] {
        let resolved = resolve(name, &rules).expect("profile valid");
        assert_eq!(resolved.len(), rules.len());
    }
}

#[test]
fn strict_profile_changes_severity_and_required_evidence() {
    let rules = super::super::load_and_validate(super::super::RULES_JSON).expect("registry valid");
    let resolved = resolve("strict", &rules).expect("strict valid");
    let dependency = resolved
        .iter()
        .find(|rule| rule.id == "new-dependency-review")
        .expect("dependency rule");
    assert_eq!(dependency.severity, Severity::Error);
    assert_eq!(
        dependency.evidence.required,
        ["check_result", "review_result"]
    );
}

#[test]
fn prototype_keeps_security_and_destructive_rules_enforced() {
    let rules = super::super::load_and_validate(super::super::RULES_JSON).expect("registry valid");
    let resolved = resolve("prototype", &rules).expect("prototype valid");
    for id in [
        "no-committed-secrets",
        "sql-parameterization",
        "destructive-operation-safeguards",
    ] {
        let rule = resolved
            .iter()
            .find(|rule| rule.id == id)
            .expect("rule present");
        assert_eq!(rule.severity, Severity::Error, "{id} must remain enforced");
    }
    let tests = resolved
        .iter()
        .find(|rule| rule.id == "new-behavior-tests-required")
        .expect("test rule");
    assert_eq!(tests.severity, Severity::Warning);
}

#[test]
fn unknown_and_malformed_config_are_rejected() {
    assert!(validate_name("fast-and-loose").is_err());
    let root = std::env::temp_dir().join(format!(
        "lgtm-profile-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(root.join(".lgtm")).expect("config directory");
    std::fs::write(root.join(".lgtm/config.json"), r#"{"profile":42}"#).expect("config writable");
    assert!(
        load_name(&root)
            .expect_err("malformed profile rejected")
            .contains("malformed profile config")
    );
    std::fs::remove_dir_all(root).expect("temp root removable");
}
