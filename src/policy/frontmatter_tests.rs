use super::*;

#[test]
fn malformed_frontmatter_has_a_specific_error() {
    let error = parse_file("fixture.md", "---\n{\n---\n# body").expect_err("must fail");
    assert!(matches!(error, FrontmatterError::Malformed { .. }));
    assert!(error.to_string().contains("fixture.md"));
}

#[test]
fn yaml_frontmatter_rejects_unknown_top_level_keys() {
    let contents = "---\npath:\n  - \"**/*.py\"\n---\n# body";
    let error = load_rule_files(&[("fixture.md", contents)]).expect_err("unknown key");
    assert!(error.to_string().contains("path"));
    assert!(error.to_string().contains("unknown frontmatter key"));
}

#[test]
fn duplicate_frontmatter_ids_have_both_paths() {
    let rule = load_registry().expect("embedded registry")[0].clone();
    let document = serde_json::to_string(&RuleFrontmatter {
        paths: Vec::new(),
        headings: Vec::new(),
        rules: vec![rule],
    })
    .expect("document JSON");
    let first = format!("---\n{document}\n---\nbody");
    let second = format!("---\n{document}\n---\nbody");
    let error = load_rule_files(&[("first.md", &first), ("second.md", &second)])
        .expect_err("duplicate must fail");
    assert!(error.to_string().contains("no-committed-secrets"));
    assert!(error.to_string().contains("first.md"));
    assert!(error.to_string().contains("second.md"));
}

#[test]
fn body_excludes_frontmatter_sentinel() {
    let body = body("---\n{\"sentinel\":\"hidden\"}\n---\n# body").expect("body");
    assert!(
        !body.contains("sentinel"),
        "frontmatter key `sentinel` leaked"
    );
    assert_eq!(body, "# body");
}

#[test]
fn crlf_frontmatter_delimiters_parse_rules() {
    let rule = load_registry().expect("embedded registry")[0].clone();
    let document = serde_json::json!({"rules": [rule.clone()]}).to_string();
    let fixture = format!("---\r\n{document}\r\n---\r\nbody");
    let rules = load_rule_files(&[("crlf-fixture.md", &fixture)]).expect("CRLF fixture");
    assert_eq!(rules, vec![rule]);
}

#[test]
fn embedded_rule_body_excludes_machine_fields() {
    let body = body(include_str!(
        "../../templates/claude-rules/rules/patterns/core.md"
    ))
    .expect("embedded rule body");
    assert!(
        !body.contains("no-committed-secrets"),
        "frontmatter id `no-committed-secrets` leaked"
    );
    assert!(
        !body.contains("\"overridable\""),
        "frontmatter key `overridable` leaked"
    );
    assert!(body.starts_with("# Core Patterns"));
}

#[test]
fn security_critical_overrides_remain_disabled() {
    let rules = load_registry().expect("embedded registry");
    for id in [
        "no-committed-secrets",
        "sql-parameterization",
        "destructive-operation-safeguards",
        "auth-change-security-review",
    ] {
        let rule = rules.iter().find(|rule| rule.id == id).expect("rule id");
        assert!(!rule.overridable, "{id} must remain non-overridable");
    }
}
