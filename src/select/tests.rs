use std::collections::BTreeMap;
use std::path::Path;

use super::*;
use crate::context;
use crate::policy::load_embedded_registry;

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python")
}

#[test]
fn fastapi_postgres_change_selects_required_backend_rules() {
    let files = vec![
        "src/routes/events.py".to_string(),
        "src/services/store.py".to_string(),
    ];
    let diff = "+ session.execute('INSERT INTO events')\n+ requests.post(url)\n";
    let context = context::build(&fixture_root(), &files, diff);
    let mut registry = load_embedded_registry().expect("embedded registry valid");
    let source = registry
        .iter()
        .find(|rule| rule.id == "external-call-timeout")
        .expect("seed timeout rule")
        .clone();
    for (id, language, domain, pattern, signal) in [
        (
            "public-input-validation",
            "python",
            "api",
            "**/*.py",
            "public-api",
        ),
        (
            "sql-parameterization",
            "python",
            "database",
            "**/*.py",
            "database-write",
        ),
        (
            "structured-error-handling",
            "python",
            "api",
            "**/*.py",
            "public-api",
        ),
        (
            "regression-test-required",
            "python",
            "database",
            "**/*.py",
            "database-write",
        ),
        (
            "react-component-rule",
            "typescript",
            "frontend",
            "**/*.tsx",
            "public-api",
        ),
        ("rust-handler-rule", "rust", "api", "**/*.rs", "public-api"),
        (
            "terraform-resource-rule",
            "terraform",
            "infrastructure",
            "**/*.tf",
            "public-api",
        ),
    ] {
        let mut rule = source.clone();
        rule.id = id.to_string();
        rule.applies_to.languages = vec![language.to_string()];
        rule.applies_to.domains = vec![domain.to_string()];
        rule.applies_to.file_patterns = vec![pattern.to_string()];
        rule.activation.signals = vec![signal.to_string()];
        registry.push(rule);
    }
    let ids: Vec<_> = select_rules(&context, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();

    for expected in [
        "external-call-timeout",
        "public-input-validation",
        "regression-test-required",
        "sql-parameterization",
        "structured-error-handling",
    ] {
        assert!(ids.contains(&expected), "missing selected rule {expected}");
    }
    assert!(ids.iter().all(|id| !id.contains("react")));
    assert!(ids.iter().all(|id| !id.contains("rust")));
    assert!(ids.iter().all(|id| !id.contains("terraform")));
}

#[test]
fn scope_requires_each_constrained_dimension_to_match() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    let source = registry.first().expect("seed rule");
    let mut excluded = source.clone();
    excluded.id = "react-only-test-rule".to_string();
    excluded.applies_to.languages = vec!["typescript".to_string()];
    let context = context::build(&fixture_root(), &["src/routes/events.py".to_string()], "");
    assert!(select_rules(&context, &[excluded], ChangeType::Modify).is_empty());
}

#[test]
fn glob_matching_respects_directory_boundaries() {
    assert!(glob_matches("**/*.py", "src/routes/events.py"));
    assert!(glob_matches("**/*.py", "main.py"));
    assert!(!glob_matches("**/*.py", "src/routes/events.rs"));
    assert!(!glob_matches("src/*.py", "src/routes/events.py"));
    assert!(glob_matches("**/*", "src/routes/events.py"));
}

#[test]
fn empty_filters_match_all_and_results_are_id_sorted() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    let mut later = registry.first().expect("seed rule").clone();
    later.id = "z-rule".to_string();
    later.applies_to.languages.clear();
    later.applies_to.domains.clear();
    later.applies_to.file_patterns.clear();
    later.activation.change_types.clear();
    later.activation.signals.clear();
    let mut earlier = later.clone();
    earlier.id = "a-rule".to_string();
    let context = TaskContext {
        languages: Vec::new(),
        domains: Vec::new(),
        files_touched: Vec::new(),
        risk_signals: Vec::new(),
        repository_commands: BTreeMap::new(),
    };

    let rules = [later, earlier];
    let selected = select_rules(&context, &rules, ChangeType::Delete);
    let ids: Vec<_> = selected.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(ids, ["a-rule", "z-rule"]);
}

#[test]
fn constrained_activation_requires_change_type_and_signal() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    let mut rule = registry.first().expect("seed rule").clone();
    rule.applies_to.languages.clear();
    rule.applies_to.domains.clear();
    rule.applies_to.file_patterns.clear();
    rule.activation.change_types = vec![ChangeType::Create];
    rule.activation.signals = vec!["credential".to_string()];
    let mut context = TaskContext {
        languages: Vec::new(),
        domains: Vec::new(),
        files_touched: Vec::new(),
        risk_signals: Vec::new(),
        repository_commands: BTreeMap::new(),
    };

    assert!(select_rules(&context, &[rule.clone()], ChangeType::Create).is_empty());
    context.risk_signals.push("credential".to_string());
    assert!(select_rules(&context, &[rule.clone()], ChangeType::Modify).is_empty());
    assert_eq!(select_rules(&context, &[rule], ChangeType::Create).len(), 1);
}

#[test]
fn semgrep_policy_rules_activate_for_representative_python_change() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/semgrep-python");
    let files = vec!["violations.py".to_string()];
    let diff = std::fs::read_to_string(root.join("violations.py")).expect("fixture readable");
    let context = context::build(&root, &files, &diff);
    let registry = load_embedded_registry().expect("embedded registry valid");
    let ids: Vec<_> = select_rules(&context, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();

    for expected in [
        "external-call-timeout",
        "public-input-validation",
        "sql-parameterization",
        "bounded-retries-loops",
        "destructive-operation-safeguards",
    ] {
        assert!(ids.contains(&expected), "missing selected rule {expected}");
    }
}
