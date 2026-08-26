use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::context;
use crate::policy::load_embedded_registry;

static NEXT_METADATA_FREE_ROOT: AtomicU64 = AtomicU64::new(0);

struct MetadataFreeRoot(PathBuf);

impl MetadataFreeRoot {
    fn new() -> Self {
        Self::new_in(&std::env::temp_dir(), &NEXT_METADATA_FREE_ROOT)
    }

    fn new_in(base: &Path, counter: &AtomicU64) -> Self {
        for _ in 0..64 {
            let unique = counter.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "lgtm-select-path-signals-{}-{unique}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("metadata-free root should be creatable: {error}"),
            }
        }
        panic!("metadata-free root exhausted unique candidates");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for MetadataFreeRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python")
}

#[test]
fn metadata_free_root_atomically_creates_a_process_local_unique_root_and_cannot_reuse_existing_contents()
 {
    let (first_path, second_path);
    {
        let first = MetadataFreeRoot::new();
        let marker = first.path().join("pre-existing-marker");
        std::fs::write(&marker, "contaminated").expect("marker should be writable");

        let second = MetadataFreeRoot::new();
        first_path = first.path().to_path_buf();
        second_path = second.path().to_path_buf();

        assert_ne!(first_path, second_path);
        assert!(marker.is_file(), "the first root must remain untouched");
        assert!(!second.path().join("pre-existing-marker").exists());
    }

    assert!(
        !first_path.exists(),
        "first root should be cleaned up on drop"
    );
    assert!(
        !second_path.exists(),
        "second root should be cleaned up on drop"
    );
}

#[test]
fn metadata_free_root_skips_preexisting_candidates_and_cleans_created_root() {
    let base_path;
    {
        let base = MetadataFreeRoot::new();
        base_path = base.path().to_path_buf();
        let counter = AtomicU64::new(0);
        let stale = base
            .path()
            .join(format!("lgtm-select-path-signals-{}-0", std::process::id()));
        std::fs::create_dir(&stale).expect("stale candidate should be creatable");
        let marker = stale.join("pre-existing-marker");
        std::fs::write(&marker, "stale").expect("stale marker should be writable");

        let created = MetadataFreeRoot::new_in(base.path(), &counter);
        let created_path = created.path().to_path_buf();
        assert_ne!(created_path, stale);
        assert!(marker.is_file(), "stale candidate must remain untouched");
        drop(created);
        assert!(
            !created_path.exists(),
            "created root should be cleaned up on drop"
        );
        assert!(marker.is_file(), "stale marker must survive cleanup");
    }
    assert!(
        !base_path.exists(),
        "stale-root parent should be cleaned up on drop"
    );
}

#[test]
fn path_signal_context_drives_independent_selection_and_explain_outcomes() {
    let root = MetadataFreeRoot::new();
    let registry = load_embedded_registry().expect("embedded registry valid");
    let mut rule = registry.first().expect("seed rule").clone();
    rule.id = "root-route-auth-boundary-rule".to_string();
    rule.applies_to.languages = vec!["python".to_string()];
    rule.applies_to.domains = vec!["api".to_string()];
    rule.applies_to.file_patterns = vec!["**/*.py".to_string()];
    rule.activation.change_types = vec![ChangeType::Modify];
    rule.activation.signals = vec!["authentication".to_string()];

    #[derive(Clone, Copy)]
    struct SelectionCase {
        path: &'static str,
        expected_domains: &'static [&'static str],
        expected_risks: &'static [&'static str],
        expected_selected: bool,
        expected_reason: &'static str,
    }

    let cases = [
        SelectionCase {
            path: "routes/auth.py",
            expected_domains: &["api"],
            expected_risks: &["authentication"],
            expected_selected: true,
            expected_reason: "all scope and activation conditions matched",
        },
        SelectionCase {
            path: "auth.py",
            expected_domains: &[],
            expected_risks: &["authentication"],
            expected_selected: false,
            expected_reason: "domain scope did not match",
        },
        SelectionCase {
            path: "routes/handler.py",
            expected_domains: &["api"],
            expected_risks: &[],
            expected_selected: false,
            expected_reason: "activation signal did not match",
        },
        SelectionCase {
            path: "routes2/auth.py",
            expected_domains: &[],
            expected_risks: &["authentication"],
            expected_selected: false,
            expected_reason: "domain scope did not match",
        },
        SelectionCase {
            path: "myroutes/auth.py",
            expected_domains: &[],
            expected_risks: &["authentication"],
            expected_selected: false,
            expected_reason: "domain scope did not match",
        },
        SelectionCase {
            path: "routes/author.py",
            expected_domains: &["api"],
            expected_risks: &[],
            expected_selected: false,
            expected_reason: "activation signal did not match",
        },
    ];

    for SelectionCase {
        path,
        expected_domains,
        expected_risks,
        expected_selected,
        expected_reason,
    } in cases
    {
        let task_context = context::build(root.path(), &[path.to_string()], "");
        assert_eq!(
            task_context.languages,
            ["python"],
            "unexpected languages for path: {path}"
        );
        assert_eq!(
            task_context.domains,
            expected_domains
                .iter()
                .map(|domain| (*domain).to_string())
                .collect::<Vec<_>>(),
            "unexpected domains for path: {path}"
        );
        assert_eq!(
            task_context.risk_signals,
            expected_risks
                .iter()
                .map(|risk| (*risk).to_string())
                .collect::<Vec<_>>(),
            "unexpected risks for path: {path}"
        );

        let rules = [rule.clone()];
        let selected_ids: Vec<_> = select_rules(&task_context, &rules, ChangeType::Modify)
            .iter()
            .map(|selected| selected.id.as_str())
            .collect();
        if expected_selected {
            assert_eq!(
                selected_ids,
                ["root-route-auth-boundary-rule"],
                "unexpected selection for path: {path}"
            );
        } else {
            assert!(
                selected_ids.is_empty(),
                "unexpected selection for path: {path}"
            );
        }

        let decisions = explain_rules(&task_context, &rules, ChangeType::Modify);
        assert_eq!(
            decisions.len(),
            1,
            "unexpected decision count for path: {path}"
        );
        let decision = &decisions[0];
        assert_eq!(decision.selected, expected_selected, "path: {path}");
        assert_eq!(decision.reason, expected_reason, "path: {path}");
    }
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
fn glob_matching_supports_brace_alternation() {
    assert!(glob_matches("**/*.{rs,py}", "src/main.rs"));
    assert!(glob_matches("**/*.{rs,py}", "src/main.py"));
    assert!(glob_matches("**/*.{rs,{py,js}}", "src/main.js"));
    assert!(glob_matches("file,name.md", "file,name.md"));
    assert!(!glob_matches("**/*.{rs,py}", "src/main.md"));
    assert!(!glob_matches("**/*.{rs,py", "src/main.rs"));
}

#[test]
fn glob_matching_many_brace_groups_does_not_materialize_combinations() {
    let pattern = "{a,b}".repeat(32);

    assert!(!glob_matches(&pattern, &"c".repeat(32)));
    assert!(glob_matches(&pattern, &"b".repeat(32)));
}

#[test]
fn unsupported_glob_constructs_never_match() {
    assert!(!file_pattern_matches("**/*.[rs]", "src/main.rs"));
    assert!(!file_pattern_is_supported("**/*.[rs]"));
    assert!(file_pattern_is_supported("**/*.{rs,py}"));
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

#[test]
fn endpoint_security_consumers_use_produced_canonical_signals() {
    let root = fixture_root();
    let context = context::build(
        &root,
        &["src/routes/signals.py".to_string()],
        "+@router.post(\"/items\")\n+jwt.decode(token)\n+request.get_json()\n",
    );
    assert!(context.risk_signals.contains(&"authentication".to_string()));
    assert!(context.risk_signals.contains(&"public-api".to_string()));
    assert!(context.risk_signals.contains(&"public-input".to_string()));

    let registry = load_embedded_registry().expect("embedded registry valid");
    let expected = [
        (
            "endpoint-controls-review",
            vec!["public-api".to_string(), "authentication".to_string()],
        ),
        (
            "auth-input-enforcement",
            vec![
                "public-api".to_string(),
                "authentication".to_string(),
                "public-input".to_string(),
            ],
        ),
        ("public-endpoint-review", vec!["public-api".to_string()]),
        (
            "safe-construction-review",
            vec![
                "shell".to_string(),
                "html".to_string(),
                "url".to_string(),
                "json".to_string(),
                "regex".to_string(),
                "sql".to_string(),
                "public-input".to_string(),
            ],
        ),
    ];
    for (id, signals) in expected {
        let rule = registry
            .iter()
            .find(|rule| rule.id == id)
            .unwrap_or_else(|| panic!("missing endpoint security rule {id}"));
        assert_eq!(
            rule.activation.signals, signals,
            "unexpected signals for {id}"
        );
        for legacy in ["endpoint", "route", "api", "public", "auth", "input"] {
            assert!(
                !rule
                    .activation
                    .signals
                    .iter()
                    .any(|signal| signal == legacy),
                "legacy signal {legacy} remains in {id}"
            );
        }
    }
}

#[test]
fn route_decorator_in_api_context_selects_all_endpoint_security_rules() {
    let context = context::build(
        &fixture_root(),
        &["src/api/handler.py".to_string()],
        "+@router.post(\"/items\")\n",
    );
    assert!(context.domains.contains(&"api".to_string()));
    assert!(context.risk_signals.contains(&"public-api".to_string()));
    assert!(!context.risk_signals.contains(&"authentication".to_string()));

    let registry = load_embedded_registry().expect("embedded registry valid");
    let ids: Vec<_> = select_rules(&context, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    for expected in [
        "endpoint-controls-review",
        "auth-input-enforcement",
        "public-endpoint-review",
    ] {
        assert!(ids.contains(&expected), "missing selected rule {expected}");
    }
}

#[test]
fn authentication_and_public_input_remain_meaningful_activation_signals() {
    let root = fixture_root();
    let authentication = context::build(
        &root,
        &["src/routes/auth_probe.py".to_string()],
        "+jwt.decode(token)\n",
    );
    let public_input = context::build(
        &root,
        &["src/routes/input_probe.py".to_string()],
        "+request.get_json()\n",
    );
    let registry = load_embedded_registry().expect("embedded registry valid");

    let authentication_ids: Vec<_> = select_rules(&authentication, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    for expected in ["endpoint-controls-review", "auth-input-enforcement"] {
        assert!(
            authentication_ids.contains(&expected),
            "authentication missed {expected}"
        );
    }
    assert!(!authentication_ids.contains(&"public-endpoint-review"));

    let public_input_ids: Vec<_> = select_rules(&public_input, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    for expected in ["auth-input-enforcement", "safe-construction-review"] {
        assert!(
            public_input_ids.contains(&expected),
            "public-input missed {expected}"
        );
    }
    assert!(!public_input_ids.contains(&"endpoint-controls-review"));
    assert!(!public_input_ids.contains(&"public-endpoint-review"));
}
