use super::*;

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context-python")
}

#[test]
fn derives_context_from_fixture_repo_and_diff() {
    let paths = vec![
        "src/routes/events.py".to_string(),
        "src/services/store.py".to_string(),
        "src/routes/events.py".to_string(),
    ];
    let diff = "+    session.commit()\n+    requests.post(url)\n";
    let context = build(&fixture_root(), &paths, diff);

    assert_eq!(context.languages, ["python"]);
    assert_eq!(context.domains, ["api", "database"]);
    assert_eq!(
        context.files_touched,
        ["src/routes/events.py", "src/services/store.py"]
    );
    assert_eq!(
        context.risk_signals,
        [
            "authentication",
            "database-client",
            "database-write",
            "http-client",
            "public-api"
        ]
    );
    assert_eq!(context.repository_commands["lint"], ["ruff check ."]);
    assert_eq!(context.repository_commands["types"], ["mypy --strict src"]);
    assert_eq!(context.repository_commands["tests"], ["pytest"]);
}

#[test]
fn real_emitted_context_validates_against_schema() {
    let context = build(
        &fixture_root(),
        &["src/routes/events.py".to_string()],
        "+requests.post(url)\n",
    );
    let schema = serde_json::from_str(TASK_CONTEXT_SCHEMA_JSON).expect("schema JSON valid");
    let artifact = serde_json::to_value(context).expect("context serializable");
    let validator = jsonschema::validator_for(&schema).expect("schema valid");
    let errors: Vec<_> = validator
        .iter_errors(&artifact)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "task context schema violations: {errors:?}"
    );
}

#[test]
fn rejects_hostile_paths_and_bounds_diff_without_panicking() {
    let huge_diff = format!("{}é", "x".repeat(MAX_DIFF_BYTES));
    let paths = vec![
        "../secret.py".to_string(),
        "..\\secret.py".to_string(),
        "/etc/passwd".to_string(),
        "C:\\Windows\\system.ini".to_string(),
        "src/routes/events.py".to_string(),
    ];
    let context = build(&fixture_root(), &paths, &huge_diff);
    assert_eq!(context.files_touched, ["src/routes/events.py"]);
}

#[test]
fn output_order_is_stable_across_input_order() {
    let first = vec!["z.rs".to_string(), "a.py".to_string()];
    let second = vec!["a.py".to_string(), "z.rs".to_string()];
    assert_eq!(
        build(&fixture_root(), &first, ""),
        build(&fixture_root(), &second, "")
    );
}

#[test]
fn derives_framework_domain_from_repository_metadata() {
    let context = build(&fixture_root(), &[], "");
    assert_eq!(context.domains, ["api"]);
}

#[test]
fn derives_exception_handler_signals_from_diff() {
    let context = build(
        &fixture_root(),
        &["src/services/store.py".to_string()],
        "+try:\n+    work()\n+except:\n+    pass\n",
    );

    assert!(context.risk_signals.contains(&"try-except".to_string()));
    assert!(context.risk_signals.contains(&"bare-except".to_string()));
}
