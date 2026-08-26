use std::collections::BTreeSet;

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

fn path_observations(path: &str) -> (Vec<String>, Vec<String>) {
    let mut languages = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut risks = BTreeSet::new();
    super::signals::add_path_observations(path, &mut languages, &mut domains, &mut risks);
    (domains.into_iter().collect(), risks.into_iter().collect())
}

fn assert_empty_path_observations(path: &str) {
    let (domains, risks) = path_observations(path);
    assert!(domains.is_empty(), "unexpected domain for path: {path}");
    assert!(risks.is_empty(), "unexpected risk for path: {path}");
}

#[test]
fn directory_domain_signals_require_a_descendant_file() {
    for path in ["routes/handler.rs", "src/routes/handler.rs"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["api"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in ["api/handler.rs", "src/api/handler.rs"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["api"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in ["models/entity.rs", "src/models/entity.rs"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["database"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in ["migrations/001.rs", "src/migrations/001.rs"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["database"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in ["workers/job.rs", "src/workers/job.rs"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["worker"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in ["components/view.tsx", "src/components/view.tsx"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["frontend"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }

    let (domains, risks) = path_observations(".github/workflows/ci.yml");
    assert_eq!(domains, ["infrastructure"]);
    assert!(risks.is_empty());

    for path in [
        "terraform/main.tf",
        "src/terraform/main.tf",
        "terraform.tf",
        "src/terraform.tf",
    ] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["infrastructure"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }

    for path in [
        "routes",
        "src/routes",
        "api",
        "src/api",
        "models",
        "src/models",
        "migrations",
        "src/migrations",
        "workers",
        "src/workers",
        "components",
        "src/components",
        "src/routes2/handler.rs",
        "src/api2/handler.rs",
        "src/models2/entity.rs",
        "src/migrations2/001.rs",
        "src/workers2/job.rs",
        "src/components2/view.rs",
        "routes.py",
        "api.py",
        "models.py",
        "migrations.py",
        "workers.py",
        "components.py",
        "routes.v1/handler.rs",
        "src/routes.v1/handler.rs",
        "api.v1/handler.rs",
        "src/api.v1/handler.rs",
        "models.v1/entity.rs",
        "src/models.v1/entity.rs",
        "migrations.v1/001.rs",
        "src/migrations.v1/001.rs",
        "workers.v1/job.rs",
        "src/workers.v1/job.rs",
        "components.v1/view.rs",
        "src/components.v1/view.rs",
        "src/terraformer/main.tf",
        "src/terraformer.tf",
        "github/workflows/ci.yml",
        ".github2/workflows/ci.yml",
        ".github/workflows2/ci.yml",
        ".github/actions/workflows/ci.yml",
        ".github/workflows",
        "src/.github/workflows",
        "terraform.tf/main.rs",
        "src/terraform.tf/main.rs",
        "terraform.v1/main.rs",
        "src/terraform.v1/main.rs",
    ] {
        assert_empty_path_observations(path);
    }
}

#[test]
fn github_workflows_requires_workflows_to_be_a_directory() {
    for path in [
        ".github/workflows/ci.yml",
        "src/.github/workflows/ci.yml",
        ".github/.github/workflows/ci.yml",
    ] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["infrastructure"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }

    for path in [
        ".github/workflows",
        "src/.github/workflows",
        "github/workflows",
        ".github2/workflows",
        ".github/workflows2",
        ".github/actions/workflows",
        "github/workflows/ci.yml",
        ".github2/workflows/ci.yml",
        ".github/workflows2/ci.yml",
        ".github/actions/workflows/ci.yml",
    ] {
        assert_empty_path_observations(path);
    }
}

#[test]
fn path_security_observations_cover_complete_boundary_matrix() {
    for name in ["auth", "security", "permissions", "oauth"] {
        for path in [
            format!("{name}/handler.rs"),
            format!("src/{name}/handler.rs"),
            format!("{name}.rs"),
            format!("src/{name}.rs"),
        ] {
            let (domains, risks) = path_observations(&path);
            assert!(domains.is_empty(), "unexpected domain for path: {path}");
            assert_eq!(risks, ["authentication"], "path: {path}");
        }
    }

    for name in ["author", "security-tools", "permissions2", "oauth2"] {
        for path in [
            format!("{name}/handler.rs"),
            format!("src/{name}/handler.rs"),
            format!("{name}.rs"),
            format!("src/{name}.rs"),
        ] {
            assert_empty_path_observations(&path);
        }
    }
}

#[test]
fn exact_component_signals_cover_terminal_and_both_lookalike_sides() {
    for name in ["auth", "security", "permissions", "oauth"] {
        for path in [name.to_string(), format!("src/{name}")] {
            let (domains, risks) = path_observations(&path);
            assert!(domains.is_empty(), "unexpected domain for path: {path}");
            assert_eq!(risks, ["authentication"], "path: {path}");
        }

        for path in [
            format!("my{name}/handler.rs"),
            format!("src/my{name}/handler.rs"),
            format!("my{name}.rs"),
            format!("src/my{name}.rs"),
        ] {
            assert_empty_path_observations(&path);
        }
    }

    for path in ["terraform", "src/terraform"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["infrastructure"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }

    for path in [
        "myterraform/main.tf",
        "src/myterraform/main.tf",
        "myterraform.tf",
        "src/myterraform.tf",
        "myroutes/handler.rs",
        "src/myroutes/handler.rs",
        "myapi/handler.rs",
        "src/myapi/handler.rs",
        "mymodels/entity.rs",
        "src/mymodels/entity.rs",
        "mymigrations/001.rs",
        "src/mymigrations/001.rs",
        "myworkers/job.rs",
        "src/myworkers/job.rs",
        "mycomponents/view.tsx",
        "src/mycomponents/view.tsx",
        ".github/myworkflows/ci.yml",
        "src/.github/myworkflows/ci.yml",
        "x.github/workflows/ci.yml",
        "src/x.github/workflows/ci.yml",
    ] {
        assert_empty_path_observations(path);
    }
}

#[test]
fn filename_stems_split_at_the_last_dot() {
    for name in ["auth", "security", "permissions", "oauth"] {
        for path in [format!("{name}.py"), format!("src/{name}.py")] {
            let (domains, risks) = path_observations(&path);
            assert!(domains.is_empty(), "unexpected domain for path: {path}");
            assert_eq!(risks, ["authentication"], "path: {path}");
        }

        for suffix in ["py", "v1"] {
            for path in [
                format!("{name}.{suffix}/helpers.rs"),
                format!("src/{name}.{suffix}/helpers.rs"),
            ] {
                assert_empty_path_observations(&path);
            }
        }

        for path in [
            format!("{name}.feature.py"),
            format!("src/{name}.feature.py"),
        ] {
            assert_empty_path_observations(&path);
        }
    }

    for path in ["terraform.tf", "src/terraform.tf"] {
        let (domains, risks) = path_observations(path);
        assert_eq!(domains, ["infrastructure"], "path: {path}");
        assert!(risks.is_empty(), "unexpected risk for path: {path}");
    }
    for path in [
        "terraform.tf/main.rs",
        "src/terraform.tf/main.rs",
        "terraform.v1/main.rs",
        "src/terraform.v1/main.rs",
        "terraform.feature.tf",
        "src/terraform.feature.tf",
    ] {
        assert_empty_path_observations(path);
    }
}
