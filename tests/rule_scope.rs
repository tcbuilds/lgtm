use std::collections::BTreeMap;

use lgtm::context::TaskContext;
use lgtm::policy::frontmatter::{RULE_DOCUMENT_SOURCES, load_rule_files};
use lgtm::policy::{ChangeType, Rule, load_embedded_registry};
use lgtm::select::{file_pattern_is_supported, file_pattern_matches, select_rules};

/// Check that representative paths from every rule pattern are accepted by at
/// least one path pattern on the containing document.
pub fn patterns_cover(document_patterns: &[String], rule_pattern: &str) -> bool {
    let representatives = representative_paths(rule_pattern);
    !representatives.is_empty()
        && representatives.iter().all(|path| {
            document_patterns
                .iter()
                .any(|pattern| file_pattern_matches(pattern, path))
        })
}

/// Exercise root-level, nested, wildcard, and literal branches through the
/// production matcher instead of maintaining a second glob implementation.
fn representative_paths(pattern: &str) -> Vec<String> {
    const PREFIXES: &[&str] = &["", "src/", "src/nested/", "tests/", "src/tests/"];
    const FILES: &[&str] = &[
        "file.rs",
        "file.py",
        "file.pyi",
        "file.ts",
        "file.tsx",
        "file.js",
        "file.jsx",
        "file.mjs",
        "file.cjs",
        "file.go",
        "file.java",
        "file.kt",
        "file.kts",
        "file.cs",
        "file.c",
        "file.cc",
        "file.cpp",
        "file.cxx",
        "file.h",
        "file.hh",
        "file.hpp",
        "file.hxx",
        "file.sql",
        "file.sh",
        "file.bash",
        "file.zsh",
        "file.html",
        "file.htm",
        "file.css",
        "file.scss",
        "file.sass",
        "file.less",
        "file.tf",
        "file.tfvars",
        "file.rb",
        "file.swift",
        "file.scala",
        "file.yaml",
        "file.yml",
        "file.json",
        "file.toml",
        "file.ini",
        "file.env",
        "file.test.ts",
        "file.spec.tsx",
        "file_test.py",
        "test_file.py",
        "README.md",
        ".env.example",
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "pyproject.toml",
        "requirements.txt",
        "Gemfile",
        "Podfile",
        "Dockerfile",
        "Dockerfile.dev",
        "docker-compose.yml",
        "docker-compose.dev.yaml",
        "docs/file.md",
        "migrations/file.sql",
        "__tests__/file.ts",
        ".github/workflows/check.yml",
    ];

    PREFIXES
        .iter()
        .flat_map(|prefix| FILES.iter().map(move |file| format!("{prefix}{file}")))
        .filter(|path| file_pattern_matches(pattern, path))
        .collect()
}

/// Load only the rule records from documents whose native paths match a file.
fn native_rules_for_file(file: &str) -> Vec<Rule> {
    RULE_DOCUMENT_SOURCES
        .iter()
        .filter(|(_, contents)| {
            frontmatter_paths(contents)
                .iter()
                .any(|pattern| file_pattern_matches(pattern, file))
        })
        .flat_map(|(path, contents)| {
            load_rule_files(&[(*path, *contents)]).expect("embedded rule file parses")
        })
        .collect()
}

fn frontmatter_paths(contents: &str) -> Vec<String> {
    let Some(frontmatter) = contents.strip_prefix("---\n") else {
        return Vec::new();
    };
    let Some((frontmatter, _)) = frontmatter.split_once("\n---\n") else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    let mut reading = false;
    for line in frontmatter.lines() {
        let trimmed = line.trim();
        if trimmed == "paths:" {
            reading = true;
            continue;
        }
        if reading && !line.starts_with(' ') {
            break;
        }
        if reading && let Some(path) = trimmed.strip_prefix("- ") {
            paths.push(path.trim_matches('"').to_string());
        }
    }
    paths
}

#[test]
fn narrower_document_scope_does_not_cover_a_broader_rule_scope() {
    let document = ["**/tests/**".to_string()];
    assert!(!patterns_cover(&document, "**/*.py"));
}

#[test]
fn matching_document_scope_covers_a_rule_scope() {
    let document = ["**/*.{ts,tsx,js,jsx}".to_string()];
    assert!(patterns_cover(&document, "**/*.{ts,tsx,js,jsx}"));
}

/// Keep every native scanner's extension contract covered by its rule and document scopes.
fn scanned_extensions(check: &str) -> &'static [&'static str] {
    match check {
        "native.ui-review" => &["html", "htm", "tsx", "jsx", "css"],
        _ => &[],
    }
}

#[test]
fn every_scanned_extension_is_covered_by_guidance_scope() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    for rule in registry {
        let Some((document_path, document)) =
            RULE_DOCUMENT_SOURCES.iter().find(|(path, contents)| {
                load_rule_files(&[(*path, *contents)])
                    .expect("embedded rule file parses")
                    .iter()
                    .any(|candidate| candidate.id == rule.id)
            })
        else {
            continue;
        };
        let document_patterns = frontmatter_paths(document);
        for check in &rule.enforcement.checks {
            for extension in scanned_extensions(check) {
                let file = format!("src/file.{extension}");
                assert!(
                    rule.applies_to.file_patterns.is_empty()
                        || rule
                            .applies_to
                            .file_patterns
                            .iter()
                            .any(|pattern| file_pattern_matches(pattern, &file)),
                    "{} does not cover {file} scanned by {check}",
                    rule.id
                );
                assert!(
                    document_patterns
                        .iter()
                        .any(|pattern| file_pattern_matches(pattern, &file)),
                    "{document_path} does not cover {file} scanned by {check}"
                );
            }
        }
    }
}

#[test]
fn protected_rules_select_representative_production_scopes() {
    let cases = [
        (
            "no-committed-secrets",
            "src/main.rs",
            &["rust"][..],
            &["backend"][..],
            &["credential"][..],
        ),
        (
            "no-committed-secrets",
            ".env",
            &[][..],
            &["backend"][..],
            &["env-file"][..],
        ),
        (
            "no-committed-secrets",
            ".env.local",
            &[][..],
            &["backend"][..],
            &["env-file"][..],
        ),
        (
            "no-committed-secrets",
            "config/.env.local",
            &[][..],
            &["backend"][..],
            &["env-file"][..],
        ),
        (
            "no-committed-secrets",
            "services/api/.env.production",
            &[][..],
            &["backend"][..],
            &["env-file"][..],
        ),
        (
            "no-committed-secrets",
            "deploy/staging/.env",
            &[][..],
            &["backend"][..],
            &["env-file"][..],
        ),
        (
            "no-committed-secrets",
            "config/settings.yaml",
            &[][..],
            &["backend"][..],
            &["credential"][..],
        ),
        (
            "no-committed-secrets",
            "Dockerfile",
            &[][..],
            &["infrastructure"][..],
            &["credential"][..],
        ),
        (
            "sql-parameterization",
            "src/services/store.py",
            &["python"][..],
            &["backend"][..],
            &["database-write"][..],
        ),
        (
            "destructive-operation-safeguards",
            "src/cleanup.py",
            &["python"][..],
            &["backend"][..],
            &["destructive-operation"][..],
        ),
        (
            "auth-change-security-review",
            "src/auth.py",
            &["python"][..],
            &[][..],
            &["authentication"][..],
        ),
    ];

    for (rule_id, file, languages, domains, risk_signals) in cases {
        let context = TaskContext {
            languages: languages.iter().map(|value| (*value).to_string()).collect(),
            domains: domains.iter().map(|value| (*value).to_string()).collect(),
            files_touched: vec![file.to_string()],
            risk_signals: risk_signals
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            repository_commands: BTreeMap::new(),
        };
        let native_rules = native_rules_for_file(file);
        let selected: Vec<_> = select_rules(&context, &native_rules, ChangeType::Modify)
            .iter()
            .map(|rule| rule.id.as_str())
            .collect();
        assert!(
            selected.contains(&rule_id),
            "{rule_id} was not selected for {file}"
        );
    }
}

#[test]
fn production_selection_honors_brace_alternation_for_code_files() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    let expected = [
        "function-size",
        "file-size",
        "function-complexity",
        "module-boundary-review",
        "anti-slop-checklist",
        "auth-change-security-review",
    ];

    for (file, language) in [("src/main.rs", "rust"), ("src/main.py", "python")] {
        let context = TaskContext {
            languages: vec![language.to_string()],
            domains: Vec::new(),
            files_touched: vec![file.to_string()],
            risk_signals: vec!["authentication".to_string(), "module".to_string()],
            repository_commands: BTreeMap::new(),
        };
        let selected: Vec<_> = select_rules(&context, &registry, ChangeType::Modify)
            .iter()
            .map(|rule| rule.id.as_str())
            .collect();
        for rule_id in expected {
            assert!(selected.contains(&rule_id), "{file} missed {rule_id}");
        }
    }

    let markdown = TaskContext {
        languages: Vec::new(),
        domains: Vec::new(),
        files_touched: vec!["README.md".to_string()],
        risk_signals: vec!["authentication".to_string()],
        repository_commands: BTreeMap::new(),
    };
    let selected: Vec<_> = select_rules(&markdown, &registry, ChangeType::Modify)
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    for rule_id in expected {
        assert!(!selected.contains(&rule_id), "README.md selected {rule_id}");
    }
}

#[test]
fn every_registry_file_pattern_uses_production_supported_syntax() {
    let registry = load_embedded_registry().expect("embedded registry valid");
    for rule in registry {
        for pattern in rule.applies_to.file_patterns {
            assert!(
                file_pattern_is_supported(&pattern),
                "{} uses unsupported file pattern {pattern}",
                rule.id
            );
        }
    }
}
