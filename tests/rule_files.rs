use lgtm::policy::frontmatter::{RULE_DOCUMENT_SOURCES, body, load_registry, load_rule_files};
use lgtm::select::file_pattern_matches;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "rule_scope.rs"]
mod rule_scope;

use rule_scope::patterns_cover;

const RULE_MARKER_PREFIX: &str = "<!-- lgtm-rule: ";

const ORIGINAL_SECTIONS: &[&str] = &[
    "Core Principles",
    "Non-Negotiable Rules",
    "Code Organization",
    "Naming Standards",
    "Design For Debugging",
    "Error Handling",
    "Testing Standards",
    "Observability Standards",
    "Performance Standards",
    "Security Standards",
    "Dependency Standards",
    "Documentation Standards",
    "Review And Change Standards",
    "Refactoring Standards",
    "Debugging Protocol",
    "Anti-Slop Checklist",
    "Language-Specific Standards",
    "AI-Assisted Coding Standards",
    "Master Techniques For Maintainable Systems",
    "Quality Gates",
];

#[test]
fn every_original_section_is_in_exactly_one_rule_location() {
    let mut locations: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        for heading in ORIGINAL_SECTIONS {
            if contents.lines().any(|line| {
                line.strip_prefix('#')
                    .is_some_and(|rest| rest.trim_start_matches('#').trim() == *heading)
            }) {
                locations.entry(heading).or_default().push(path);
            }
        }
    }

    for heading in ORIGINAL_SECTIONS {
        assert_eq!(
            locations.get(heading).map(Vec::len),
            Some(1),
            "{heading} must be mapped to one rule location, found {:?}",
            locations.get(heading)
        );
    }
}

#[test]
fn entry_document_stays_within_the_always_loaded_budget() {
    let entry = RULE_DOCUMENT_SOURCES
        .iter()
        .find(|(path, _)| *path == "templates/claude-rules/CLAUDE.md")
        .map(|(_, contents)| *contents)
        .expect("entry document is embedded");
    assert!(body(entry).expect("entry body").lines().count() < 200);
}

#[test]
fn source_rules_match_python_but_not_docs() {
    let new_files = [
        "templates/claude-rules/rules/anti-slop.md",
        "templates/claude-rules/rules/code-organization.md",
        "templates/claude-rules/rules/error-handling.md",
        "templates/claude-rules/rules/naming.md",
        "templates/claude-rules/rules/observability.md",
        "templates/claude-rules/rules/performance.md",
    ];

    for path in new_files {
        let contents = source(path);
        let paths = frontmatter_paths(contents);
        assert!(!paths.is_empty(), "{path} needs paths frontmatter");
        assert!(
            paths
                .iter()
                .any(|pattern| file_pattern_matches(pattern, "src/main.py")),
            "{path} must load for Python edits"
        );
        assert!(
            !paths
                .iter()
                .any(|pattern| file_pattern_matches(pattern, "README.md")),
            "{path} must not load for docs-only edits"
        );
    }
}

#[test]
fn every_rule_record_stays_with_its_documented_prose() {
    let registry = load_registry().expect("embedded registry");
    let registry_ids: std::collections::BTreeSet<_> =
        registry.iter().map(|rule| rule.id.as_str()).collect();

    let mut record_locations = BTreeMap::new();
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        for rule in load_rule_files(&[(*path, *contents)]).expect("rule file parses") {
            let previous = record_locations.insert(rule.id.clone(), *path);
            assert!(
                previous.is_none(),
                "rule `{}` has records in both `{}` and `{}`",
                rule.id,
                previous.unwrap_or("<unknown>"),
                path
            );
        }
    }

    assert_eq!(record_locations.len(), registry_ids.len());
    assert_eq!(
        record_locations
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        registry_ids
    );

    let mut body_locations: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        let prose = body(contents).expect("rule body");
        for rule in &registry {
            let marker = format!("{RULE_MARKER_PREFIX}{} -->\n#### {}", rule.id, rule.title);
            if prose.contains(&marker) {
                body_locations
                    .entry(rule.id.as_str())
                    .or_default()
                    .push(path);
            }
        }
    }

    for rule in &registry {
        let locations = body_locations
            .get(rule.id.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        assert_eq!(
            locations.len(),
            1,
            "rule `{}` must have exactly one documented body, found {locations:?}",
            rule.id
        );
        assert_eq!(
            Some(locations[0]),
            record_locations.get(&rule.id).copied(),
            "rule `{}` record and documented body must share a file",
            rule.id
        );
    }
}

#[test]
fn every_rule_scope_is_loadable_from_its_document() {
    let mut failures = Vec::new();
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        let paths = frontmatter_paths(contents);
        if paths.is_empty() {
            continue;
        }
        for rule in load_rule_files(&[(*path, *contents)]).expect("rule file parses") {
            for applies_to in &rule.applies_to.file_patterns {
                if !patterns_cover(&paths, applies_to) {
                    failures.push(format!("{path}:{}={applies_to}", rule.id));
                }
            }
        }
    }
    assert!(failures.is_empty(), "scope coverage gaps: {failures:?}");
}

#[test]
fn frontmatter_schema_rejects_empty_path_entries() {
    let contents = "---\npaths:\n  - \"\"\n---\n# body";
    let error = load_rule_files(&[("empty-path.md", contents)]).expect_err("empty path");
    assert!(error.to_string().contains("empty-path.md"));
    assert!(error.to_string().contains("paths"));
}

#[test]
fn frontmatter_schema_rejects_duplicate_paths_and_headings() {
    let duplicate_paths = "---\npaths:\n  - \"**/*.rs\"\n  - \"**/*.rs\"\n---\n# body";
    let path_error =
        load_rule_files(&[("duplicate-paths.md", duplicate_paths)]).expect_err("duplicate paths");
    assert!(path_error.to_string().contains("duplicate-paths.md"));
    assert!(path_error.to_string().contains("paths"));

    let duplicate_headings = "---\nheadings: [\"Rust\", \"Rust\"]\n---\n# body";
    let heading_error = load_rule_files(&[("duplicate-headings.md", duplicate_headings)])
        .expect_err("duplicate headings");
    assert!(heading_error.to_string().contains("duplicate-headings.md"));
    assert!(heading_error.to_string().contains("headings"));
}

#[test]
fn rule_files_have_reviewable_line_lengths() {
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        for (line_number, line) in contents.lines().enumerate() {
            assert!(
                line.chars().count() <= 400,
                "{path}:{} exceeds the 400-character line limit",
                line_number + 1
            );
        }
    }
}

#[test]
fn repository_files_do_not_refer_to_the_retired_standards_filename() {
    let retired_name = ["codingStandards", "md"].join(".");
    for absolute in repository_files() {
        let path = absolute
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .expect("repository file is under the manifest directory");
        let path = path.to_string_lossy();
        if path == retired_name || path == ".codex-brief.md" {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&absolute) else {
            continue;
        };
        assert!(
            !contents.contains(&retired_name),
            "{path} must use rule-file references instead of the retired filename"
        );
    }
}

#[test]
fn repository_files_do_not_store_line_number_anchors() {
    for absolute in repository_files() {
        let path = absolute
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .expect("repository file is under the manifest directory")
            .to_string_lossy();
        let Ok(contents) = std::fs::read_to_string(&absolute) else {
            continue;
        };
        assert!(
            !contains_line_anchor(&contents),
            "{path} stores a line anchor"
        );
    }
}

#[test]
fn line_anchor_requires_digits_after_prefix() {
    assert!(!contains_line_anchor("https://example.test/#License"));
    assert!(!contains_line_anchor("#Login"));
    let anchor = format!("https://github.test/repo{}L42", "#");
    assert!(contains_line_anchor(&anchor));
}

fn source(path: &str) -> &'static str {
    RULE_DOCUMENT_SOURCES
        .iter()
        .find(|(candidate, _)| *candidate == path)
        .map(|(_, contents)| *contents)
        .expect("source is embedded")
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

/// Read only paths tracked by Git so local evidence and scratch files cannot
/// change the repository invariant tests.
fn repository_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("git")
        .args(["ls-files", "--cached", "-z"])
        .current_dir(root)
        .output()
        .expect("git ls-files starts");
    assert!(output.status.success(), "git ls-files must succeed");
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| root.join(String::from_utf8_lossy(path).as_ref()))
        .collect()
}

/// Match only the GitHub-style line-anchor prefix followed by a line number.
fn contains_line_anchor(contents: &str) -> bool {
    contents
        .as_bytes()
        .windows(3)
        .any(|window| window[0] == b'#' && window[1] == b'L' && window[2].is_ascii_digit())
}
