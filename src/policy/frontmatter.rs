//! Frontmatter-backed rule files.
//!
//! Rule files carry a JSON-compatible YAML frontmatter object so the same
//! document can be consumed by Claude Code and by the embedded policy loader.

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use super::{Rule, load_and_validate};

pub use super::frontmatter_sources::RULE_DOCUMENT_SOURCES;

/// Rule files compiled into the enforcement binary.
pub const RULE_FILE_SOURCES: &[(&str, &str)] = RULE_DOCUMENT_SOURCES;

/// Preserve the registry order that callers use for stable packet output.
const RULE_ORDER: &[&str] = &[
    "no-committed-secrets",
    "no-swallowed-errors",
    "no-broad-exception-handling",
    "external-call-timeout",
    "public-input-validation",
    "sql-parameterization",
    "bounded-retries-loops",
    "destructive-operation-safeguards",
    "regression-test-required",
    "new-behavior-tests-required",
    "preserve-unrelated-user-changes",
    "new-dependency-review",
    "auth-change-security-review",
    "required-repository-commands",
    "evidence-claims-honest",
    "rust-no-unsafe",
    "rust-no-unwrap-expect",
    "typescript-no-any",
    "react-no-state-mutation",
    "react-unstable-key",
    "typescript-unsafe-unknown",
    "typescript-api-response-validation",
    "rust-spawn-cancellation",
    "rust-no-mutable-global",
    "react-effect-cleanup",
    "react-error-loading-states",
    "react-accessibility-review",
    "rust-async-timeout-review",
    "rust-id-unit-newtype-review",
    "go-ignored-error",
    "go-goroutine-cancellation",
    "go-mutable-global",
    "go-error-wrapping",
    "go-context-first-review",
    "function-size",
    "file-size",
    "function-complexity",
    "shell-safety-review",
    "shell-idempotency-review",
    "iac-validation-review",
    "config-schema-review",
    "ai-assisted-discipline",
    "commit-pr-evidence",
    "refactor-discipline-review",
    "documentation-change-review",
    "dependency-change-review",
    "performance-review",
    "endpoint-controls-review",
    "auth-input-enforcement",
    "public-endpoint-review",
    "safe-construction-review",
    "justification-metadata",
    "sql-migration-review",
    "cpp-review",
    "csharp-review",
    "jvm-review",
    "ui-accessibility-review",
    "ui-responsive-review",
    "test-naming-review",
    "determinism-review",
    "behavior-test-quality",
    "test-quality-guidance",
    "debugging-protocol",
    "sensitive-logging-review",
    "structured-observability-review",
    "boundary-error-review",
    "contextual-design-guidance",
    "naming-review",
    "module-boundary-review",
    "error-contract-review",
    "anti-slop-checklist",
];

/// The machine-readable portion of a rule file.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleFrontmatter {
    pub description: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub headings: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Errors raised while loading rule-file frontmatter.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrontmatterError {
    #[error("rule file `{path}` has malformed frontmatter: {reason}")]
    Malformed { path: String, reason: String },
    #[error("rule file `{path}` has invalid rule data: {reason}")]
    InvalidRule { path: String, reason: String },
    #[error("duplicate rule id `{id}` in rule files `{first_path}` and `{duplicate_path}`")]
    DuplicateId {
        id: String,
        first_path: String,
        duplicate_path: String,
    },
    #[error(
        "normative heading `{heading}` appears in rule files `{first_path}` and `{duplicate_path}`"
    )]
    DuplicateHeading {
        heading: String,
        first_path: String,
        duplicate_path: String,
    },
    #[error("frontmatter registry differs from JSON registry: {details}")]
    RegistryMismatch { details: String },
    #[error("frontmatter registry is incomplete: expected {expected} rules, found {actual}")]
    Incomplete { expected: usize, actual: usize },
    #[error("frontmatter schema is invalid: {0}")]
    Schema(String),
}

/// Load every rule declared in the embedded rule-file frontmatter.
pub fn load_registry() -> Result<Vec<Rule>, FrontmatterError> {
    let mut rules = load_rule_files(RULE_FILE_SOURCES)?;
    rules.sort_by_key(|rule| {
        RULE_ORDER
            .iter()
            .position(|candidate| *candidate == rule.id)
            .unwrap_or(RULE_ORDER.len())
    });
    if rules.len() != 71 {
        return Err(FrontmatterError::Incomplete {
            expected: 71,
            actual: rules.len(),
        });
    }
    Ok(rules)
}

/// Load a caller-supplied set of rule files, retaining path-specific errors for
/// malformed metadata and duplicate IDs.
pub fn load_rule_files(sources: &[(&str, &str)]) -> Result<Vec<Rule>, FrontmatterError> {
    let mut rules = Vec::new();
    let mut paths_by_id = BTreeMap::new();
    for (path, contents) in sources {
        let Some(frontmatter) = parse_file(path, contents)? else {
            continue;
        };
        for rule in frontmatter.rules {
            if let Some(first_path) = paths_by_id.insert(rule.id.clone(), (*path).to_string()) {
                return Err(FrontmatterError::DuplicateId {
                    id: rule.id,
                    first_path,
                    duplicate_path: (*path).to_string(),
                });
            }
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// Return the normative headings declared by the embedded rule documents.
pub fn normative_headings() -> Result<std::collections::BTreeSet<String>, FrontmatterError> {
    let mut headings = std::collections::BTreeSet::new();
    let mut paths_by_heading = BTreeMap::new();
    for (path, contents) in RULE_DOCUMENT_SOURCES {
        if let Some(document) = parse_file(path, contents)? {
            for heading in document.headings {
                if let Some(first_path) = paths_by_heading.insert(heading.clone(), *path) {
                    return Err(FrontmatterError::DuplicateHeading {
                        heading,
                        first_path: first_path.to_string(),
                        duplicate_path: (*path).to_string(),
                    });
                }
                headings.insert(heading);
            }
        }
        if *path == "templates/claude-rules/CLAUDE.md" {
            for heading in marked_headings(contents) {
                if let Some(first_path) = paths_by_heading.insert(heading.clone(), *path) {
                    return Err(FrontmatterError::DuplicateHeading {
                        heading,
                        first_path: first_path.to_string(),
                        duplicate_path: (*path).to_string(),
                    });
                }
                headings.insert(heading);
            }
        }
    }
    Ok(headings)
}

/// Return the body Claude Code hands to a consumer after stripping metadata.
pub fn body(contents: &str) -> Result<&str, FrontmatterError> {
    split_frontmatter("<inline>", contents).map(|parts| parts.map_or(contents, |(_, body)| body))
}

pub(crate) fn parse_file(
    path: &str,
    contents: &str,
) -> Result<Option<RuleFrontmatter>, FrontmatterError> {
    let Some((raw, _)) = split_frontmatter(path, contents)? else {
        return Ok(None);
    };
    let (document, value) = parse_document(path, raw)?;
    super::frontmatter_schema::validate(path, &value)?;
    if !document.rules.is_empty() {
        let serialized = serde_json::to_string(&document.rules).map_err(|error| {
            FrontmatterError::InvalidRule {
                path: path.to_string(),
                reason: error.to_string(),
            }
        })?;
        load_and_validate(&serialized).map_err(|error| FrontmatterError::InvalidRule {
            path: path.to_string(),
            reason: error.to_string(),
        })?;
    }
    Ok(Some(document))
}

fn parse_document(
    path: &str,
    raw: &str,
) -> Result<(RuleFrontmatter, serde_json::Value), FrontmatterError> {
    if let Ok(value) = serde_json::from_str(raw) {
        return parse_value(path, value);
    }
    parse_yaml_shell(path, raw)
}

fn parse_value(
    path: &str,
    value: serde_json::Value,
) -> Result<(RuleFrontmatter, serde_json::Value), FrontmatterError> {
    let document =
        serde_json::from_value(value.clone()).map_err(|error| FrontmatterError::Malformed {
            path: path.to_string(),
            reason: error.to_string(),
        })?;
    Ok((document, value))
}

fn parse_yaml_shell(
    path: &str,
    raw: &str,
) -> Result<(RuleFrontmatter, serde_json::Value), FrontmatterError> {
    let keys = yaml_top_level_keys(raw);
    if keys.is_empty() {
        return Err(FrontmatterError::Malformed {
            path: path.to_string(),
            reason: "expected description, paths, headings, or rules metadata".to_string(),
        });
    }
    for key in &keys {
        if !matches!(*key, "description" | "paths" | "headings" | "rules") {
            return Err(FrontmatterError::Malformed {
                path: path.to_string(),
                reason: format!("unknown frontmatter key `{key}`"),
            });
        }
    }
    let description = yaml_scalar(path, raw, "description")?;
    let paths = yaml_list(path, raw, "paths")?;
    let headings = inline_list(path, raw, "headings")?;
    let rules: Vec<Rule> = match raw.find("rules:") {
        Some(rules_start) => {
            let rules_raw = raw[rules_start + "rules:".len()..].trim();
            serde_json::from_str(rules_raw).map_err(|error| FrontmatterError::Malformed {
                path: path.to_string(),
                reason: format!("rules must be a JSON-compatible YAML sequence: {error}"),
            })?
        }
        None => Vec::new(),
    };
    let mut object = serde_json::Map::new();
    if let Some(description) = description {
        object.insert(
            "description".to_string(),
            serde_json::Value::String(description),
        );
    }
    if keys.contains(&"paths") {
        object.insert(
            "paths".to_string(),
            serde_json::Value::Array(paths.into_iter().map(serde_json::Value::String).collect()),
        );
    }
    if keys.contains(&"headings") {
        object.insert(
            "headings".to_string(),
            serde_json::Value::Array(
                headings
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if keys.contains(&"rules") {
        object.insert(
            "rules".to_string(),
            serde_json::to_value(rules).map_err(|error| FrontmatterError::Malformed {
                path: path.to_string(),
                reason: format!("rules could not be represented: {error}"),
            })?,
        );
    }
    parse_value(path, serde_json::Value::Object(object))
}

/// Collect only YAML keys at the frontmatter document's top level.
fn yaml_top_level_keys(raw: &str) -> Vec<&str> {
    raw.lines()
        .filter_map(|line| {
            if line.is_empty() || line.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
                return None;
            }
            let line = line.split_once('#').map_or(line, |(value, _)| value).trim();
            let key = line.split_once(':').map(|(key, _)| key.trim())?;
            (!key.is_empty())
                .then_some(key.trim_matches(|character| matches!(character, '"' | '\'')))
        })
        .collect()
}

fn yaml_scalar(path: &str, raw: &str, key: &str) -> Result<Option<String>, FrontmatterError> {
    let Some(value) = raw.lines().find_map(|line| {
        if line.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
            return None;
        }
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then_some(value.trim())
    }) else {
        return Ok(None);
    };
    if value.starts_with('"') {
        return serde_json::from_str(value).map(Some).map_err(|error| {
            FrontmatterError::Malformed {
                path: path.to_string(),
                reason: format!("{key} must be a string: {error}"),
            }
        });
    }
    Ok(Some(value.trim_matches('\'').to_string()))
}

fn yaml_list(path: &str, raw: &str, key: &str) -> Result<Vec<String>, FrontmatterError> {
    let Some(line) = raw.lines().find(|line| {
        !line.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
            && line
                .split_once(':')
                .is_some_and(|(candidate, _)| candidate.trim() == key)
    }) else {
        return Ok(Vec::new());
    };
    let value = line.split_once(':').map_or("", |(_, value)| value.trim());
    if !value.is_empty() {
        return inline_list(path, raw, key);
    }

    let mut values = Vec::new();
    let mut reading = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed == format!("{key}:") {
            reading = true;
            continue;
        }
        if reading && !line.starts_with(' ') {
            break;
        }
        if !reading || trimmed.is_empty() {
            continue;
        }
        let Some(value) = trimmed.strip_prefix("- ") else {
            return Err(FrontmatterError::Malformed {
                path: path.to_string(),
                reason: format!("{key} must be a JSON-compatible YAML sequence"),
            });
        };
        values.push(value.trim_matches('"').to_string());
    }
    if values.is_empty() {
        return Err(FrontmatterError::Malformed {
            path: path.to_string(),
            reason: format!("{key} must contain at least one path"),
        });
    }
    Ok(values)
}

fn inline_list(path: &str, raw: &str, key: &str) -> Result<Vec<String>, FrontmatterError> {
    let Some(line) = raw.lines().find(|line| {
        line.trim_start()
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    }) else {
        return Ok(Vec::new());
    };
    let Some(value) = line.split_once(':').map(|(_, value)| value.trim()) else {
        return Ok(Vec::new());
    };
    serde_json::from_str(value).map_err(|error| FrontmatterError::Malformed {
        path: path.to_string(),
        reason: format!("{key} must be a JSON-compatible YAML sequence: {error}"),
    })
}

fn marked_headings(contents: &str) -> Vec<String> {
    const PREFIX: &str = "<!-- lgtm-normative-headings: ";
    contents
        .lines()
        .find_map(|line| {
            line.strip_prefix(PREFIX)
                .and_then(|value| value.strip_suffix(" -->"))
        })
        .map(|value| {
            value
                .split(',')
                .map(|heading| heading.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn split_frontmatter<'a>(
    path: &str,
    contents: &'a str,
) -> Result<Option<(&'a str, &'a str)>, FrontmatterError> {
    let Some(opening_end) = frontmatter_line_end(contents, 0) else {
        return Ok(None);
    };
    let rest = &contents[opening_end..];
    let mut offset = 0;
    let Some((raw, body)) = (loop {
        let Some(line_end) = rest[offset..].find('\n').map(|index| offset + index + 1) else {
            break None;
        };
        let line = rest[offset..line_end].trim_end_matches(['\r', '\n']);
        if line == "---" {
            break Some((&rest[..offset], &rest[line_end..]));
        }
        offset = line_end;
        if offset == rest.len() {
            break None;
        }
    }) else {
        return Err(FrontmatterError::Malformed {
            path: path.to_string(),
            reason: "opening delimiter has no closing `---`".to_string(),
        });
    };
    Ok(Some((raw, body)))
}

fn frontmatter_line_end(contents: &str, delimiter_start: usize) -> Option<usize> {
    if !contents[delimiter_start..].starts_with("---") {
        return None;
    }
    let newline_start = delimiter_start + 3;
    if contents[newline_start..].starts_with("\r\n") {
        return Some(newline_start + 2);
    }
    contents[newline_start..]
        .starts_with('\n')
        .then_some(newline_start + 1)
}

#[cfg(test)]
#[path = "frontmatter_tests.rs"]
mod tests;
