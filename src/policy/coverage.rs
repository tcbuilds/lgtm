//! Honest coverage mapping between rule-file prose and executable policy.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::frontmatter;

pub const COVERAGE_SCHEMA_JSON: &str = include_str!("../../policy/standards-coverage.schema.json");
pub const COVERAGE_JSON: &str = include_str!("../../policy/standards-coverage.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoverageLedger {
    pub rule_files: String,
    pub version: String,
    pub normative_headings: Vec<String>,
    pub sections: Vec<CoverageSection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoverageSection {
    pub id: String,
    pub heading: String,
    pub scope: String,
    pub status: CoverageStatus,
    pub mechanism: CoverageMechanism,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub supported_languages: Vec<String>,
    pub enforcement_stages: Vec<String>,
    pub limitations: String,
    pub notes: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    Covered,
    Partial,
    Unsupported,
}

impl std::fmt::Display for CoverageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Covered => "covered",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageMechanism {
    Native,
    Wrapped,
    Command,
    Instruction,
    Review,
    Evidence,
    Unsupported,
}

impl std::fmt::Display for CoverageMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Native => "native",
            Self::Wrapped => "wrapped",
            Self::Command => "command",
            Self::Instruction => "instruction",
            Self::Review => "review",
            Self::Evidence => "evidence",
            Self::Unsupported => "unsupported",
        })
    }
}

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("coverage schema is invalid: {0}")]
    Schema(String),
    #[error("coverage ledger is invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("coverage ledger is incomplete: {0}")]
    Incomplete(String),
}

/// Validate the embedded ledger and prove every normative list item belongs to
/// exactly one declared standards section.
pub fn load() -> Result<CoverageLedger, CoverageError> {
    let schema: serde_json::Value = serde_json::from_str(COVERAGE_SCHEMA_JSON)
        .map_err(|error| CoverageError::Schema(error.to_string()))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| CoverageError::Schema(error.to_string()))?;
    let value: serde_json::Value = serde_json::from_str(COVERAGE_JSON)?;
    let errors: Vec<_> = validator
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(CoverageError::Incomplete(errors.join("; ")));
    }
    let ledger: CoverageLedger = serde_json::from_value(value)?;
    validate_sections(&ledger)?;
    let _ = items(&ledger)?;
    Ok(ledger)
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageItem {
    pub id: String,
    pub heading: String,
    pub text: String,
    pub section_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    #[serde(flatten)]
    pub ledger: CoverageLedger,
    pub items: Vec<CoverageItem>,
}

pub fn report() -> Result<CoverageReport, CoverageError> {
    let ledger = load()?;
    let items = items(&ledger)?;
    Ok(CoverageReport { ledger, items })
}

/// Count direct numbered/bulleted normative items under each top-level section.
pub fn item_counts() -> Result<Vec<(String, usize)>, CoverageError> {
    item_counts_from_sources(frontmatter::RULE_DOCUMENT_SOURCES)
}

fn item_counts_from_sources(
    sources: &[(&str, &str)],
) -> Result<Vec<(String, usize)>, CoverageError> {
    let parsed = parsed_items(sources)?;
    let headings: BTreeSet<_> = parsed.iter().map(|item| item.heading.clone()).collect();
    Ok(headings
        .into_iter()
        .map(|heading| {
            let count = parsed.iter().filter(|item| item.heading == heading).count();
            (heading, count)
        })
        .collect())
}

/// Expand each normative Markdown list item into a deterministic coverage row.
pub fn items(ledger: &CoverageLedger) -> Result<Vec<CoverageItem>, CoverageError> {
    let section_ids: std::collections::BTreeMap<_, _> = ledger
        .sections
        .iter()
        .map(|section| (section.heading.as_str(), section.id.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    let mut expanded = Vec::new();
    for item in parsed_items(frontmatter::RULE_DOCUMENT_SOURCES)? {
        let section_id = section_ids
            .get(item.heading.as_str())
            .ok_or_else(|| CoverageError::Incomplete(format!("unmapped item `{}`", item.id)))?;
        if !seen.insert(item.id.clone()) {
            return Err(CoverageError::Incomplete(format!(
                "duplicate normative item `{}`",
                item.id
            )));
        }
        expanded.push(CoverageItem {
            id: item.id,
            heading: item.heading,
            text: item.text,
            section_id: section_id.to_string(),
        });
    }
    Ok(expanded)
}

#[derive(Debug, Clone)]
struct ParsedItem {
    id: String,
    heading: String,
    text: String,
}

fn parsed_items(sources: &[(&str, &str)]) -> Result<Vec<ParsedItem>, CoverageError> {
    let headings = frontmatter::normative_headings()
        .map_err(|error| CoverageError::Incomplete(error.to_string()))?;
    let mut items = Vec::new();
    for (_path, contents) in sources {
        let body = frontmatter::body(contents)
            .map_err(|error| CoverageError::Incomplete(error.to_string()))?;
        let mut current: Option<(String, usize)> = None;
        let mut item_number = 0_usize;
        for line in body.lines() {
            if let Some((level, heading)) = markdown_heading(line) {
                if headings.contains(&heading) {
                    current = Some((heading, level));
                    item_number = 0;
                } else if current
                    .as_ref()
                    .is_some_and(|(_, current_level)| level <= *current_level)
                {
                    current = None;
                }
                continue;
            }
            let Some((heading, _)) = current.as_ref() else {
                continue;
            };
            let trimmed = line.trim_start();
            let numbered = trimmed.split_once('.').is_some_and(|(prefix, rest)| {
                !prefix.is_empty()
                    && prefix.chars().all(|character| character.is_ascii_digit())
                    && !rest.trim().is_empty()
            });
            if numbered || trimmed.starts_with("- ") {
                item_number += 1;
                let text = if numbered {
                    trimmed
                        .split_once('.')
                        .map(|(_, rest)| rest.trim())
                        .unwrap_or(trimmed)
                } else {
                    trimmed.trim_start_matches("- ").trim()
                };
                items.push(ParsedItem {
                    id: format!("{}-{:03}", slugify(heading), item_number),
                    heading: heading.clone(),
                    text: text.to_string(),
                });
            }
        }
    }
    Ok(items)
}

fn markdown_heading(line: &str) -> Option<(usize, String)> {
    let level = line
        .chars()
        .take_while(|character| *character == '#')
        .count();
    (level > 0 && line.as_bytes().get(level) == Some(&b' '))
        .then(|| (level, line[level..].trim().to_string()))
}

fn slugify(value: &str) -> String {
    let mut slug = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_string()
}

fn validate_sections(ledger: &CoverageLedger) -> Result<(), CoverageError> {
    let expected = frontmatter::normative_headings()
        .map_err(|error| CoverageError::Incomplete(error.to_string()))?;
    let allowlist: BTreeSet<_> = ledger.normative_headings.iter().cloned().collect();
    let actual: BTreeSet<_> = ledger
        .sections
        .iter()
        .map(|section| section.heading.clone())
        .collect();
    if expected != allowlist || expected != actual {
        return Err(CoverageError::Incomplete(format!(
            "headings differ; expected={:?} allowlist={:?} sections={:?}",
            expected, allowlist, actual
        )));
    }
    let mut ids = BTreeSet::new();
    let mut section_headings = BTreeSet::new();
    for section in &ledger.sections {
        if !ids.insert(&section.id) {
            return Err(CoverageError::Incomplete(format!(
                "duplicate section id `{}`",
                section.id
            )));
        }
        if !section_headings.insert(&section.heading) {
            return Err(CoverageError::Incomplete(format!(
                "duplicate section heading `{}`",
                section.heading
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_ledger_covers_every_standards_section() {
        let ledger = load().expect("coverage ledger validates");
        let counts = item_counts().expect("embedded item counts parse");
        assert_eq!(ledger.sections.len(), counts.len());
        let expanded = items(&ledger).expect("normative items map");
        assert!(expanded.len() > ledger.sections.len());
    }

    #[test]
    fn item_counts_surfaces_unterminated_frontmatter() {
        let sources = [(
            "tests/fixtures/unterminated_rule.md",
            include_str!("../../tests/fixtures/unterminated_rule.md"),
        )];
        let error = item_counts_from_sources(&sources)
            .expect_err("unterminated frontmatter must not become empty coverage");
        assert!(error.to_string().contains("no closing `---`"));
    }

    #[test]
    fn unmapped_rule_bullet_is_rejected() {
        let mut ledger = load().expect("coverage ledger validates");
        ledger.sections.retain(|section| section.heading != "Rust");
        let error = items(&ledger).expect_err("Rust bullets must have a section");
        assert!(error.to_string().contains("unmapped item"));
    }

    #[test]
    fn duplicate_section_mapping_is_rejected() {
        let mut ledger = load().expect("coverage ledger validates");
        let mut duplicate = ledger.sections[0].clone();
        duplicate.id = "duplicate-core-principles".to_string();
        ledger.sections.push(duplicate);
        let error = validate_sections(&ledger).expect_err("duplicate mapping must fail");
        assert!(error.to_string().contains("duplicate section heading"));
    }
}
