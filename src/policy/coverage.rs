//! Honest coverage mapping between codingStandards.md and executable policy.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const COVERAGE_SCHEMA_JSON: &str = include_str!("../../policy/standards-coverage.schema.json");
pub const COVERAGE_JSON: &str = include_str!("../../policy/standards-coverage.json");
pub const STANDARDS_TEXT: &str = include_str!("../../codingStandards.md");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoverageLedger {
    pub standards_file: String,
    pub version: String,
    pub normative_headings: Vec<String>,
    pub sections: Vec<CoverageSection>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoverageSection {
    pub id: String,
    pub heading: String,
    pub source_anchor: String,
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
    pub source_anchor: String,
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
pub fn item_counts() -> Vec<(String, usize)> {
    let parsed = parsed_items();
    let headings: BTreeSet<_> = parsed.iter().map(|item| item.heading.clone()).collect();
    headings
        .into_iter()
        .map(|heading| {
            let count = parsed.iter().filter(|item| item.heading == heading).count();
            (heading, count)
        })
        .collect()
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
    for item in parsed_items() {
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
            source_anchor: item.source_anchor,
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
    source_anchor: String,
    text: String,
}

fn parsed_items() -> Vec<ParsedItem> {
    let mut items = Vec::new();
    let mut current: Option<String> = None;
    let mut item_number = 0_usize;
    for (line_index, line) in STANDARDS_TEXT.lines().enumerate() {
        if let Some(heading) = line
            .strip_prefix("## ")
            .or_else(|| line.strip_prefix("### "))
        {
            current = Some(heading.trim().to_string());
            item_number = 0;
            continue;
        }
        let Some(heading) = current.as_ref() else {
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
                source_anchor: format!("codingStandards.md#L{}", line_index + 1),
                text: text.to_string(),
            });
        }
    }
    items
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
    let counts = item_counts();
    let expected: BTreeSet<_> = counts.iter().map(|(heading, _)| heading.clone()).collect();
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
    for section in &ledger.sections {
        if !ids.insert(&section.id) {
            return Err(CoverageError::Incomplete(format!(
                "duplicate section id `{}`",
                section.id
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
        assert_eq!(ledger.sections.len(), item_counts().len());
        let expanded = items(&ledger).expect("normative items map");
        assert!(expanded.len() > ledger.sections.len());
        assert!(expanded.iter().all(|item| !item.source_anchor.is_empty()));
    }
}
