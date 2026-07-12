//! Repository-local policy overlays that can only tighten known rules.

use std::path::Path;

use serde::Deserialize;

use super::{Rule, Severity};

const MAX_BYTES: u64 = 256 * 1024;
pub const SCHEMA_JSON: &str = include_str!("../../policy/repository-overlay.schema.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    rules: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    severity: Severity,
    instruction: Option<String>,
    #[allow(dead_code)]
    selectors: Option<Vec<String>>,
}

pub fn apply(root: &Path, rules: &mut [Rule]) -> Result<(), String> {
    let path = root.join(".lgtm/policy.json");
    let raw = crate::fsutil::read_optional_bounded(&path, MAX_BYTES);
    if raw.trim().is_empty() {
        return Ok(());
    }
    let overlay: Overlay =
        serde_json::from_str(&raw).map_err(|error| format!("overlay JSON invalid ({error})"))?;
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_JSON)
        .map_err(|error| format!("overlay schema invalid ({error})"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| format!("overlay JSON invalid ({error})"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("overlay schema invalid ({error})"))?;
    if let Some(error) = validator.iter_errors(&value).next() {
        return Err(format!("overlay schema violation ({error})"));
    }
    for entry in overlay.rules {
        let Some(rule) = rules.iter_mut().find(|rule| rule.id == entry.id) else {
            return Err(format!("overlay references unknown rule `{}`", entry.id));
        };
        if weakens(rule.severity, entry.severity) {
            return Err(format!(
                "overlay cannot weaken severity for protected rule `{}`",
                rule.id
            ));
        }
        rule.severity = entry.severity;
        if let Some(instruction) = entry.instruction {
            rule.instruction = instruction;
        }
    }
    Ok(())
}

fn weakens(current: Severity, requested: Severity) -> bool {
    rank(requested) < rank(current)
}

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_rejects_unknown_and_weakening_rules() {
        let root = std::env::temp_dir().join(format!("lgtm-overlay-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".lgtm")).expect("config dir");
        std::fs::write(
            root.join(".lgtm/policy.json"),
            r#"{"rules":[{"id":"no-committed-secrets","severity":"info"}]}"#,
        )
        .expect("overlay");
        let mut rules = vec![Rule {
            id: "no-committed-secrets".to_string(),
            title: "x".to_string(),
            description: "x".to_string(),
            mechanism: super::super::Mechanism::Native,
            confidence: super::super::Confidence::High,
            examples: Vec::new(),
            limitations: Vec::new(),
            enforcement_stage: super::super::EnforcementStage::PostTool,
            language_implementations: std::collections::BTreeMap::new(),
            severity: Severity::Error,
            level: super::super::Level::Must,
            category: super::super::Category::Security,
            applies_to: super::super::AppliesTo {
                languages: Vec::new(),
                domains: Vec::new(),
                file_patterns: Vec::new(),
            },
            activation: super::super::Activation {
                change_types: Vec::new(),
                signals: Vec::new(),
            },
            instruction: "x".to_string(),
            enforcement: super::super::Enforcement {
                mode: super::super::EnforcementMode::Static,
                checks: vec!["gitleaks.detect".to_string()],
            },
            overridable: false,
            evidence: super::super::Evidence {
                required: Vec::new(),
            },
            references: Vec::new(),
        }];
        assert!(apply(&root, &mut rules).is_err());
        std::fs::remove_dir_all(root).ok();
    }
}
