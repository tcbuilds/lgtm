//! Optional organization policy layer with an explicit local digest pin.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{Rule, Severity};

const MAX_BYTES: u64 = 256 * 1024;
pub const SCHEMA_JSON: &str = include_str!("../../policy/org-bundle.schema.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    version: String,
    rules: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    severity: Severity,
    instruction: Option<String>,
}

pub fn apply(root: &Path, rules: &mut [Rule]) -> Result<Option<String>, String> {
    let bundle_path = root.join(".lgtm/org-policy.json");
    let Some(bundle_raw) = read_optional(&bundle_path)? else {
        return Ok(None);
    };
    let pin = read_required(&root.join(".lgtm/org-policy.sha256"))?;
    let digest = digest(&bundle_raw);
    if pin != digest {
        return Err(
            "organization policy digest does not match .lgtm/org-policy.sha256".to_string(),
        );
    }
    let value: serde_json::Value = serde_json::from_str(&bundle_raw)
        .map_err(|error| format!("organization policy JSON invalid ({error})"))?;
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_JSON)
        .map_err(|error| format!("organization policy schema invalid ({error})"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("organization policy schema invalid ({error})"))?;
    if let Some(error) = validator.iter_errors(&value).next() {
        return Err(format!("organization policy schema violation ({error})"));
    }
    let bundle: Bundle = serde_json::from_value(value)
        .map_err(|error| format!("organization policy JSON invalid ({error})"))?;
    if bundle.version.trim().is_empty() {
        return Err("organization policy version must not be empty".to_string());
    }
    for entry in bundle.rules {
        let Some(rule) = rules.iter_mut().find(|rule| rule.id == entry.id) else {
            return Err(format!(
                "organization policy references unknown rule `{}`",
                entry.id
            ));
        };
        if rank(entry.severity) < rank(rule.severity) {
            return Err(format!(
                "organization policy cannot weaken severity for protected rule `{}`",
                rule.id
            ));
        }
        rule.severity = entry.severity;
        if let Some(instruction) = entry.instruction {
            rule.instruction = instruction;
        }
    }
    Ok(Some(format!("organization@{}:{digest}", bundle.version)))
}

fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

fn digest(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.as_bytes()))
}

fn read_optional(path: &Path) -> Result<Option<String>, String> {
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open {} ({error})", path.display()))?
    else {
        return Ok(None);
    };
    read_file(file, path).map(Some)
}

fn read_required(path: &Path) -> Result<String, String> {
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open {} ({error})", path.display()))?
    else {
        return Err(format!(
            "{} is required when organization policy is enabled",
            path.display()
        ));
    };
    let pin = read_file(file, path)?;
    if pin.len() != 64 || !pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("organization policy digest pin must be 64 hexadecimal characters".to_string());
    }
    Ok(pin.to_ascii_lowercase())
}

fn read_file(file: std::fs::File, path: &Path) -> Result<String, String> {
    let mut raw = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read {} ({error})", path.display()))?;
    if raw.len() as u64 > MAX_BYTES {
        return Err(format!("{} exceeds {MAX_BYTES} bytes", path.display()));
    }
    Ok(raw.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_pinned_bundle_without_weakening() {
        let root = std::env::temp_dir().join(format!("lgtm-org-bundle-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".lgtm")).expect("directory");
        let raw =
            r#"{"version":"2026-01","rules":[{"id":"x","severity":"error","instruction":"org"}]}"#;
        std::fs::write(root.join(".lgtm/org-policy.json"), raw).expect("bundle");
        std::fs::write(root.join(".lgtm/org-policy.sha256"), digest(raw)).expect("pin");
        let mut rules = vec![Rule {
            id: "x".to_string(),
            title: "x".to_string(),
            description: "x".to_string(),
            mechanism: super::super::Mechanism::Instruction,
            confidence: super::super::Confidence::High,
            examples: Vec::new(),
            limitations: vec!["x".to_string()],
            enforcement_stage: super::super::EnforcementStage::None,
            language_implementations: std::collections::BTreeMap::new(),
            severity: Severity::Warning,
            level: super::super::Level::Review,
            category: super::super::Category::Documentation,
            applies_to: super::super::AppliesTo {
                languages: Vec::new(),
                domains: Vec::new(),
                file_patterns: Vec::new(),
            },
            activation: super::super::Activation {
                change_types: Vec::new(),
                signals: Vec::new(),
            },
            instruction: "base".to_string(),
            enforcement: super::super::Enforcement {
                mode: super::super::EnforcementMode::Instruction,
                checks: Vec::new(),
            },
            overridable: true,
            evidence: super::super::Evidence {
                required: vec!["review".to_string()],
            },
            references: vec!["test".to_string()],
        }];
        assert_eq!(
            apply(&root, &mut rules).expect("bundle"),
            Some(format!("organization@2026-01:{}", digest(raw)))
        );
        assert_eq!(rules[0].instruction, "org");
        std::fs::remove_dir_all(root).ok();
    }
}
