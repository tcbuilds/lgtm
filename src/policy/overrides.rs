use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Rule, Severity};
use crate::checks::{EnforcementResult, Status};

const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    disabled_rules: Vec<String>,
    #[serde(default)]
    severity_overrides: BTreeMap<String, Severity>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverrideRecord {
    pub rule_id: String,
    pub action: String,
    pub severity: Option<Severity>,
}

pub fn apply(root: &Path, rules: &mut [Rule]) -> Result<Vec<OverrideRecord>, String> {
    let config = load(root)?;
    validate(&config, rules)?;
    let mut records = Vec::new();
    for rule in rules {
        if config.disabled_rules.contains(&rule.id) {
            records.push(OverrideRecord {
                rule_id: rule.id.clone(),
                action: "disabled".to_string(),
                severity: None,
            });
        } else if let Some(severity) = config.severity_overrides.get(&rule.id) {
            rule.severity = *severity;
            records.push(OverrideRecord {
                rule_id: rule.id.clone(),
                action: "severity".to_string(),
                severity: Some(*severity),
            });
        }
    }
    Ok(records)
}

pub fn apply_results(records: &[OverrideRecord], results: &mut [EnforcementResult]) {
    for result in results {
        if records
            .iter()
            .any(|record| record.rule_id == result.rule_id && record.action == "disabled")
        {
            result.status = Status::Overridden;
            result.message = format!(
                "{} disabled by validated repository policy.",
                result.rule_id
            );
            result.remediation = None;
        }
    }
}

fn load(root: &Path) -> Result<Config, String> {
    let path = root.join(".lgtm/config.json");
    let Some(file) = crate::fsutil::open_regular_file(&path)
        .map_err(|error| format!("open policy config ({error})"))?
    else {
        return Ok(Config::default());
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read policy config ({error})"))?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("policy config exceeds maximum size".to_string());
    }
    serde_json::from_str(&raw).map_err(|error| format!("malformed policy overrides ({error})"))
}

fn validate(config: &Config, rules: &[Rule]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for id in &config.disabled_rules {
        if !seen.insert(id.clone()) {
            return Err(format!("disabled_rules contains duplicate rule `{id}`"));
        }
    }
    for id in config.severity_overrides.keys() {
        if seen.contains(id) {
            return Err(format!(
                "rule `{id}` is both disabled and severity-overridden"
            ));
        }
    }
    for id in seen.iter().chain(config.severity_overrides.keys()) {
        let rule = rules
            .iter()
            .find(|rule| &rule.id == id)
            .ok_or_else(|| format!("policy override references unknown rule `{id}`"))?;
        if !rule.overridable {
            return Err(format!(
                "rule `{id}` is security-critical or non-overridable"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(config: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lgtm-overrides-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(path.join(".lgtm")).unwrap();
        std::fs::write(path.join(".lgtm/config.json"), config).unwrap();
        path
    }

    #[test]
    fn applies_allowed_severity_and_records_it() {
        let root = root(r#"{"severity_overrides":{"regression-test-required":"warning"}}"#);
        let mut rules = super::super::load_embedded_registry().unwrap();
        let records = apply(&root, &mut rules).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].rule_id, "regression-test-required");
        assert_eq!(
            rules
                .iter()
                .find(|rule| rule.id == "regression-test-required")
                .unwrap()
                .severity,
            Severity::Warning
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rejects_non_overridable_and_unknown_rules() {
        for config in [
            r#"{"disabled_rules":["no-committed-secrets"]}"#,
            r#"{"disabled_rules":["unknown-rule"]}"#,
        ] {
            let root = root(config);
            let mut rules = super::super::load_embedded_registry().unwrap();
            assert!(apply(&root, &mut rules).is_err());
            std::fs::remove_dir_all(root).ok();
        }
    }

    #[test]
    fn disabled_result_and_record_are_explicit() {
        let root = root(r#"{"disabled_rules":["new-behavior-tests-required"]}"#);
        let mut rules = super::super::load_embedded_registry().unwrap();
        let records = apply(&root, &mut rules).unwrap();
        let mut results = vec![EnforcementResult {
            rule_id: "new-behavior-tests-required".to_string(),
            status: Status::Failed,
            severity: Severity::Error,
            message: "failed".to_string(),
            locations: Vec::new(),
            remediation: None,
            evidence: crate::checks::ResultEvidence {
                check: "git.diff".to_string(),
                tool_version: None,
                finding_descriptions: Vec::new(),
            },
        }];
        apply_results(&records, &mut results);
        assert_eq!(results[0].status, Status::Overridden);
        assert!(results[0].remediation.is_none());
        assert_eq!(
            serde_json::to_value(&records).unwrap()[0]["action"],
            "disabled"
        );
        std::fs::remove_dir_all(root).ok();
    }
}
