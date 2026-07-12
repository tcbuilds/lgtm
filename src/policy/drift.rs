//! Deterministic policy bundle drift reporting.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use super::{Rule, Severity};

#[derive(Debug, Serialize)]
pub struct DriftReport {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub severity_changed: Vec<String>,
    pub hardening: Vec<String>,
}

pub fn compare(candidate: &Path) -> Result<DriftReport, String> {
    let base = super::load_embedded_registry().map_err(|error| error.to_string())?;
    let installed = super::authoring::load_file(candidate)?;
    Ok(compare_rules(&base, &installed))
}

pub fn enforce_acceptance(report: &DriftReport, accepted: bool) -> Result<(), String> {
    if !report.hardening.is_empty() && !accepted {
        return Err(format!(
            "policy drift adds or strengthens hard rules: {}; rerun with --accept-hardening",
            report.hardening.join(", ")
        ));
    }
    Ok(())
}

fn compare_rules(base: &[Rule], installed: &[Rule]) -> DriftReport {
    let base_map: BTreeMap<_, _> = base.iter().map(|rule| (&rule.id, rule)).collect();
    let installed_map: BTreeMap<_, _> = installed.iter().map(|rule| (&rule.id, rule)).collect();
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut severity_changed = Vec::new();
    let mut hardening = Vec::new();
    for (id, rule) in &installed_map {
        match base_map.get(id) {
            None => {
                added.push((*id).clone());
                if rule.severity == Severity::Error {
                    hardening.push((*id).clone());
                }
            }
            Some(previous) if previous.severity != rule.severity => {
                severity_changed.push((*id).clone());
                if rank(rule.severity) > rank(previous.severity) {
                    hardening.push((*id).clone());
                }
            }
            Some(_) => {}
        }
    }
    for id in base_map.keys() {
        if !installed_map.contains_key(id) {
            removed.push((*id).clone());
        }
    }
    DriftReport {
        added,
        removed,
        severity_changed,
        hardening,
    }
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
    fn detects_added_hard_rule() {
        let base = vec![rule("base", Severity::Warning)];
        let installed = vec![rule("base", Severity::Error), rule("new", Severity::Error)];
        let report = compare_rules(&base, &installed);
        assert_eq!(report.added, vec!["new"]);
        assert_eq!(report.severity_changed, vec!["base"]);
        assert_eq!(report.hardening, vec!["base", "new"]);
        assert!(enforce_acceptance(&report, false).is_err());
        assert!(enforce_acceptance(&report, true).is_ok());
    }

    fn rule(id: &str, severity: Severity) -> Rule {
        Rule {
            id: id.to_string(),
            title: id.to_string(),
            description: id.to_string(),
            mechanism: super::super::Mechanism::Instruction,
            confidence: super::super::Confidence::High,
            examples: Vec::new(),
            limitations: vec!["test".to_string()],
            enforcement_stage: super::super::EnforcementStage::None,
            language_implementations: std::collections::BTreeMap::new(),
            severity,
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
            instruction: id.to_string(),
            enforcement: super::super::Enforcement {
                mode: super::super::EnforcementMode::Instruction,
                checks: Vec::new(),
            },
            overridable: true,
            evidence: super::super::Evidence {
                required: vec!["review".to_string()],
            },
            references: vec!["test".to_string()],
        }
    }
}
