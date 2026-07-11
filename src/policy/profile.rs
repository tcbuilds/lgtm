use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use super::{Rule, Severity};
use crate::checks::EnforcementResult;

const MAX_CONFIG_BYTES: u64 = 256 * 1_024;
const SOURCES: [(&str, &str); 4] = [
    (
        "default",
        include_str!("../../policy/profiles/default.json"),
    ),
    ("strict", include_str!("../../policy/profiles/strict.json")),
    (
        "prototype",
        include_str!("../../policy/profiles/prototype.json"),
    ),
    (
        "infrastructure",
        include_str!("../../policy/profiles/infrastructure.json"),
    ),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    name: String,
    rules: BTreeMap<String, Overlay>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    severity: Severity,
    required_evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RepoConfig {
    #[serde(default = "default_name")]
    profile: String,
}

fn default_name() -> String {
    "default".to_string()
}

pub fn load_name(root: &Path) -> Result<String, String> {
    let path = root.join(".lgtm/config.json");
    let Some(file) = crate::fsutil::open_regular_file(&path)
        .map_err(|error| format!("open profile config ({error})"))?
    else {
        return Ok(default_name());
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read profile config ({error})"))?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("profile config exceeds maximum size".to_string());
    }
    if raw.trim().is_empty() {
        return Ok(default_name());
    }
    let config: RepoConfig = serde_json::from_str(&raw)
        .map_err(|error| format!("malformed profile config ({error})"))?;
    parse(&config.profile)?;
    Ok(config.profile)
}

pub fn validate_name(name: &str) -> Result<(), String> {
    parse(name).map(|_| ())
}

pub fn resolve(name: &str, rules: &[Rule]) -> Result<Vec<Rule>, String> {
    let profile = parse(name)?;
    validate(&profile, rules)?;
    let mut resolved = rules.to_vec();
    for rule in &mut resolved {
        if let Some(overlay) = profile.rules.get(&rule.id) {
            rule.severity = overlay.severity;
            rule.evidence
                .required
                .clone_from(&overlay.required_evidence);
        }
    }
    Ok(resolved)
}

pub fn apply_results(
    name: &str,
    rules: &[Rule],
    results: &mut [EnforcementResult],
) -> Result<(), String> {
    let resolved = resolve(name, rules)?;
    apply_resolved_results(&resolved, results);
    Ok(())
}

pub fn apply_resolved_results(rules: &[Rule], results: &mut [EnforcementResult]) {
    let severities: BTreeMap<_, _> = rules.iter().map(|rule| (&rule.id, rule.severity)).collect();
    for result in results {
        if let Some(severity) = severities.get(&result.rule_id) {
            result.severity = *severity;
        }
    }
}

pub fn validate_embedded(rules: &[Rule]) -> Result<(), String> {
    for (name, _) in SOURCES {
        validate(&parse(name)?, rules)?;
    }
    Ok(())
}

fn parse(name: &str) -> Result<Profile, String> {
    let source = SOURCES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, source)| *source)
        .ok_or_else(|| format!("unknown profile `{}`", safe_name(name)))?;
    let profile: Profile = serde_json::from_str(source)
        .map_err(|error| format!("embedded profile `{name}` malformed ({error})"))?;
    if profile.name != name {
        return Err(format!("embedded profile name mismatch for `{name}`"));
    }
    Ok(profile)
}

fn safe_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}

fn validate(profile: &Profile, rules: &[Rule]) -> Result<(), String> {
    let ids: BTreeSet<_> = rules.iter().map(|rule| rule.id.as_str()).collect();
    for (id, overlay) in &profile.rules {
        if !ids.contains(id.as_str()) {
            return Err(format!(
                "profile `{}` references unknown rule `{id}`",
                profile.name
            ));
        }
        if overlay.required_evidence.is_empty() {
            return Err(format!(
                "profile `{}` rule `{id}` requires no evidence",
                profile.name
            ));
        }
        let unique: BTreeSet<_> = overlay.required_evidence.iter().collect();
        if unique.len() != overlay.required_evidence.len() {
            return Err(format!(
                "profile `{}` rule `{id}` duplicates evidence",
                profile.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "profile/tests.rs"]
mod tests;
