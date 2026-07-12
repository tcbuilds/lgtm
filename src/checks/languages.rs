//! Small native language checks used when a repository has no external linter.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const MAX_SOURCE_BYTES: u64 = 512 * 1024;

#[derive(Clone, Copy)]
struct RuleSpec {
    id: &'static str,
    extensions: &'static [&'static str],
    needles: &'static [&'static str],
    message: &'static str,
}

const RULES: [RuleSpec; 9] = [
    RuleSpec {
        id: "rust-no-unsafe",
        extensions: &["rs"],
        needles: &["unsafe ", "unsafe{"],
        message: "Rust unsafe requires an architecture-approved invariant review.",
    },
    RuleSpec {
        id: "rust-no-unwrap-expect",
        extensions: &["rs"],
        needles: &[".unwrap(", ".expect("],
        message: "Rust production paths should use typed error handling instead of unwrap/expect.",
    },
    RuleSpec {
        id: "rust-spawn-cancellation",
        extensions: &["rs"],
        needles: &["tokio::spawn(", "thread::spawn("],
        message: "Spawned Rust tasks require cancellation and error reporting.",
    },
    RuleSpec {
        id: "rust-no-mutable-global",
        extensions: &["rs"],
        needles: &["static mut "],
        message: "Mutable Rust globals require an explicit architecture review.",
    },
    RuleSpec {
        id: "typescript-no-any",
        extensions: &["ts", "tsx", "js", "jsx"],
        needles: &[": any", "as any", "<any>"],
        message: "TypeScript boundaries should use unknown or a precise type instead of any.",
    },
    RuleSpec {
        id: "typescript-unsafe-unknown",
        extensions: &["ts", "tsx", "js", "jsx"],
        needles: &["JSON.parse(", "response.json()"],
        message: "External JSON must be parsed as unknown and narrowed before use.",
    },
    RuleSpec {
        id: "typescript-api-response-validation",
        extensions: &["ts", "tsx", "js", "jsx"],
        needles: &["fetch("],
        message: "API responses require explicit runtime validation before use.",
    },
    RuleSpec {
        id: "react-no-state-mutation",
        extensions: &["tsx", "jsx"],
        needles: &[".state =", "this.state["],
        message: "React state must be updated through the state setter, never mutated in place.",
    },
    RuleSpec {
        id: "react-unstable-key",
        extensions: &["tsx", "jsx"],
        needles: &["key={index}", "key={i}"],
        message: "React list keys must use stable domain IDs instead of array indexes.",
    },
];

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    RULES.iter().map(|rule| scan_rule(rule, files)).collect()
}

fn scan_rule(rule: &RuleSpec, files: &[String]) -> EnforcementResult {
    let applicable: Vec<_> = files
        .iter()
        .filter(|file| {
            Path::new(file)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| rule.extensions.contains(&extension))
        })
        .collect();
    if applicable.is_empty() {
        return result(rule, Status::NotApplicable, Vec::new());
    }
    let mut locations = Vec::new();
    for file in applicable {
        let language = match Path::new(file)
            .extension()
            .and_then(|extension| extension.to_str())
        {
            Some("rs") => "rust",
            Some("ts" | "tsx") => "typescript",
            Some("js" | "jsx") => "javascript",
            _ => "unsupported",
        };
        if crate::structure::analyze_file(Path::new(file), language).is_err() {
            return result(rule, Status::Unverified, Vec::new());
        }
        let Ok(metadata) = std::fs::metadata(file) else {
            return result(rule, Status::Unverified, Vec::new());
        };
        if metadata.len() > MAX_SOURCE_BYTES {
            return result(rule, Status::Unverified, Vec::new());
        }
        let Ok(source) = std::fs::read_to_string(file) else {
            return result(rule, Status::Unverified, Vec::new());
        };
        for (line, text) in source.lines().enumerate() {
            if rule.needles.iter().any(|needle| text.contains(needle)) {
                locations.push(Location {
                    file: file.clone(),
                    line: Some((line + 1) as u64),
                });
            }
        }
    }
    let status = if locations.is_empty() {
        Status::Passed
    } else {
        Status::Failed
    };
    result(rule, status, locations)
}

fn result(rule: &RuleSpec, status: Status, locations: Vec<Location>) -> EnforcementResult {
    let failed = status == Status::Failed;
    EnforcementResult {
        rule_id: rule.id.to_string(),
        status,
        severity: Severity::Warning,
        message: if failed {
            format!("{} ({} finding(s)).", rule.message, locations.len())
        } else {
            rule.message.to_string()
        },
        locations,
        remediation: failed
            .then(|| "Fix the finding, then rerun the native language check.".to_string()),
        evidence: ResultEvidence {
            check: format!("native.{}", rule.id),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_findings_are_line_localized() {
        let path = std::env::temp_dir().join(format!("lgtm-rust-check-{}.rs", std::process::id()));
        std::fs::write(&path, "fn main() {\n let value = thing.unwrap();\n}\n").expect("source");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        let rule = results
            .iter()
            .find(|result| result.rule_id == "rust-no-unwrap-expect")
            .expect("rule");
        assert_eq!(rule.status, Status::Failed);
        assert_eq!(rule.locations[0].line, Some(2));
        assert_eq!(
            results
                .iter()
                .find(|result| result.rule_id == "rust-spawn-cancellation")
                .unwrap()
                .status,
            Status::Passed
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn clean_typescript_is_passed_and_python_is_not_applicable() {
        let path = std::env::temp_dir().join(format!("lgtm-ts-check-{}.ts", std::process::id()));
        std::fs::write(&path, "const value: unknown = input;\n").expect("source");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(
            results
                .iter()
                .find(|result| result.rule_id == "typescript-no-any")
                .unwrap()
                .status,
            Status::Passed
        );
        assert_eq!(
            results
                .iter()
                .find(|result| result.rule_id == "rust-no-unsafe")
                .unwrap()
                .status,
            Status::NotApplicable
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn unsafe_typescript_boundary_patterns_are_localized() {
        let path = std::env::temp_dir().join(format!("lgtm-ts-boundary-{}.ts", std::process::id()));
        std::fs::write(
            &path,
            "const value = JSON.parse(raw);\nconst response = fetch(url);\n",
        )
        .expect("source");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(
            results
                .iter()
                .find(|result| result.rule_id == "typescript-unsafe-unknown")
                .unwrap()
                .status,
            Status::Failed
        );
        assert_eq!(
            results
                .iter()
                .find(|result| result.rule_id == "typescript-api-response-validation")
                .unwrap()
                .status,
            Status::Failed
        );
        std::fs::remove_file(path).ok();
    }
}
