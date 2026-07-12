//! Conservative public-endpoint control signals.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    let mut missing = Vec::new();
    for file in files {
        let lower_path = file.to_ascii_lowercase();
        let Ok(source) = std::fs::read_to_string(Path::new(file)) else {
            continue;
        };
        let lower_source = source.to_ascii_lowercase();
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let endpoint = lower.contains("@app.get")
                || lower.contains("@app.post")
                || lower.contains("@router.")
                || lower.contains("app.get(")
                || lower.contains("app.post(")
                || lower.contains("router.get(")
                || lower_path.contains("/api/")
                || lower.contains("export async function get(")
                || lower.contains("export async function post(");
            if !endpoint {
                continue;
            }
            let controls = [
                contains_any(
                    &lower_source,
                    &["validate", "schema", "parse(", "pydantic", "zod"],
                ),
                contains_any(
                    &lower_source,
                    &["auth", "session", "jwt", "current_user", "require"],
                ),
                contains_any(
                    &lower_source,
                    &["ratelimit", "rate_limit", "throttle", "limiter"],
                ),
                contains_any(
                    &lower_source,
                    &["httponly", "secure", "csrf", "cors", "debug=false"],
                ),
            ];
            let missing_count = controls.iter().filter(|present| !**present).count();
            if missing_count > 0 {
                missing.push((file.clone(), (index + 1) as u64, missing_count));
            } else {
                locations.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
        }
    }
    if files.is_empty() {
        return vec![result(
            Status::NotApplicable,
            Vec::new(),
            "No files were changed.",
        )];
    }
    if missing.is_empty() && locations.is_empty() {
        return vec![result(
            Status::NotApplicable,
            Vec::new(),
            "No supported public endpoint signal was found.",
        )];
    }
    let mut findings = locations;
    findings.extend(missing.iter().map(|(file, line, _)| Location {
        file: file.clone(),
        line: Some(*line),
    }));
    let status = if missing.is_empty() {
        Status::Unverified
    } else {
        Status::Warning
    };
    let message = if missing.is_empty() {
        "Lexical control signals are present; runtime auth, validation, rate-limit, and secure-default semantics remain unverified.".to_string()
    } else {
        format!(
            "{} public endpoint signal(s) lack one or more required control categories; runtime semantics remain review.",
            missing.len()
        )
    };
    vec![result(status, findings, &message)]
}

fn contains_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| source.contains(needle))
}

fn result(status: Status, locations: Vec<Location>, message: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: "auth-input-enforcement".to_string(),
        status,
        severity: Severity::Warning,
        message: message.to_string(),
        locations,
        remediation: Some("Add runtime boundary validation, server-side authorization, rate limiting, secure cookies/CORS/CSRF, and non-debug defaults; attach runtime evidence.".to_string()),
        evidence: ResultEvidence { check: "native.auth-input-enforcement".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_missing_controls_from_unverified_complete_signals() {
        let root = std::env::temp_dir().join(format!("lgtm-auth-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        let weak = root.join("weak.py");
        std::fs::write(&weak, "@app.post('/x')\ndef x(): pass\n").expect("weak");
        assert_eq!(
            scan(&[weak.to_string_lossy().into_owned()])[0].status,
            Status::Warning
        );
        let strong = root.join("strong.py");
        std::fs::write(
            &strong,
            "@app.post('/x')\nvalidate schema auth session rate_limit csrf secure debug=False\n",
        )
        .expect("strong");
        assert_eq!(
            scan(&[strong.to_string_lossy().into_owned()])[0].status,
            Status::Unverified
        );
        std::fs::remove_dir_all(root).ok();
    }
}
