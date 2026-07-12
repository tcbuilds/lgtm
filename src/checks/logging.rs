//! Secret-adjacent logging review that never echoes the logged value.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const SENSITIVE: [&str; 8] = [
    "password",
    "token",
    "cookie",
    "authorization",
    "set-cookie",
    "raw_body",
    "payload",
    "pii",
];

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    for file in files {
        let path = Path::new(file);
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let logging =
                lower.contains("print") || lower.contains("log") || lower.contains("logger");
            if logging && SENSITIVE.iter().any(|term| lower.contains(term)) {
                locations.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
        }
    }
    let status = if files.is_empty() {
        Status::NotApplicable
    } else if locations.is_empty() {
        Status::Passed
    } else {
        Status::Warning
    };
    vec![EnforcementResult {
        rule_id: "sensitive-logging-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() { "No sensitive logging signals were found.".to_string() } else { format!("Review {} sensitive logging signal(s); values are intentionally redacted.", locations.len()) },
        locations,
        remediation: (status == Status::Warning).then(|| "Redact or remove credentials, auth headers, cookies, PII, and raw payloads from logs.".to_string()),
        evidence: ResultEvidence { check: "native.sensitive-logging".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_sensitive_logging_without_echoing_value() {
        let path = std::env::temp_dir().join(format!("lgtm-logging-{}.py", std::process::id()));
        std::fs::write(&path, "logger.info('token=%s', token)\n").expect("fixture");
        let file = path.to_string_lossy().into_owned();
        let results = scan(std::slice::from_ref(&file));
        assert_eq!(results[0].status, Status::Warning);
        assert!(!results[0].message.contains("token=%s"));
        std::fs::remove_file(path).ok();
    }
}
