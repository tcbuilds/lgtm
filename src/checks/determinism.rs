//! Determinism review for unit-test paths.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    for file in files {
        let lower_path = file.to_ascii_lowercase();
        if !is_test_path(&lower_path)
            || lower_path.contains("integration")
            || lower_path.contains("e2e")
        {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(Path::new(file)) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("sleep(")
                || lower.contains("thread::sleep")
                || lower.contains("math.random")
                || lower.contains("random.random")
                || lower.contains("rand::random")
                || lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("requests.get")
                || lower.contains("fetch(")
            {
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
        rule_id: "determinism-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() { "No high-confidence nondeterminism signals were found in unit-test paths.".to_string() } else { format!("Review {} nondeterminism signal(s) or mark the test as integration/e2e.", locations.len()) },
        locations,
        remediation: (status == Status::Warning).then(|| "Seed randomness, replace real sleeps/network calls, isolate fixtures, or explicitly mark integration/e2e scope.".to_string()),
        evidence: ResultEvidence { check: "native.determinism".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }]
}

fn is_test_path(path: &str) -> bool {
    path.contains("/tests/")
        || path.contains("\\tests\\")
        || path.ends_with("_test.py")
        || path.ends_with(".spec.ts")
        || path.ends_with(".test.ts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unit_sleep_and_allows_e2e_marker() {
        let root = std::env::temp_dir().join(format!("lgtm-determinism-{}", std::process::id()));
        std::fs::create_dir_all(root.join("tests")).expect("tests");
        let unit = root.join("tests/unit.py");
        let e2e = root.join("tests/e2e.spec.ts");
        std::fs::write(&unit, "time.sleep(1)\n").expect("unit");
        std::fs::write(&e2e, "fetch('https://example.test')\n").expect("e2e");
        assert_eq!(
            scan(&[unit.to_string_lossy().into_owned()])[0].status,
            Status::Warning
        );
        assert_eq!(
            scan(&[e2e.to_string_lossy().into_owned()])[0].status,
            Status::Passed
        );
        std::fs::remove_dir_all(root).ok();
    }
}
