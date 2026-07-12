//! Conservative naming review for clearly placeholder identifiers.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const VAGUE: [&str; 8] = [
    "foo", "bar", "baz", "tmp", "thing", "stuff", "foobar", "xxx",
];

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    let mut test_locations = Vec::new();
    for file in files {
        let path = Path::new(file);
        let Some(language) = language(path) else {
            continue;
        };
        let Ok(analysis) = crate::structure::analyze_file(path, language) else {
            continue;
        };
        for function in analysis.functions {
            if VAGUE.contains(&function.name.to_ascii_lowercase().as_str()) {
                locations.push(Location {
                    file: file.clone(),
                    line: Some(function.start_line as u64),
                });
            }
            if is_test_path(&file.to_ascii_lowercase())
                && matches!(
                    function.name.to_ascii_lowercase().as_str(),
                    "test" | "it" | "smoke" | "works"
                )
            {
                test_locations.push(Location {
                    file: file.clone(),
                    line: Some(function.start_line as u64),
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
    let mut results = vec![EnforcementResult {
        rule_id: "naming-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() {
            "No clearly placeholder function names were found.".to_string()
        } else {
            format!("Review {} placeholder identifier(s).", locations.len())
        },
        locations,
        remediation: (status == Status::Warning).then(|| {
            "Use a domain-specific verb-first name or document the protocol constraint.".to_string()
        }),
        evidence: ResultEvidence {
            check: "native.naming".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }];
    let test_status = if files.is_empty() {
        Status::NotApplicable
    } else if test_locations.is_empty() {
        Status::Passed
    } else {
        Status::Warning
    };
    results.push(EnforcementResult {
        rule_id: "test-naming-review".to_string(),
        status: test_status,
        severity: Severity::Warning,
        message: if test_locations.is_empty() {
            "No generic test names were found.".to_string()
        } else {
            format!("Review {} generic test name(s).", test_locations.len())
        },
        locations: test_locations,
        remediation: (test_status == Status::Warning)
            .then(|| "Name tests after the observable behavior they verify.".to_string()),
        evidence: ResultEvidence {
            check: "native.test-naming".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    });
    results
}

fn language(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => Some("python"),
        Some("rs") => Some("rust"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("js" | "jsx") => Some("javascript"),
        Some("go") => Some("go"),
        _ => None,
    }
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
    fn flags_only_clearly_placeholder_function_names() {
        let path = std::env::temp_dir().join(format!("lgtm-naming-{}.py", std::process::id()));
        std::fs::write(&path, "def foo(value):\n    return value\n").expect("fixture");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(results[0].status, Status::Warning);
        assert_eq!(results[0].locations[0].line, Some(1));
        assert_eq!(results[1].status, Status::Passed);
        std::fs::remove_file(path).ok();
    }
}
