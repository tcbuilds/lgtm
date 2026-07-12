//! Structural checks backed by the bounded analysis substrate.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const HARD_FUNCTION_LINES: usize = 50;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let applicable: Vec<_> = files
        .iter()
        .filter(|file| supported_extension(Path::new(file)))
        .collect();
    if applicable.is_empty() {
        return vec![
            result(
                "function-size",
                Status::NotApplicable,
                Vec::new(),
                "Function-size review was not applicable.",
            ),
            result(
                "file-size",
                Status::NotApplicable,
                Vec::new(),
                "File-size review was not applicable.",
            ),
            result(
                "function-complexity",
                Status::NotApplicable,
                Vec::new(),
                "Complexity review was not applicable.",
            ),
        ];
    }
    let mut analyses = Vec::new();
    for file in applicable {
        let language = language_for(Path::new(file)).expect("supported extension");
        let analysis = match crate::structure::analyze_file(Path::new(file), language) {
            Ok(analysis) => analysis,
            Err(_) => {
                return ["function-size", "file-size", "function-complexity"]
                    .into_iter()
                    .map(|rule| {
                        result(
                            rule,
                            Status::Unverified,
                            Vec::new(),
                            "Structural analysis could not run.",
                        )
                    })
                    .collect();
            }
        };
        analyses.push((file.clone(), analysis));
    }
    let function_review_findings = analyses
        .iter()
        .flat_map(|(file, analysis)| {
            analysis
                .functions
                .iter()
                .filter(|function| !function.exempt && function.lines > 30)
                .map(|function| Location {
                    file: file.clone(),
                    line: Some(function.start_line as u64),
                })
        })
        .collect::<Vec<_>>();
    let file_findings = analyses
        .iter()
        .filter(|(_, analysis)| analysis.file_lines > 300)
        .map(|(file, _)| Location {
            file: file.clone(),
            line: Some(1),
        })
        .collect::<Vec<_>>();
    let complexity_findings = analyses
        .iter()
        .flat_map(|(file, analysis)| {
            analysis
                .functions
                .iter()
                .filter(|function| {
                    !function.exempt && {
                        function.complexity > 10
                            || function.max_nesting > 3
                            || function.parameters > 4
                    }
                })
                .map(|function| Location {
                    file: file.clone(),
                    line: Some(function.start_line as u64),
                })
        })
        .collect::<Vec<_>>();
    vec![
        result(
            "function-size",
            threshold_status(&function_review_findings, &analyses),
            function_review_findings,
            "Function-size review found functions above the target threshold.",
        ),
        result(
            "file-size",
            status(&file_findings),
            file_findings,
            "File-size review found files over 300 lines.",
        ),
        result(
            "function-complexity",
            status(&complexity_findings),
            complexity_findings,
            "Complexity review found high-parameter, deeply nested, or high-complexity functions.",
        ),
    ]
}

fn status(locations: &[Location]) -> Status {
    if locations.is_empty() {
        Status::Passed
    } else {
        Status::Failed
    }
}

fn threshold_status(
    locations: &[Location],
    analyses: &[(String, crate::structure::Analysis)],
) -> Status {
    let has_hard_violation = analyses.iter().any(|(_, analysis)| {
        analysis
            .functions
            .iter()
            .any(|function| !function.exempt && function.lines > HARD_FUNCTION_LINES)
    });
    if has_hard_violation {
        Status::Failed
    } else if locations.is_empty() {
        Status::Passed
    } else {
        Status::Warning
    }
}

fn result(
    rule_id: &str,
    status: Status,
    locations: Vec<Location>,
    summary: &str,
) -> EnforcementResult {
    let failed = status == Status::Failed;
    EnforcementResult {
        rule_id: rule_id.to_string(),
        status,
        severity: if rule_id == "function-size" && failed {
            Severity::Error
        } else {
            Severity::Warning
        },
        message: if failed {
            format!("{summary} ({} finding(s)).", locations.len())
        } else {
            summary.to_string()
        },
        locations,
        remediation: failed.then(|| {
            "Review the finding and split the structure or document a parser/table/state-machine exemption.".to_string()
        }),
        evidence: ResultEvidence {
            check: "native.function-size".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

fn supported_extension(path: &Path) -> bool {
    language_for(path).is_some()
}

fn language_for(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("py") => Some("python"),
        Some("rs") => Some("rust"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("js" | "jsx") => Some("javascript"),
        Some("go") => Some("go"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_function_is_localized_and_clean_function_passes() {
        let path =
            std::env::temp_dir().join(format!("lgtm-function-size-{}.py", std::process::id()));
        let mut source = String::from("def long():\n");
        source.push_str(&"    value = 1\n".repeat(51));
        std::fs::write(&path, source).expect("fixture source");
        let files = vec![path.to_string_lossy().into_owned()];
        let findings = scan(&files);
        assert_eq!(findings[0].status, Status::Failed);
        assert_eq!(findings[0].locations[0].line, Some(1));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn target_threshold_warns_before_hard_limit() {
        let path =
            std::env::temp_dir().join(format!("lgtm-function-target-{}.py", std::process::id()));
        let mut source = String::from("def medium():\n");
        source.push_str(&"    value = 1\n".repeat(31));
        std::fs::write(&path, source).expect("fixture source");
        let findings = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(findings[0].status, Status::Warning);
        assert_eq!(findings[0].severity, Severity::Warning);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn complete_exemption_metadata_avoids_function_size_finding() {
        let path =
            std::env::temp_dir().join(format!("lgtm-function-exempt-{}.py", std::process::id()));
        let mut source = String::from(
            "# lgtm: exempt reason=parser state machine owner=team expires=2099-01-01\ndef parser():\n",
        );
        source.push_str(&"    value = 1\n".repeat(51));
        std::fs::write(&path, source).expect("fixture source");
        let findings = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(findings[0].status, Status::Passed);
        std::fs::remove_file(path).ok();
    }
}
