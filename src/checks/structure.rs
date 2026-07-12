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
        return vec![result(Status::NotApplicable, Vec::new())];
    }
    let mut findings = Vec::new();
    for file in applicable {
        let language = language_for(Path::new(file)).expect("supported extension");
        let analysis = match crate::structure::analyze_file(Path::new(file), language) {
            Ok(analysis) => analysis,
            Err(_) => return vec![result(Status::Unverified, Vec::new())],
        };
        findings.extend(
            analysis
                .functions
                .into_iter()
                .filter(|function| function.lines > HARD_FUNCTION_LINES)
                .map(|function| Location {
                    file: file.clone(),
                    line: Some(function.start_line as u64),
                }),
        );
    }
    vec![result(
        if findings.is_empty() {
            Status::Passed
        } else {
            Status::Failed
        },
        findings,
    )]
}

fn result(status: Status, locations: Vec<Location>) -> EnforcementResult {
    let failed = status == Status::Failed;
    EnforcementResult {
        rule_id: "function-size".to_string(),
        status,
        severity: Severity::Warning,
        message: if failed {
            format!(
                "Function-size review found {} function(s) over {} lines.",
                locations.len(),
                HARD_FUNCTION_LINES
            )
        } else {
            "Function-size review passed or was not applicable.".to_string()
        },
        locations,
        remediation: failed.then(|| {
            "Split the function or document a parser/table/state-machine exemption.".to_string()
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
}
