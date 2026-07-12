//! High-confidence HTML/CSS accessibility and responsive review signals.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut accessibility = Vec::new();
    let mut responsive = Vec::new();
    for file in files {
        let extension = Path::new(file).extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("html" | "htm" | "tsx" | "jsx" | "css")) {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(file) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(file) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if (lower.contains("<img") && !lower.contains(" alt="))
                || (lower.contains("<input")
                    && !lower.contains("aria-label")
                    && !lower.contains("<label"))
            {
                accessibility.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
            if lower.contains("style=") || (lower.contains("px") && lower.contains("!important")) {
                responsive.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
        }
    }
    vec![
        result(
            "ui-accessibility-review",
            accessibility,
            "Review missing labels, roles, and image alternatives.",
        ),
        result(
            "ui-responsive-review",
            responsive,
            "Review fixed styling and responsive viewport behavior.",
        ),
    ]
}

fn result(rule_id: &str, locations: Vec<Location>, summary: &str) -> EnforcementResult {
    let status = if locations.is_empty() {
        Status::NotApplicable
    } else {
        Status::Warning
    };
    EnforcementResult {
        rule_id: rule_id.to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() { format!("{summary} No high-confidence signal found.") } else { format!("{summary} ({} finding(s)).", locations.len()) },
        locations,
        remediation: (status == Status::Warning).then(|| "Fix the high-confidence signal and verify responsive/accessibility behavior at configured viewports.".to_string()),
        evidence: ResultEvidence { check: "native.ui-review".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_missing_alt_and_fixed_inline_style() {
        let path = std::env::temp_dir().join(format!("lgtm-ui-{}.html", std::process::id()));
        std::fs::write(
            &path,
            "<img src='x'><div style='width: 400px !important'>x</div>",
        )
        .expect("fixture");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(results[0].status, Status::Warning);
        assert_eq!(results[1].status, Status::Warning);
        std::fs::remove_file(path).ok();
    }
}
