//! Conservative cross-language boundary-error review.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    for file in files {
        let path = Path::new(file);
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !matches!(extension, "py" | "ts" | "tsx" | "js" | "jsx") {
            continue;
        }
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        let lines: Vec<_> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let boundary = trimmed.starts_with("except") || trimmed.starts_with("catch");
            let retry = trimmed.to_ascii_lowercase().contains("retry");
            if !boundary && !retry {
                continue;
            }
            let followup = lines.get(index + 1).map_or("", |value| value.trim());
            let nearby = lines
                .iter()
                .skip(index + 1)
                .take(8)
                .copied()
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase();
            let empty_handler = boundary
                && (followup == "pass"
                    || (followup.is_empty()
                        && !nearby.contains("throw")
                        && !nearby.contains("raise")));
            let unbounded_retry = retry
                && !nearby.contains("backoff")
                && !nearby.contains("jitter")
                && !nearby.contains("cancel")
                && !nearby.contains("timeout");
            if empty_handler || unbounded_retry {
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
        rule_id: "boundary-error-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() {
            "No clearly swallowed boundary errors were found.".to_string()
        } else {
            format!("Review {} boundary error path(s).", locations.len())
        },
        locations,
        remediation: (status == Status::Warning).then(|| {
            "Add context, convert the external error, or rethrow it with a documented reason."
                .to_string()
        }),
        evidence: ResultEvidence {
            check: "native.boundary-errors".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_empty_python_except_and_clean_catch() {
        let path = std::env::temp_dir().join(format!("lgtm-boundary-{}.py", std::process::id()));
        std::fs::write(&path, "try:\n    run()\nexcept Exception:\n    pass\n").expect("fixture");
        let file = path.to_string_lossy().into_owned();
        assert_eq!(scan(std::slice::from_ref(&file))[0].status, Status::Warning);
        std::fs::write(
            &path,
            "try:\n    run()\nexcept Exception:\n    raise RuntimeError('context')\n",
        )
        .expect("clean fixture");
        assert_eq!(scan(&[file])[0].status, Status::Passed);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn flags_retry_without_bounds_and_accepts_backoff_cancellation() {
        let path = std::env::temp_dir().join(format!("lgtm-retry-{}.py", std::process::id()));
        std::fs::write(&path, "for retry in range(3):\n    run()\n").expect("retry fixture");
        let file = path.to_string_lossy().into_owned();
        assert_eq!(scan(std::slice::from_ref(&file))[0].status, Status::Warning);
        std::fs::write(&path, "for retry in range(3):\n    backoff_and_cancel()\n")
            .expect("bounded fixture");
        assert_eq!(scan(&[file])[0].status, Status::Passed);
        std::fs::remove_file(path).ok();
    }
}
