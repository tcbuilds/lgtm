//! Review high-confidence string-built unsafe boundaries.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    for file in files {
        let Ok(metadata) = std::fs::metadata(Path::new(file)) else {
            continue;
        };
        if !metadata.is_file() || metadata.len() > 256 * 1024 {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(Path::new(file)) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let shell = (lower.contains("subprocess")
                || lower.contains("child_process")
                || lower.contains("command"))
                && lower.contains('+');
            let html = lower.contains("innerhtml") && lower.contains('+');
            let sql = (lower.contains("select ")
                || lower.contains("insert ")
                || lower.contains("update "))
                && lower.contains('+');
            let url_or_json = (lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("json.stringify"))
                && lower.contains('+');
            if shell || html || sql || url_or_json {
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
        rule_id: "safe-construction-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() { "No high-confidence string-built boundary signals were found.".to_string() } else { format!("Review {} string-built boundary signal(s); use contextual builders and escaping.", locations.len()) },
        locations,
        remediation: (status == Status::Warning).then(|| "Use parameterized SQL, argv/builders, contextual escaping, and typed serializers instead of concatenation.".to_string()),
        evidence: ResultEvidence { check: "native.safe-construction".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_string_built_shell_and_sql_boundaries() {
        let path =
            std::env::temp_dir().join(format!("lgtm-construction-{}.py", std::process::id()));
        std::fs::write(
            &path,
            "subprocess.run('git ' + user)\nquery = 'SELECT * ' + value\n",
        )
        .expect("fixture");
        let results = scan(&[path.to_string_lossy().into_owned()]);
        assert_eq!(results[0].status, Status::Warning);
        assert_eq!(results[0].locations.len(), 2);
        std::fs::remove_file(path).ok();
    }
}
