//! Review and expiry checks for temporary/disabled-code justification markers.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut findings = Vec::new();
    let mut expired = false;
    let today = today();
    for file in files {
        let Ok(source) = std::fs::read_to_string(Path::new(file)) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let marker = lower.contains("todo")
                || lower.contains("fixme")
                || lower.contains("temporary")
                || lower.contains("disable");
            if !marker {
                continue;
            }
            if !(lower.contains("reason=")
                && lower.contains("owner=")
                && lower.contains("expires=")
                && lower.contains("delete="))
            {
                findings.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
                continue;
            }
            if let Some(expiry) = lower
                .split("expires=")
                .nth(1)
                .and_then(|value| value.split_whitespace().next())
                && expiry.len() == 10
                && expiry < today.as_str()
            {
                expired = true;
                findings.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
        }
    }
    let status = if files.is_empty() {
        Status::NotApplicable
    } else if expired {
        Status::Failed
    } else if findings.is_empty() {
        Status::Passed
    } else {
        Status::Warning
    };
    vec![EnforcementResult {
        rule_id: "justification-metadata".to_string(),
        status,
        severity: if expired { Severity::Error } else { Severity::Warning },
        message: if expired { "Expired justification metadata must be removed or renewed.".to_string() } else if findings.is_empty() { "Temporary and disabled-code markers have complete justification metadata.".to_string() } else { format!("Review {} marker(s) missing owner, reason, expiry, or deletion condition.", findings.len()) },
        locations: findings,
        remediation: (status == Status::Failed || status == Status::Warning).then(|| "Add reason=, owner=, expires=YYYY-MM-DD, and delete=... metadata or remove the temporary marker.".to_string()),
        evidence: ResultEvidence { check: "native.justification".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }]
}

fn today() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_secs() / 86_400) as i64;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_complete_metadata_and_flags_expiry() {
        let path =
            std::env::temp_dir().join(format!("lgtm-justification-{}.py", std::process::id()));
        std::fs::write(&path, "# TODO fix later\n").expect("fixture");
        let file = path.to_string_lossy().into_owned();
        assert_eq!(scan(std::slice::from_ref(&file))[0].status, Status::Warning);
        let expired = format!(
            "# TODO reason=legacy owner=team expires={} delete=replace\n",
            "2000-01-01"
        );
        std::fs::write(&path, expired).expect("expired fixture");
        assert_eq!(scan(&[file])[0].status, Status::Failed);
        std::fs::remove_file(path).ok();
    }
}
