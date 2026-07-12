//! Local evidence-only telemetry summary; never transmits data.

use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 256;

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct StatsReport {
    pub records: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub noisy_rules: Vec<RuleCount>,
    pub slowest_commands_ms: Vec<u64>,
    pub missing_tools: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RuleCount {
    pub rule_id: String,
    pub findings: usize,
}

pub fn summarize(path: &Path) -> Result<StatsReport, String> {
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open evidence ({error})"))?
    else {
        return Err(format!("evidence file is missing: {}", path.display()));
    };
    let mut raw = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read evidence ({error})"))?;
    if raw.len() as u64 > MAX_BYTES {
        return Err("evidence exceeds maximum size".to_string());
    }
    let mut report = StatsReport::default();
    let mut rule_counts = BTreeMap::new();
    for (index, line) in raw.lines().enumerate() {
        if index >= MAX_RECORDS {
            return Err(format!("evidence exceeds {MAX_RECORDS} records"));
        }
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("malformed evidence line {} ({error})", index + 1))?;
        report.records += 1;
        if let Some(results) = value.get("results").and_then(serde_json::Value::as_array) {
            for result in results {
                if let Some(status) = result.get("status").and_then(serde_json::Value::as_str) {
                    *report.status_counts.entry(status.to_string()).or_default() += 1;
                }
                if let (Some(rule), Some(status)) = (
                    result.get("rule_id").and_then(serde_json::Value::as_str),
                    result.get("status").and_then(serde_json::Value::as_str),
                ) && matches!(status, "failed" | "warning")
                {
                    *rule_counts.entry(rule.to_string()).or_default() += 1;
                }
            }
        }
        if let Some(commands) = value.get("commands").and_then(serde_json::Value::as_array) {
            for command in commands {
                if let Some(duration) = command
                    .get("duration_ms")
                    .and_then(serde_json::Value::as_u64)
                {
                    report.slowest_commands_ms.push(duration);
                }
                if command
                    .get("exit_code")
                    .is_some_and(serde_json::Value::is_null)
                {
                    report.missing_tools += 1;
                }
            }
        }
    }
    report.slowest_commands_ms.sort_unstable_by(|a, b| b.cmp(a));
    report.slowest_commands_ms.truncate(5);
    report.noisy_rules = rule_counts
        .into_iter()
        .map(|(rule_id, findings)| RuleCount { rule_id, findings })
        .collect();
    report
        .noisy_rules
        .sort_by(|left, right| right.findings.cmp(&left.findings));
    report.noisy_rules.truncate(10);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_statuses_slow_commands_and_missing_tools() {
        let path = std::env::temp_dir().join(format!("lgtm-stats-{}.jsonl", std::process::id()));
        std::fs::write(
            &path,
            r#"{"results":[{"rule_id":"x","status":"failed"},{"rule_id":"x","status":"warning"}],"commands":[{"duration_ms":42,"exit_code":null}]}"#,
        )
        .expect("evidence");
        let report = summarize(&path).expect("summary");
        assert_eq!(report.records, 1);
        assert_eq!(report.status_counts["failed"], 1);
        assert_eq!(report.noisy_rules[0].findings, 2);
        assert_eq!(report.slowest_commands_ms, vec![42]);
        assert_eq!(report.missing_tools, 1);
        std::fs::remove_file(path).ok();
    }
}
