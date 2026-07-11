//! Offline Semgrep adapter for the embedded Python policy rules.

use std::path::Path;
use std::process::{Command, Stdio};

use serde::Deserialize;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const SEMGREP_BIN: &str = "semgrep";
const RULES: &str = include_str!("../../policy/semgrep-python.yml");
const RULE_IDS: [&str; 5] = [
    "external-call-timeout",
    "public-input-validation",
    "sql-parameterization",
    "bounded-retries-loops",
    "destructive-operation-safeguards",
];

#[derive(Deserialize)]
struct Output {
    #[serde(default)]
    results: Vec<Finding>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct Finding {
    check_id: String,
    path: String,
    start: Start,
}

#[derive(Deserialize)]
struct Start {
    line: u64,
}

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    scan_with_binary(SEMGREP_BIN, files)
}

pub fn installed_version() -> Option<String> {
    version_with_binary(SEMGREP_BIN)
}

fn scan_with_binary(binary: &str, files: &[String]) -> Vec<EnforcementResult> {
    let files: Vec<_> = files
        .iter()
        .filter(|file| file.ends_with(".py") && Path::new(file).is_file())
        .collect();
    if files.is_empty() {
        return RULE_IDS.iter().map(|rule| not_applicable(rule)).collect();
    }
    let version = version_with_binary(binary);
    match run(binary, &files) {
        Ok(findings) => normalize(findings, version),
        Err(reason) => RULE_IDS
            .iter()
            .map(|rule| unverified(rule, &reason, version.clone()))
            .collect(),
    }
}

fn run(binary: &str, files: &[&String]) -> Result<Vec<Finding>, String> {
    let directory = crate::checks::gitleaks::report::ReportDir::create()
        .map_err(|reason| format!("prepare embedded Semgrep rules ({reason})"))?;
    let rules_path = directory.report_path().with_file_name("semgrep-python.yml");
    std::fs::write(&rules_path, RULES)
        .map_err(|error| format!("write embedded Semgrep rules ({error})"))?;
    let mut command = Command::new(binary);
    command
        .arg("scan")
        .arg("--config")
        .arg(rules_path)
        .arg("--json")
        .arg("--error")
        .arg("--metrics")
        .arg("off")
        .args(files)
        .stdin(Stdio::null());
    let Some((code, stdout)) = crate::checks::gitleaks::runner::run_captured(command) else {
        return Err("semgrep missing, timed out, or could not be waited on".to_string());
    };
    if !matches!(code, Some(0 | 1)) {
        return Err(format!(
            "semgrep exited with status {}",
            code.map_or_else(|| "signal".to_string(), |value| value.to_string())
        ));
    }
    let output: Output = serde_json::from_slice(&stdout)
        .map_err(|error| format!("could not parse semgrep JSON ({error})"))?;
    if !output.errors.is_empty() {
        return Err(format!(
            "semgrep reported {} scan error(s)",
            output.errors.len()
        ));
    }
    if output.results.iter().any(|finding| {
        !RULE_IDS
            .iter()
            .any(|rule| finding_matches_rule(&finding.check_id, rule))
    }) {
        return Err("semgrep returned an unknown policy rule id".to_string());
    }
    Ok(output.results)
}

fn version_with_binary(binary: &str) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("--version").stdin(Stdio::null());
    let (code, stdout) = crate::checks::gitleaks::runner::run_captured(command)?;
    if code != Some(0) {
        return None;
    }
    let value = String::from_utf8_lossy(&stdout);
    let value = value.trim();
    (!value.is_empty()).then(|| format!("semgrep {value}"))
}

fn normalize(findings: Vec<Finding>, version: Option<String>) -> Vec<EnforcementResult> {
    RULE_IDS
        .iter()
        .map(|rule| {
            let locations = findings
                .iter()
                .filter(|finding| finding_matches_rule(&finding.check_id, rule))
                .map(|finding| Location {
                    file: sanitize(&finding.path),
                    line: Some(finding.start.line),
                })
                .collect::<Vec<_>>();
            if locations.is_empty() {
                passed(rule, version.clone())
            } else {
                failed(rule, locations, version.clone())
            }
        })
        .collect()
}

fn finding_matches_rule(check_id: &str, rule: &str) -> bool {
    check_id
        .strip_prefix("lgtm.")
        .or_else(|| check_id.rsplit_once(".lgtm.").map(|(_, suffix)| suffix))
        .is_some_and(|check| check == rule || check.starts_with(&format!("{rule}-")))
}

fn base(rule: &str, status: Status, version: Option<String>) -> EnforcementResult {
    EnforcementResult {
        rule_id: rule.to_string(),
        status,
        severity: Severity::Error,
        message: format!(
            "{rule}: Semgrep policy check {}.",
            if status == Status::Passed {
                "passed"
            } else {
                "could not run"
            }
        ),
        locations: Vec::new(),
        remediation: None,
        evidence: ResultEvidence {
            check: format!("semgrep.{rule}"),
            tool_version: version,
            finding_descriptions: Vec::new(),
        },
    }
}

fn passed(rule: &str, version: Option<String>) -> EnforcementResult {
    base(rule, Status::Passed, version)
}
fn not_applicable(rule: &str) -> EnforcementResult {
    base(rule, Status::NotApplicable, None)
}

fn unverified(rule: &str, reason: &str, version: Option<String>) -> EnforcementResult {
    let mut result = base(rule, Status::Unverified, version);
    result.message = format!(
        "{rule}: Semgrep check could not run ({}).",
        sanitize(reason)
    );
    result.remediation = Some("Install Semgrep and rerun the edit or Stop check.".to_string());
    result
}

fn failed(rule: &str, locations: Vec<Location>, version: Option<String>) -> EnforcementResult {
    let mut result = base(rule, Status::Failed, version);
    result.message = format!(
        "{rule}: Semgrep found {} policy violation(s).",
        locations.len()
    );
    result.locations = locations;
    result.remediation = Some(
        "Fix the reported policy violation at each location, then rerun the check.".to_string(),
    );
    result
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        directory: std::path::PathBuf,
        binary: String,
        source: String,
    }

    impl Fixture {
        fn create(output: &str, exit: i32) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "lgtm-semgrep-{}-{exit}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).expect("fixture directory");
            let binary_path = directory.join("semgrep");
            let script = format!(
                "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 1.2.3; exit 0; fi\n[ \"$1\" = scan ] || exit 9\n[ \"$2\" = --config ] || exit 9\n[ \"$4\" = --json ] || exit 9\n[ \"$5\" = --error ] || exit 9\n[ \"$6\" = --metrics ] || exit 9\n[ \"$7\" = off ] || exit 9\nprintf '%s' '{}'\nexit {exit}\n",
                output.replace('\'', "'\\''")
            );
            std::fs::write(&binary_path, script).expect("fake tool");
            let mut permissions = std::fs::metadata(&binary_path)
                .expect("metadata")
                .permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(&binary_path, permissions).expect("executable");
            let source_path = directory.join("sample.py");
            std::fs::write(&source_path, "print('safe')\n").expect("source");
            Self {
                directory,
                binary: binary_path.to_string_lossy().into_owned(),
                source: source_path.to_string_lossy().into_owned(),
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn exit_one_normalizes_findings_and_clean_rules() {
        let output = r#"{"results":[{"check_id":"policy.lgtm.external-call-timeout-requests","path":"sample.py","start":{"line":7}},{"check_id":"policy.lgtm.sql-parameterization","path":"sample.py","start":{"line":9}}],"errors":[]}"#;
        let fixture = Fixture::create(output, 1);
        let results = scan_with_binary(&fixture.binary, std::slice::from_ref(&fixture.source));
        assert_eq!(results.len(), 5);
        assert_eq!(
            results
                .iter()
                .find(|item| item.rule_id == "sql-parameterization")
                .unwrap()
                .status,
            Status::Failed
        );
        assert_eq!(
            results
                .iter()
                .find(|item| item.rule_id == "external-call-timeout")
                .unwrap()
                .status,
            Status::Failed
        );
        assert_eq!(
            results
                .iter()
                .filter(|item| item.status == Status::Passed)
                .count(),
            3
        );
    }

    #[test]
    fn exit_zero_with_empty_json_passes_every_rule() {
        let fixture = Fixture::create(r#"{"results":[]}"#, 0);
        let results = scan_with_binary(&fixture.binary, std::slice::from_ref(&fixture.source));
        assert!(results.iter().all(|item| item.status == Status::Passed));
    }

    #[test]
    fn tool_error_is_unverified_for_every_rule() {
        let fixture = Fixture::create(r#"{"results":[]}"#, 2);
        let results = scan_with_binary(&fixture.binary, std::slice::from_ref(&fixture.source));
        assert!(results.iter().all(|item| item.status == Status::Unverified));
    }

    #[test]
    fn reported_scan_errors_are_unverified_for_every_rule() {
        let fixture = Fixture::create(r#"{"results":[],"errors":[{"message":"parse"}]}"#, 0);
        let results = scan_with_binary(&fixture.binary, std::slice::from_ref(&fixture.source));
        assert!(results.iter().all(|item| item.status == Status::Unverified));
    }
}
