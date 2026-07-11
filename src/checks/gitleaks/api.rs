//! Gitleaks wrapper for scanning touched files without exposing secrets.

use std::path::Path;
use std::process::{Command, Stdio};

#[path = "report.rs"]
mod report;
#[path = "result.rs"]
mod result;
#[path = "runner.rs"]
mod runner;

use report::{ReportDir, ScanOutcome};
use result::{failed, passed, passed_with_version, unverified};
use runner::{run_captured, run_scan};

const GITLEAKS_BIN: &str = "gitleaks";

pub fn scan(files: &[String]) -> crate::checks::EnforcementResult {
    scan_with_binary(GITLEAKS_BIN, files)
}

pub fn installed_version() -> Option<String> {
    tool_version(GITLEAKS_BIN)
}

fn scan_with_binary(binary: &str, files: &[String]) -> crate::checks::EnforcementResult {
    let existing: Vec<_> = files
        .iter()
        .filter(|file| Path::new(file).exists())
        .collect();
    if existing.is_empty() {
        return passed();
    }
    let version = tool_version(binary);
    let mut aggregated = Vec::new();
    for file in existing {
        match run_gitleaks(binary, file) {
            ScanOutcome::Unverified(reason) => return unverified(reason, version),
            ScanOutcome::Findings(findings) => aggregated.extend(findings),
        }
    }
    if aggregated.is_empty() {
        passed_with_version(version)
    } else {
        failed(&aggregated, version)
    }
}

fn tool_version(binary: &str) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("version").stdin(Stdio::null());
    let (code, stdout) = run_captured(command)?;
    if code != Some(0) {
        return None;
    }
    let raw = String::from_utf8_lossy(&stdout);
    let version = raw.trim();
    (!version.is_empty()).then(|| format!("gitleaks {version}"))
}

fn run_gitleaks(binary: &str, file: &str) -> ScanOutcome {
    let report_dir = match ReportDir::create() {
        Ok(directory) => directory,
        Err(reason) => return ScanOutcome::Unverified(reason),
    };
    let report_path = report_dir.report_path();
    let mut command = Command::new(binary);
    command
        .arg("detect")
        .arg("--no-git")
        .arg("--report-format")
        .arg("json")
        .arg("--report-path")
        .arg(&report_path)
        .arg("--exit-code")
        .arg("2")
        .arg("--redact")
        .arg("--no-banner")
        .arg("--source")
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_scan(command, &report_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::Status;

    #[test]
    fn no_existing_files_passes() {
        let result = scan(&["/nonexistent/lgtm/does/not/exist.py".to_string()]);
        assert_eq!(result.status, Status::Passed);
    }

    #[test]
    fn absent_binary_reports_unverified_with_remediation() {
        let binary = format!("/lgtm-missing-gitleaks-{}", std::process::id());
        let path = std::env::temp_dir().join(format!("lgtm-gitleaks-{}.py", std::process::id()));
        std::fs::write(&path, "api_key = 'x'\n").expect("fixture writable");
        let result = scan_with_binary(&binary, &[path.to_string_lossy().to_string()]);
        std::fs::remove_file(path).ok();
        assert_eq!(result.status, Status::Unverified);
        assert!(
            result
                .remediation
                .is_some_and(|text| text.contains("gitleaks"))
        );
    }
}
