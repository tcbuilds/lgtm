use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

struct ChangeSet {
    files: BTreeSet<String>,
    patch: String,
}

struct Evaluation<'a> {
    bug: Status,
    behavior: Status,
    preserve: Status,
    unrelated: Option<&'a BTreeSet<String>>,
    dependency: bool,
    auth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    PostToolUse,
    Stop,
}

pub fn evaluate_at(
    root: &Path,
    touched: &BTreeSet<String>,
    baseline: Option<&BTreeSet<String>>,
    intent: Option<&str>,
    stage: Stage,
) -> Vec<EnforcementResult> {
    let mut results = evaluate(root, touched, baseline, intent);
    if stage == Stage::PostToolUse {
        defer_slice_completion(&mut results);
    }
    results
}

fn defer_slice_completion(results: &mut [EnforcementResult]) {
    for result in results {
        if result.status == Status::Failed
            && matches!(
                result.rule_id.as_str(),
                "regression-test-required" | "new-behavior-tests-required"
            )
        {
            result.status = Status::Warning;
            result
                .message
                .push_str(" Deferred until the Stop slice-completion gate.");
        }
    }
}

pub fn evaluate(
    root: &Path,
    touched: &BTreeSet<String>,
    baseline: Option<&BTreeSet<String>>,
    intent: Option<&str>,
) -> Vec<EnforcementResult> {
    let changes = match collect(root) {
        Ok(changes) => changes,
        Err(reason) => {
            return rule_ids()
                .map(|rule| {
                    result(
                        rule,
                        Status::Unverified,
                        Severity::Error,
                        &reason,
                        Vec::new(),
                    )
                })
                .collect();
        }
    };
    let source_changed = changes.files.iter().any(|file| is_source(file));
    let tests_changed = changes.files.iter().any(|file| is_test(file));
    let bug_status = match (intent, source_changed, tests_changed) {
        (Some("bug-fix"), true, false) => Status::Failed,
        (Some("bug-fix"), _, _) => Status::Passed,
        _ => Status::NotApplicable,
    };
    let behavior_status = if source_changed && !tests_changed {
        Status::Failed
    } else {
        Status::Passed
    };
    let unrelated: Option<BTreeSet<_>> = baseline.map(|baseline| {
        changes
            .files
            .difference(touched)
            .filter(|file| !baseline.contains(*file))
            .cloned()
            .collect()
    });
    let preserve_status = unrelated.as_ref().map_or(Status::Unverified, |unrelated| {
        preserve_status(&changes.files, touched, unrelated)
    });
    let dependency = changes.files.iter().any(|file| is_dependency(file));
    let auth =
        changes.files.iter().any(|file| is_auth_path(file)) || contains_auth_signal(&changes.patch);
    build_results(
        &changes,
        Evaluation {
            bug: bug_status,
            behavior: behavior_status,
            preserve: preserve_status,
            unrelated: unrelated.as_ref(),
            dependency,
            auth,
        },
    )
}

fn build_results(changes: &ChangeSet, evaluation: Evaluation<'_>) -> Vec<EnforcementResult> {
    let locations = locations(&changes.files);
    vec![
        result(
            "regression-test-required",
            evaluation.bug,
            Severity::Error,
            "Bug fixes require a corresponding regression test.",
            locations.clone(),
        ),
        result(
            "new-behavior-tests-required",
            evaluation.behavior,
            Severity::Error,
            "Source behavior changes require corresponding test changes.",
            locations.clone(),
        ),
        result(
            "preserve-unrelated-user-changes",
            evaluation.preserve,
            Severity::Error,
            &preserve_message(evaluation.unrelated),
            locations.clone(),
        ),
        result(
            "new-dependency-review",
            warning_status(evaluation.dependency),
            Severity::Warning,
            "Dependency files changed; review necessity, license, maintenance, and supply-chain risk.",
            locations.clone(),
        ),
        result(
            "auth-change-security-review",
            warning_status(evaluation.auth),
            Severity::Warning,
            "Authentication or security-sensitive code changed; perform a focused security review.",
            locations,
        ),
    ]
}

fn collect(root: &Path) -> Result<ChangeSet, String> {
    let mut files = BTreeSet::new();
    for cached in [false, true] {
        let mut command = Command::new("git");
        command.arg("-C").arg(root).arg("diff");
        if cached {
            command.arg("--cached");
        }
        command.args(["--name-status", "-z"]);
        let (code, bytes) = crate::checks::gitleaks::runner::run_captured(command)
            .ok_or("git diff unavailable or timed out")?;
        if !matches!(code, Some(0)) {
            return Err("git diff failed or repository is unavailable".to_string());
        }
        parse_name_status(&bytes, &mut files)?;
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--others", "--exclude-standard", "-z"]);
    let (code, bytes) = crate::checks::gitleaks::runner::run_captured(command)
        .ok_or("git untracked-file collection unavailable or timed out")?;
    if !matches!(code, Some(0)) {
        return Err("git untracked-file collection failed".to_string());
    }
    parse_paths(&bytes, &mut files)?;
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["diff", "--no-ext-diff", "--unified=0", "HEAD"]);
    let (code, patch) = crate::checks::gitleaks::runner::run_captured(command)
        .ok_or("git patch unavailable or timed out")?;
    if !matches!(code, Some(0)) {
        return Err("git patch failed or repository is unavailable".to_string());
    }
    Ok(ChangeSet {
        files,
        patch: String::from_utf8_lossy(&patch).into_owned(),
    })
}

pub fn changed_files(root: &Path) -> Result<BTreeSet<String>, String> {
    collect(root).map(|changes| changes.files)
}

fn parse_paths(bytes: &[u8], files: &mut BTreeSet<String>) -> Result<(), String> {
    for field in bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
    {
        let path = std::str::from_utf8(field).map_err(|_| "git path was not UTF-8")?;
        if path.starts_with('/') || path.split('/').any(|part| part == "..") {
            return Err("unsafe git path".to_string());
        }
        files.insert(path.to_string());
    }
    Ok(())
}

fn parse_name_status(bytes: &[u8], files: &mut BTreeSet<String>) -> Result<(), String> {
    let fields: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect();
    let mut index = 0;
    while index < fields.len() {
        let status = std::str::from_utf8(fields[index]).map_err(|_| "git status was not UTF-8")?;
        index += 1;
        let paths = usize::from(status.starts_with('R') || status.starts_with('C')) + 1;
        if index + paths > fields.len() {
            return Err("malformed git name-status output".to_string());
        }
        for field in &fields[index..index + paths] {
            let path = std::str::from_utf8(field).map_err(|_| "git path was not UTF-8")?;
            if path.starts_with('/') || path.split('/').any(|part| part == "..") {
                return Err("unsafe git path".to_string());
            }
            files.insert(path.to_string());
        }
        index += paths;
    }
    Ok(())
}

fn result(
    rule: &str,
    status: Status,
    severity: Severity,
    message: &str,
    locations: Vec<Location>,
) -> EnforcementResult {
    EnforcementResult {
        rule_id: rule.to_string(),
        status,
        severity,
        message: message.to_string(),
        locations,
        remediation: matches!(status, Status::Failed | Status::Warning).then(|| {
            "Review the diff and add required tests or review evidence before completion."
                .to_string()
        }),
        evidence: ResultEvidence {
            check: "git.diff".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

fn rule_ids() -> impl Iterator<Item = &'static str> {
    [
        "regression-test-required",
        "new-behavior-tests-required",
        "preserve-unrelated-user-changes",
        "new-dependency-review",
        "auth-change-security-review",
    ]
    .into_iter()
}
fn locations(files: &BTreeSet<String>) -> Vec<Location> {
    files
        .iter()
        .map(|file| Location {
            file: file.clone(),
            line: None,
        })
        .collect()
}
fn warning_status(found: bool) -> Status {
    if found {
        Status::Warning
    } else {
        Status::NotApplicable
    }
}
fn preserve_status(
    files: &BTreeSet<String>,
    touched: &BTreeSet<String>,
    unrelated: &BTreeSet<String>,
) -> Status {
    if files.is_empty() {
        Status::Passed
    } else if touched.is_empty() {
        Status::Unverified
    } else if unrelated.is_empty() {
        Status::Passed
    } else {
        Status::Failed
    }
}
fn is_test(file: &str) -> bool {
    file.starts_with("tests/")
        || file.contains("/tests/")
        || file.ends_with("_test.py")
        || file.ends_with(".spec.ts")
}
fn is_source(file: &str) -> bool {
    file.ends_with(".py") && !is_test(file)
}
fn is_dependency(file: &str) -> bool {
    [
        "Cargo.toml",
        "Cargo.lock",
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "pnpm-lock.yaml",
        "package-lock.json",
    ]
    .iter()
    .any(|name| file.ends_with(name))
}
fn is_auth_path(file: &str) -> bool {
    file.to_ascii_lowercase()
        .split('/')
        .any(|part| part.contains("auth") || part.contains("security"))
}
fn contains_auth_signal(patch: &str) -> bool {
    let patch = patch.to_ascii_lowercase();
    [
        "password",
        "token",
        "permission",
        "authorize",
        "authenticate",
        "session",
    ]
    .iter()
    .any(|signal| patch.contains(signal))
}
fn preserve_message(unrelated: Option<&BTreeSet<String>>) -> String {
    let Some(unrelated) = unrelated else {
        return "Pre-edit diff baseline is missing or malformed; unrelated changes cannot be verified.".to_string();
    };
    if unrelated.is_empty() {
        "All diff files were recorded as touched in this session.".to_string()
    } else {
        format!(
            "Diff includes files not recorded in this session: {}.",
            unrelated.iter().cloned().collect::<Vec<_>>().join(", ")
        )
    }
}

#[cfg(test)]
#[path = "diff/tests.rs"]
mod tests;
