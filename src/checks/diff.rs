use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

mod association;
mod changes;
#[cfg(test)]
mod drift_tests;
mod inline_tests;

use association::{
    association_evidence, behavior_association_message, bug_association_message,
    classify_changes_with_patch,
};
use changes::{parse_name_status, parse_paths};

struct ChangeSet {
    files: BTreeSet<String>,
    test_evidence_excluded: BTreeSet<String>,
    patch: String,
}

struct Evaluation<'a> {
    bug: Status,
    behavior: Status,
    bug_message: String,
    behavior_message: String,
    association_evidence: Vec<String>,
    preserve: Status,
    unrelated: Option<&'a BTreeSet<String>>,
    dependency: bool,
    auth: bool,
    anti_slop: bool,
    error_contract: bool,
    behavior_test_quality: bool,
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
                        &[],
                        Vec::new(),
                    )
                })
                .collect();
        }
    };
    let association = classify_changes_with_patch(
        root,
        &changes.files,
        &changes.test_evidence_excluded,
        &changes.patch,
    );
    let source_changed = !association.sources.is_empty();
    let association_missing = !association.missing_sources.is_empty();
    let association_unverified = !association.unverified.is_empty();
    let behavior_status = if association_missing || association_unverified {
        Status::Unverified
    } else {
        Status::Passed
    };
    let bug_status =
        if intent == Some("bug-fix") && (source_changed || !association.tests.is_empty()) {
            if association_missing || association_unverified {
                Status::Unverified
            } else {
                Status::Passed
            }
        } else if intent == Some("bug-fix") && association_unverified {
            Status::Unverified
        } else {
            Status::NotApplicable
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
    let anti_slop = contains_anti_slop_signal(&changes.patch);
    let error_contract = contains_error_contract_signal(&changes.patch);
    let behavior_test_quality = contains_trivial_test_signal(&changes.patch);
    build_results(
        &changes,
        Evaluation {
            bug: bug_status,
            behavior: behavior_status,
            bug_message: bug_association_message(bug_status, &association),
            behavior_message: behavior_association_message(behavior_status, &association),
            association_evidence: association_evidence(&association),
            preserve: preserve_status,
            unrelated: unrelated.as_ref(),
            dependency,
            auth,
            anti_slop,
            error_contract,
            behavior_test_quality,
        },
    )
}

fn build_results(changes: &ChangeSet, evaluation: Evaluation<'_>) -> Vec<EnforcementResult> {
    let locations = locations(&changes.files);
    let empty = Vec::<String>::new();
    [
        (
            "regression-test-required",
            evaluation.bug,
            Severity::Error,
            "Bug fixes require a corresponding regression test.",
            &evaluation.association_evidence,
            locations.clone(),
        ),
        (
            "new-behavior-tests-required",
            evaluation.behavior,
            Severity::Error,
            "Source behavior changes require corresponding test changes.",
            &evaluation.association_evidence,
            locations.clone(),
        ),
        (
            "preserve-unrelated-user-changes",
            evaluation.preserve,
            Severity::Error,
            &preserve_message(evaluation.unrelated),
            &empty,
            locations.clone(),
        ),
        (
            "new-dependency-review",
            warning_status(evaluation.dependency),
            Severity::Warning,
            "Dependency files changed; review necessity, license, maintenance, and supply-chain risk.",
            &empty,
            locations.clone(),
        ),
        (
            "auth-change-security-review",
            warning_status(evaluation.auth),
            Severity::Warning,
            "Authentication or security-sensitive code changed; perform a focused security review.",
            &empty,
            locations.clone(),
        ),
        (
            "anti-slop-checklist",
            warning_status(evaluation.anti_slop),
            Severity::Warning,
            "Diff contains a high-confidence anti-slop review signal; remove debug/scaffolding or document the suppression.",
            &empty,
            Vec::new(),
        ),
        (
            "error-contract-review",
            warning_status(evaluation.error_contract),
            Severity::Warning,
            "New boundary failure text should include action, entity, reason, and retryability.",
            &empty,
            locations,
        ),
        (
            "behavior-test-quality",
            warning_status(evaluation.behavior_test_quality),
            Severity::Warning,
            "Test diff contains a high-confidence smoke-only or trivial assertion signal.",
            &empty,
            Vec::new(),
        ),
    ]
    .into_iter()
    .map(|(rule, status, severity, message, evidence, locations)| {
        let message = match rule {
            "regression-test-required" => &evaluation.bug_message,
            "new-behavior-tests-required" => &evaluation.behavior_message,
            _ => message,
        };
        result(rule, status, severity, message, evidence, locations)
    })
    .collect()
}

fn contains_anti_slop_signal(patch: &str) -> bool {
    patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .any(|line| {
            let lower = line.to_ascii_lowercase();
            [
                "println!(",
                "print(",
                "console.log(",
                "pdb.set_trace(",
                "debugger;",
                "eslint-disable",
                "# noqa",
                "type: ignore",
                "todo: remove",
            ]
            .iter()
            .any(|signal| lower.contains(signal))
        })
}

fn contains_error_contract_signal(patch: &str) -> bool {
    patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .any(|line| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("failed") || lower.contains("error:"))
                && ["entity=", "reason=", "retryable="]
                    .iter()
                    .all(|field| !lower.contains(field))
        })
}

fn contains_trivial_test_signal(patch: &str) -> bool {
    patch
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .any(|line| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("assert!(true")
                || lower.contains("expect(true")
                || lower.trim_end().ends_with("pass"))
                && (lower.contains("test")
                    || lower.contains("spec")
                    || lower.contains("assert")
                    || lower.contains("pass"))
        })
}

fn collect(root: &Path) -> Result<ChangeSet, String> {
    let mut files = BTreeSet::new();
    let mut test_evidence_excluded = BTreeSet::new();
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
        parse_name_status(&bytes, &mut files, &mut test_evidence_excluded)?;
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
    parse_paths(&bytes, &mut files, &mut test_evidence_excluded)?;
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
        test_evidence_excluded,
        patch: String::from_utf8_lossy(&patch).into_owned(),
    })
}

pub fn changed_files(root: &Path) -> Result<BTreeSet<String>, String> {
    collect(root).map(|changes| changes.files)
}

fn result(
    rule: &str,
    status: Status,
    severity: Severity,
    message: &str,
    finding_descriptions: &[String],
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
            finding_descriptions: finding_descriptions.to_vec(),
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
        "error-contract-review",
        "behavior-test-quality",
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
    match (files.is_empty(), touched.is_empty(), unrelated.is_empty()) {
        (true, _, _) => Status::Passed,
        (_, true, _) => Status::Unverified,
        (_, _, true) => Status::Passed,
        _ => Status::Failed,
    }
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
    .into_iter()
    .any(|name| file.ends_with(name))
}
fn is_auth_path(file: &str) -> bool {
    file.to_ascii_lowercase().split('/').any(|part| {
        ["auth", "security"]
            .iter()
            .any(|needle| part.contains(needle))
    })
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
    .into_iter()
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
