use std::path::{Path, PathBuf};

use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

pub(super) fn repo_root(cwd: Option<&str>) -> Option<PathBuf> {
    let candidate = match cwd {
        Some(cwd) if !cwd.trim().is_empty() => PathBuf::from(cwd),
        _ => std::env::current_dir().ok()?,
    };
    let canonical = std::fs::canonicalize(candidate).ok()?;
    canonical.is_dir().then_some(canonical)
}

pub(super) fn resolve_target(root: &Path, file_path: &str) -> Option<String> {
    let candidate = Path::new(file_path);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let metadata = std::fs::symlink_metadata(&resolved).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let canonical = std::fs::canonicalize(resolved).ok()?;
    canonical
        .starts_with(root)
        .then(|| canonical.to_string_lossy().into_owned())
}

pub(super) fn unverified_target(file_path: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Unverified,
        severity: Severity::Error,
        message: format!(
            "Secret scan unverified: the edited path is outside the repository, absent, or not a regular file ({}).",
            sanitize(file_path)
        ),
        locations: Vec::new(),
        remediation: Some(
            "Use a regular file contained by the repository and run the edit again.".to_string(),
        ),
        evidence: ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

pub(super) fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}
