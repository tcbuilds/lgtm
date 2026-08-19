use std::path::{Path, PathBuf};

use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

pub(super) fn repo_root(cwd: Option<&str>) -> Option<PathBuf> {
    crate::hooks::root::resolve(cwd).ok()
}

pub(super) fn resolve_target(root: &Path, file_path: &str) -> Option<String> {
    let root = std::fs::canonicalize(root).ok()?;
    let candidate = Path::new(file_path);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let canonical = canonical_regular_target(&root, resolved)?;
    Some(canonical.to_string_lossy().into_owned())
}

pub(super) fn resolve_read_path(root: &Path, cwd: Option<&str>, file_path: &str) -> Option<String> {
    let root = std::fs::canonicalize(root).ok()?;
    let base = cwd
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .unwrap_or_else(|| root.clone());
    let base = std::fs::canonicalize(base).ok()?;
    if !base.is_dir() || !base.starts_with(&root) {
        return None;
    }
    let candidate = Path::new(file_path);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };
    let canonical = canonical_regular_target(&root, resolved)?;
    let relative = canonical.strip_prefix(&root).ok()?;
    (!relative.as_os_str().is_empty())
        .then(|| relative.to_str().map(str::to_owned))
        .flatten()
}

fn canonical_regular_target(root: &Path, resolved: PathBuf) -> Option<PathBuf> {
    let metadata = std::fs::symlink_metadata(&resolved).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let canonical = std::fs::canonicalize(resolved).ok()?;
    canonical.starts_with(root).then_some(canonical)
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
