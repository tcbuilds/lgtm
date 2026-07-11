//! Deterministic task-context construction from repository observables.

mod commands;
mod model;
mod signals;

use std::collections::BTreeSet;
use std::path::{Component, Path};

pub use model::TaskContext;

use crate::detect::detect;
use crate::fsutil::read_optional_bounded;

const MAX_FILES: usize = 1_024;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_DIFF_BYTES: usize = 256 * 1_024;
const MAX_TOUCHED_FILE_BYTES: u64 = 64 * 1_024;

/// Build context from touched repo-relative paths, diff text, and repo metadata.
pub fn build(root: &Path, touched_files: &[String], diff: &str) -> TaskContext {
    let detection = detect(root);
    let files_touched = normalize_paths(touched_files);
    let mut languages = detection.languages.iter().cloned().collect();
    let mut domains = BTreeSet::new();
    let mut risk_signals = BTreeSet::new();

    for path in &files_touched {
        signals::add_path_observations(path, &mut languages, &mut domains, &mut risk_signals);
        let content = read_optional_bounded(&root.join(path), MAX_TOUCHED_FILE_BYTES);
        signals::add_content_observations(&content, &mut domains, &mut risk_signals);
    }
    let metadata = read_optional_bounded(&root.join("pyproject.toml"), MAX_TOUCHED_FILE_BYTES);
    signals::add_content_observations(&metadata, &mut domains, &mut risk_signals);
    let bounded_diff = truncate_utf8(diff, MAX_DIFF_BYTES);
    signals::add_content_observations(bounded_diff, &mut domains, &mut risk_signals);

    TaskContext {
        languages: languages.into_iter().collect(),
        domains: domains.into_iter().collect(),
        files_touched,
        risk_signals: risk_signals.into_iter().collect(),
        repository_commands: commands::repository_commands(&detection),
    }
}

fn normalize_paths(paths: &[String]) -> Vec<String> {
    let mut normalized = BTreeSet::new();
    for path in paths.iter().take(MAX_FILES) {
        let portable = path.replace('\\', "/");
        if portable.len() <= MAX_PATH_BYTES && is_safe_relative_path(&portable) {
            normalized.insert(portable);
        }
    }
    normalized.into_iter().collect()
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !has_windows_drive_prefix(value)
        && !value.contains('\0')
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests;
