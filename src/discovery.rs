//! Bounded, deterministic discovery of nested workspaces and quality gates.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fsutil::{open_regular_file, read_optional_bounded};

const MAX_DEPTH: usize = 8;
const MAX_WORKSPACES: usize = 64;
const MAX_ENTRIES: usize = 4096;
const MAX_FILESYSTEM_ENTRIES: usize = 64 * 1024;
const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_GITIGNORE_MATCHING_WORK: usize = 4 * 1024 * 1024;
const MAX_GITIGNORE_PATTERN_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Workspace {
    pub id: String,
    pub language: String,
    pub root: PathBuf,
    pub commands: Vec<CommandSpec>,
    #[serde(default)]
    pub coverage: Vec<CoverageSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CoverageSpec {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub scope: String,
    pub line_threshold_percent: Option<u8>,
    pub branch_threshold_percent: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub tier: String,
    pub purpose: String,
    pub source: String,
    pub confidence: String,
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery root is not a directory: {path}")]
    RootNotDirectory { path: PathBuf },
    #[error("discovery refused symlink: {path}")]
    SymlinkRefused { path: PathBuf },
    #[error("discovery exceeded {limit} admitted entries")]
    EntryLimit { limit: usize },
    #[error("discovery exceeded {limit} filesystem scan entries")]
    FilesystemEntryLimit { limit: usize },
    #[error("discovery found more than {limit} workspaces")]
    WorkspaceLimit { limit: usize },
}

/// Find supported nested workspaces without executing repository code.
pub fn discover(root: &Path) -> Result<Vec<Workspace>, DiscoveryError> {
    discover_with_filesystem_limit(root, MAX_FILESYSTEM_ENTRIES)
}

fn discover_with_filesystem_limit(
    root: &Path,
    filesystem_entry_limit: usize,
) -> Result<Vec<Workspace>, DiscoveryError> {
    let metadata =
        std::fs::symlink_metadata(root).map_err(|_| DiscoveryError::RootNotDirectory {
            path: root.to_path_buf(),
        })?;
    if !metadata.is_dir() {
        return Err(DiscoveryError::RootNotDirectory {
            path: root.to_path_buf(),
        });
    }

    let mut candidates = Vec::new();
    let mut entries_seen = 0_usize;
    let mut filesystem_entries_seen = 0_usize;
    let mut gitignore_matching_work = 0_usize;
    let gitignore = read_gitignore_patterns(root, &mut gitignore_matching_work);
    let mut state = WalkState {
        entries_seen: &mut entries_seen,
        filesystem_entries_seen: &mut filesystem_entries_seen,
        filesystem_entry_limit,
        gitignore_matching_work: &mut gitignore_matching_work,
        candidates: &mut candidates,
    };
    walk(root, root, 0, &gitignore, &mut state)?;
    candidates.sort();
    candidates.dedup();

    let mut workspaces = Vec::new();
    for path in candidates {
        if let Some(workspace) = workspace_for(
            root,
            &path,
            &gitignore,
            &mut gitignore_matching_work,
            &mut filesystem_entries_seen,
            filesystem_entry_limit,
        )? {
            workspaces.push(workspace);
            if workspaces.len() > MAX_WORKSPACES {
                return Err(DiscoveryError::WorkspaceLimit {
                    limit: MAX_WORKSPACES,
                });
            }
        }
    }
    workspaces.sort_by(|left, right| left.root.cmp(&right.root));
    Ok(workspaces)
}

#[cfg(test)]
fn discover_with_test_filesystem_limit(
    root: &Path,
    filesystem_entry_limit: usize,
) -> Result<Vec<Workspace>, DiscoveryError> {
    discover_with_filesystem_limit(root, filesystem_entry_limit)
}

struct WalkState<'a> {
    entries_seen: &'a mut usize,
    filesystem_entries_seen: &'a mut usize,
    filesystem_entry_limit: usize,
    gitignore_matching_work: &'a mut usize,
    candidates: &'a mut Vec<PathBuf>,
}

struct ScannedEntry {
    entry: std::fs::DirEntry,
    is_dir: bool,
    is_file: bool,
}

fn walk(
    root: &Path,
    current: &Path,
    depth: usize,
    gitignore: &[GitignorePattern],
    state: &mut WalkState<'_>,
) -> Result<(), DiscoveryError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(current).map_err(|_| DiscoveryError::RootNotDirectory {
        path: current.to_path_buf(),
    })?;
    let mut scanned_entries = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| DiscoveryError::RootNotDirectory {
            path: current.to_path_buf(),
        })?;
        let path = entry.path();
        consume_filesystem_entry(state.filesystem_entries_seen, state.filesystem_entry_limit)?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| DiscoveryError::RootNotDirectory { path: path.clone() })?;
        if metadata.file_type().is_symlink() {
            return Err(DiscoveryError::SymlinkRefused { path });
        }
        scanned_entries.push(ScannedEntry {
            entry,
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
        });
    }
    scanned_entries.sort_by(|left, right| left.entry.path().cmp(&right.entry.path()));
    for entry in scanned_entries {
        let path = entry.entry.path();
        let file_name = entry.entry.file_name();
        let gitignore_ignored = gitignored(
            root,
            &path,
            gitignore,
            entry.is_dir,
            state.gitignore_matching_work,
        );
        if (entry.is_dir && ignored_dir(file_name.to_string_lossy().as_ref())) || gitignore_ignored
        {
            continue;
        }
        consume_admitted_entry(state.entries_seen)?;
        if entry.is_dir {
            walk(root, &path, depth + 1, gitignore, state)?;
        } else if entry.is_file && is_marker(path.file_name().and_then(|name| name.to_str())) {
            state
                .candidates
                .push(path.parent().unwrap_or(root).to_path_buf());
        }
    }
    Ok(())
}

fn consume_filesystem_entry(entries_seen: &mut usize, limit: usize) -> Result<(), DiscoveryError> {
    *entries_seen = entries_seen
        .checked_add(1)
        .ok_or(DiscoveryError::FilesystemEntryLimit { limit })?;
    if *entries_seen > limit {
        return Err(DiscoveryError::FilesystemEntryLimit { limit });
    }
    Ok(())
}

fn consume_admitted_entry(entries_seen: &mut usize) -> Result<(), DiscoveryError> {
    *entries_seen = entries_seen
        .checked_add(1)
        .ok_or(DiscoveryError::EntryLimit { limit: MAX_ENTRIES })?;
    if *entries_seen > MAX_ENTRIES {
        return Err(DiscoveryError::EntryLimit { limit: MAX_ENTRIES });
    }
    Ok(())
}

fn ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".lgtm"
            | ".claude"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | "vendor"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".mypy_cache"
            | ".pytest_cache"
            | ".next"
            | ".open-next"
            | ".turbo"
            | ".cache"
            | ".vite"
            | ".svelte-kit"
            | ".parcel-cache"
            | "coverage"
            | "out"
            | "storybook-static"
            // Fixture trees hold deliberately malformed sources used to exercise the
            // checkers. Registering them as workspaces points required commands at
            // code that is supposed to fail, which blocks every downstream gate.
            | "fixtures"
            | "testdata"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitignorePattern {
    segments: Vec<String>,
    negated: bool,
    anchored: bool,
    directory_only: bool,
    unsupported: bool,
}

impl GitignorePattern {
    fn fail_closed() -> Self {
        Self {
            segments: Vec::new(),
            negated: false,
            anchored: false,
            directory_only: false,
            unsupported: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobMatch {
    NoMatch,
    Matched,
    Unsupported,
    BudgetExceeded,
}

enum GitignoreContents {
    Missing,
    Invalid,
    Valid(String),
}

fn read_gitignore_contents(root: &Path) -> GitignoreContents {
    let path = root.join(".gitignore");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return GitignoreContents::Missing;
        }
        Err(_) => return GitignoreContents::Invalid,
    };
    if !metadata.file_type().is_file() {
        return GitignoreContents::Invalid;
    }
    let Ok(Some(file)) = open_regular_file(&path) else {
        return GitignoreContents::Invalid;
    };
    let mut contents = String::new();
    if file
        .take(MAX_METADATA_BYTES.saturating_add(1))
        .read_to_string(&mut contents)
        .is_err()
        || contents.len() as u64 > MAX_METADATA_BYTES
    {
        return GitignoreContents::Invalid;
    }
    GitignoreContents::Valid(contents)
}

fn read_gitignore_patterns(root: &Path, matching_work: &mut usize) -> Vec<GitignorePattern> {
    let contents = match read_gitignore_contents(root) {
        GitignoreContents::Missing => return Vec::new(),
        GitignoreContents::Invalid => return vec![GitignorePattern::fail_closed()],
        GitignoreContents::Valid(contents) => contents,
    };
    let mut patterns = Vec::new();
    let contents = contents.replace("\r\n", "\n");
    for line in contents.lines() {
        if line.bytes().any(|byte| byte.is_ascii_control()) {
            return vec![GitignorePattern::fail_closed()];
        }
        let pattern = line.trim_end();
        if pattern.is_empty() || pattern.starts_with('#') {
            continue;
        }
        let cost = pattern.len().saturating_add(1);
        if !consume_matching_work(matching_work, cost) {
            return vec![GitignorePattern::fail_closed()];
        }
        let pattern_is_overlong = pattern.len() > MAX_GITIGNORE_PATTERN_BYTES;
        let (negated, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern), |pattern| (true, pattern));
        let directory_only = pattern.ends_with('/');
        let directory_pattern = pattern.trim_end_matches('/');
        let anchored = directory_pattern.starts_with('/');
        let directory_pattern = directory_pattern.trim_start_matches('/');
        let segments: Vec<_> = directory_pattern
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(str::to_string)
            .collect();
        if segments.is_empty() {
            return vec![GitignorePattern::fail_closed()];
        }
        let unsupported = pattern_is_overlong
            || segments
                .iter()
                .any(|segment| pattern_is_unsupported(segment));
        if unsupported {
            return vec![GitignorePattern::fail_closed()];
        }
        patterns.push(GitignorePattern {
            segments,
            negated,
            anchored,
            directory_only,
            unsupported: false,
        });
    }
    patterns
}

fn gitignored(
    root: &Path,
    path: &Path,
    patterns: &[GitignorePattern],
    is_directory: bool,
    matching_work: &mut usize,
) -> bool {
    if patterns.is_empty() || !consume_matching_work(matching_work, 1) {
        return !patterns.is_empty();
    }
    let Some(path_segments) = relative_path_segments(root, path, matching_work) else {
        return true;
    };
    let mut ignored = false;
    let mut directory_scoped_ignore = false;
    let mut direct_file_ignore = false;
    for pattern in patterns {
        if !consume_matching_work(matching_work, 1) {
            return true;
        }
        let result = if !is_directory && pattern.directory_only {
            if !pattern.negated {
                continue;
            }
            gitignore_directory_ancestor_matches(pattern, &path_segments, matching_work)
        } else if pattern.unsupported {
            GlobMatch::Unsupported
        } else {
            gitignore_pattern_matches(pattern, &path_segments, matching_work)
        };
        match result {
            GlobMatch::Matched if pattern.negated => {
                if is_directory || !pattern.directory_only {
                    ignored = false;
                    directory_scoped_ignore = false;
                    direct_file_ignore = false;
                } else if directory_scoped_ignore && !direct_file_ignore {
                    ignored = false;
                    directory_scoped_ignore = false;
                }
            }
            GlobMatch::Matched => {
                ignored = true;
                if !is_directory && !pattern.directory_only {
                    let matches_ancestor =
                        match matches_directory_ancestor(pattern, &path_segments, matching_work) {
                            GlobMatch::Matched => true,
                            GlobMatch::NoMatch => false,
                            GlobMatch::Unsupported | GlobMatch::BudgetExceeded => return true,
                        };
                    let pattern_is_directory_scoped =
                        (pattern.anchored || pattern.segments.len() > 1) && matches_ancestor;
                    if pattern_is_directory_scoped {
                        // Preserve an independent direct-file ignore while adding an
                        // inherited directory-scoped source.
                        directory_scoped_ignore = true;
                    } else {
                        direct_file_ignore = true;
                    }
                } else {
                    direct_file_ignore = false;
                    directory_scoped_ignore = false;
                }
            }
            GlobMatch::Unsupported => return true,
            GlobMatch::NoMatch => {}
            GlobMatch::BudgetExceeded => return true,
        }
    }
    ignored
}

fn relative_path_segments(
    root: &Path,
    path: &Path,
    matching_work: &mut usize,
) -> Option<Vec<String>> {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut cost = 1_usize;
    for component in relative.components() {
        let Component::Normal(segment) = component else {
            continue;
        };
        cost = cost.checked_add(segment.len().checked_add(1)?)?;
    }
    if !consume_matching_work(matching_work, cost) {
        return None;
    }
    let mut segments = Vec::new();
    for component in relative.components() {
        if let Component::Normal(segment) = component {
            segments.push(segment.to_str()?.to_owned());
        }
    }
    Some(segments)
}

fn matches_directory_ancestor(
    pattern: &GitignorePattern,
    relative: &[String],
    matching_work: &mut usize,
) -> GlobMatch {
    gitignore_directory_ancestor_matches(pattern, relative, matching_work)
}

fn gitignore_directory_ancestor_matches(
    pattern: &GitignorePattern,
    relative: &[String],
    matching_work: &mut usize,
) -> GlobMatch {
    if pattern.unsupported || relative.is_empty() {
        return if pattern.unsupported {
            GlobMatch::Unsupported
        } else {
            GlobMatch::NoMatch
        };
    }
    if !pattern.negated
        && pattern.segments.len() > 1
        && pattern
            .segments
            .last()
            .is_some_and(|segment| segment == "**")
    {
        let prefix = &pattern.segments[..pattern.segments.len() - 1];
        for end in 1..relative.len() {
            match glob_match_path(prefix, &relative[..end], matching_work) {
                GlobMatch::Matched => return GlobMatch::Matched,
                GlobMatch::BudgetExceeded => return GlobMatch::BudgetExceeded,
                GlobMatch::Unsupported => return GlobMatch::Unsupported,
                GlobMatch::NoMatch => {}
            }
        }
    }
    for end in 1..relative.len() {
        match gitignore_pattern_matches(pattern, &relative[..end], matching_work) {
            GlobMatch::Matched => return GlobMatch::Matched,
            GlobMatch::BudgetExceeded => return GlobMatch::BudgetExceeded,
            GlobMatch::Unsupported => return GlobMatch::Unsupported,
            GlobMatch::NoMatch => {}
        }
    }
    GlobMatch::NoMatch
}

fn gitignore_pattern_matches(
    pattern: &GitignorePattern,
    relative: &[String],
    matching_work: &mut usize,
) -> GlobMatch {
    if pattern.segments.is_empty() {
        return GlobMatch::NoMatch;
    }
    if !pattern.negated
        && pattern.segments.len() > 1
        && pattern
            .segments
            .last()
            .is_some_and(|segment| segment == "**")
    {
        let prefix = &pattern.segments[..pattern.segments.len() - 1];
        let mut matches_parent = false;
        let mut matches_descendant = false;
        for end in 0..=relative.len() {
            match glob_match_path(prefix, &relative[..end], matching_work) {
                GlobMatch::Matched if end == relative.len() => matches_parent = true,
                GlobMatch::Matched => matches_descendant = true,
                GlobMatch::BudgetExceeded => return GlobMatch::BudgetExceeded,
                GlobMatch::NoMatch | GlobMatch::Unsupported => {}
            }
        }
        if matches_parent && !matches_descendant {
            return GlobMatch::NoMatch;
        }
    }
    if pattern.anchored || pattern.segments.len() > 1 {
        return glob_match_path(&pattern.segments, relative, matching_work);
    }
    let mut unsupported = false;
    for segment in relative {
        match glob_match_segment(&pattern.segments[0], segment, matching_work) {
            GlobMatch::Matched => return GlobMatch::Matched,
            GlobMatch::Unsupported => unsupported = true,
            GlobMatch::BudgetExceeded => return GlobMatch::BudgetExceeded,
            GlobMatch::NoMatch => {}
        }
    }
    if unsupported {
        GlobMatch::Unsupported
    } else {
        GlobMatch::NoMatch
    }
}

fn glob_match_path(pattern: &[String], path: &[String], matching_work: &mut usize) -> GlobMatch {
    let Some(cells) = (pattern.len() + 1).checked_mul(path.len() + 1) else {
        return GlobMatch::BudgetExceeded;
    };
    if !consume_matching_work(matching_work, cells) {
        return GlobMatch::BudgetExceeded;
    }
    let mut matches = vec![vec![false; path.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;
    for pattern_index in 0..pattern.len() {
        for path_index in 0..=path.len() {
            if !matches[pattern_index][path_index] {
                continue;
            }
            if pattern[pattern_index] == "**" {
                matches[pattern_index + 1][path_index] = true;
                if path_index < path.len() {
                    matches[pattern_index][path_index + 1] = true;
                }
            } else if path_index < path.len() {
                match glob_match_segment(&pattern[pattern_index], &path[path_index], matching_work)
                {
                    GlobMatch::Matched => matches[pattern_index + 1][path_index + 1] = true,
                    GlobMatch::BudgetExceeded => return GlobMatch::BudgetExceeded,
                    GlobMatch::NoMatch => {}
                    GlobMatch::Unsupported => return GlobMatch::Unsupported,
                }
            }
        }
    }
    if matches[pattern.len()][path.len()] {
        GlobMatch::Matched
    } else {
        GlobMatch::NoMatch
    }
}

fn glob_match_segment(pattern: &str, text: &str, matching_work: &mut usize) -> GlobMatch {
    let classification_cost = pattern.len().saturating_add(1);
    if !consume_matching_work(matching_work, classification_cost) {
        return GlobMatch::BudgetExceeded;
    }
    if pattern_is_unsupported(pattern) {
        return GlobMatch::Unsupported;
    }
    if !text.is_ascii()
        && pattern
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'['))
    {
        return GlobMatch::Unsupported;
    }
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let Some(cells) = (pattern.len() + 1).checked_mul(text.len() + 1) else {
        return GlobMatch::BudgetExceeded;
    };
    if !consume_matching_work(matching_work, cells) {
        return GlobMatch::BudgetExceeded;
    }
    let mut matches = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    matches[0][0] = true;
    for pattern_index in 0..pattern.len() {
        for text_index in 0..=text.len() {
            if !matches[pattern_index][text_index] {
                continue;
            }
            match pattern[pattern_index] {
                b'*' => {
                    matches[pattern_index + 1][text_index] = true;
                    if text_index < text.len() {
                        matches[pattern_index][text_index + 1] = true;
                    }
                }
                b'?' if text_index < text.len() => {
                    matches[pattern_index + 1][text_index + 1] = true;
                }
                b'[' if text_index < text.len() => {
                    let Some((end, matched)) =
                        character_class(pattern, pattern_index, text[text_index])
                    else {
                        return GlobMatch::Unsupported;
                    };
                    if matched {
                        matches[end][text_index + 1] = true;
                    }
                }
                byte if text_index < text.len() && byte == text[text_index] => {
                    matches[pattern_index + 1][text_index + 1] = true;
                }
                _ => {}
            }
        }
    }
    if matches[pattern.len()][text.len()] {
        GlobMatch::Matched
    } else {
        GlobMatch::NoMatch
    }
}

fn pattern_is_unsupported(pattern: &str) -> bool {
    if pattern.len() > MAX_GITIGNORE_PATTERN_BYTES
        || pattern
            .bytes()
            .any(|byte| matches!(byte, b'\\' | b'{' | b'}'))
    {
        return true;
    }
    let pattern = pattern.as_bytes();
    let mut index = 0;
    while index < pattern.len() {
        if pattern[index] == b'[' {
            let Some((end, _)) = character_class(pattern, index, 0) else {
                return true;
            };
            index = end;
        } else {
            index += 1;
        }
    }
    false
}

fn consume_matching_work(matching_work: &mut usize, amount: usize) -> bool {
    let Some(next) = matching_work.checked_add(amount) else {
        return false;
    };
    if next > MAX_GITIGNORE_MATCHING_WORK {
        return false;
    }
    *matching_work = next;
    true
}

fn character_class(pattern: &[u8], start: usize, byte: u8) -> Option<(usize, bool)> {
    let mut index = start + 1;
    let negated = matches!(pattern.get(index), Some(b'!') | Some(b'^'));
    if negated {
        index += 1;
    }
    let mut matched = false;
    let mut has_item = false;
    while index < pattern.len() {
        if pattern[index] == b']' && has_item {
            return Some((index + 1, if negated { !matched } else { matched }));
        }
        let first = pattern[index];
        has_item = true;
        index += 1;
        if pattern.get(index) == Some(&b'-') && pattern.get(index + 1).is_some() {
            let last = pattern[index + 1];
            if first > last {
                return None;
            }
            matched |= first <= byte && byte <= last;
            index += 2;
        } else {
            matched |= first == byte;
        }
    }
    None
}

fn is_marker(name: Option<&str>) -> bool {
    let Some(name) = name else { return false };
    matches!(
        name,
        "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "requirements.txt"
            | "package.json"
            | "tsconfig.json"
            | "Cargo.toml"
            | "go.mod"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "global.json"
            | "CMakeLists.txt"
            | "meson.build"
            | "Makefile"
    ) || name.ends_with(".sh")
        || name.ends_with(".tf")
        || name.ends_with(".csproj")
        || name.ends_with(".sln")
        || name.ends_with(".sql")
}

fn workspace_for(
    root: &Path,
    path: &Path,
    gitignore: &[GitignorePattern],
    gitignore_matching_work: &mut usize,
    filesystem_entries_seen: &mut usize,
    filesystem_entry_limit: usize,
) -> Result<Option<Workspace>, DiscoveryError> {
    let Some(mut relative) = path.strip_prefix(root).ok().map(Path::to_path_buf) else {
        return Ok(None);
    };
    relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative
    };
    let markers = marker_set(
        root,
        path,
        gitignore,
        gitignore_matching_work,
        filesystem_entries_seen,
        filesystem_entry_limit,
    )?;
    let (language, commands) = if markers.contains("pyproject.toml")
        || markers.contains("setup.py")
        || markers.contains("setup.cfg")
        || markers.contains("requirements.txt")
    {
        ("python", python_commands(path))
    } else if markers.contains("package.json") || markers.contains("tsconfig.json") {
        ("typescript", typescript_commands(path))
    } else if markers.contains("Cargo.toml") {
        ("rust", rust_commands())
    } else if markers.contains("go.mod") {
        ("go", go_commands())
    } else if markers.contains("pom.xml")
        || markers.contains("build.gradle")
        || markers.contains("build.gradle.kts")
        || markers.contains("settings.gradle")
    {
        ("jvm", jvm_commands(path, &markers))
    } else if markers.iter().any(|marker| {
        marker.ends_with(".csproj") || marker.ends_with(".sln") || marker == "global.json"
    }) {
        ("csharp", csharp_commands())
    } else if markers.contains("CMakeLists.txt")
        || markers.contains("meson.build")
        || markers.contains("Makefile")
    {
        ("cpp", cpp_commands(path, &markers))
    } else if markers.iter().any(|marker| marker.ends_with(".sh")) {
        ("shell", shell_commands(path, &markers))
    } else if markers.iter().any(|marker| marker.ends_with(".tf")) {
        ("terraform", terraform_commands())
    } else if markers.iter().any(|marker| marker.ends_with(".sql")) {
        ("sql", sql_commands())
    } else {
        return Ok(None);
    };
    let id = if relative == Path::new(".") {
        language.to_string()
    } else {
        relative.to_string_lossy().replace(['/', '\\'], "-")
    };
    Ok(Some(Workspace {
        id,
        language: language.to_string(),
        root: relative.clone(),
        commands: commands
            .into_iter()
            .map(|(argv, purpose, confidence)| CommandSpec {
                argv,
                cwd: relative.clone(),
                timeout_seconds: 300,
                tier: command_tier(purpose).to_string(),
                purpose: purpose.to_string(),
                source: "discovery".to_string(),
                confidence: confidence.to_string(),
            })
            .collect(),
        coverage: Vec::new(),
    }))
}

fn command_tier(purpose: &str) -> &'static str {
    match purpose {
        "lint" | "format" => "fast",
        "types" | "typecheck" => "targeted",
        _ => "full",
    }
}

fn marker_set(
    root: &Path,
    path: &Path,
    gitignore: &[GitignorePattern],
    gitignore_matching_work: &mut usize,
    filesystem_entries_seen: &mut usize,
    filesystem_entry_limit: usize,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let entries = std::fs::read_dir(path).map_err(|_| DiscoveryError::RootNotDirectory {
        path: path.to_path_buf(),
    })?;
    let mut marker_entries = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| DiscoveryError::RootNotDirectory {
            path: path.to_path_buf(),
        })?;
        consume_filesystem_entry(filesystem_entries_seen, filesystem_entry_limit)?;
        let marker_path = entry.path();
        let metadata = std::fs::symlink_metadata(&marker_path).map_err(|_| {
            DiscoveryError::RootNotDirectory {
                path: marker_path.clone(),
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(DiscoveryError::SymlinkRefused { path: marker_path });
        }
        if !metadata.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if is_marker(Some(name)) {
            marker_entries.push((marker_path, name.to_string()));
        }
    }
    marker_entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut markers = BTreeSet::new();
    for (marker_path, name) in marker_entries {
        if gitignored(
            root,
            &marker_path,
            gitignore,
            false,
            gitignore_matching_work,
        ) {
            continue;
        }
        markers.insert(name);
    }
    Ok(markers)
}

fn python_commands(root: &Path) -> Vec<(Vec<String>, &'static str, &'static str)> {
    let pyproject = read_optional_bounded(&root.join("pyproject.toml"), MAX_METADATA_BYTES);
    let uv =
        root.join("uv.lock").is_file() || pyproject.lines().any(|line| line.trim() == "[tool.uv]");
    let prefix: Vec<String> = if uv {
        vec!["uv", "run"]
    } else if root.join("poetry.lock").is_file() {
        vec!["poetry", "run"]
    } else if root.join("pdm.lock").is_file() {
        vec!["pdm", "run"]
    } else {
        Vec::new()
    }
    .into_iter()
    .map(String::from)
    .collect();
    let ruff_configured = has_table(&pyproject, "tool.ruff") || has_dependency(root, "ruff");
    let mypy_configured = has_table(&pyproject, "tool.mypy") || has_dependency(root, "mypy");
    let pytest_configured = pyproject
        .lines()
        .any(|line| line.trim().starts_with("[tool.pytest"))
        || root.join("pytest.ini").is_file()
        || root.join("tox.ini").is_file()
        || has_dependency(root, "pytest");
    let mut commands = Vec::new();
    for (tool, args, purpose, enabled) in [
        ("ruff", vec!["check"], "lint", ruff_configured),
        ("ruff", vec!["format", "--check"], "format", ruff_configured),
        ("mypy", vec![], "types", mypy_configured),
        ("pytest", vec![], "test", pytest_configured),
    ] {
        if !enabled {
            continue;
        }
        let mut argv = prefix.clone();
        argv.push(tool.to_string());
        argv.extend(args.into_iter().map(String::from));
        commands.push((argv, purpose, "high"));
    }
    commands
}

fn has_dependency(root: &Path, package: &str) -> bool {
    let requirements = read_optional_bounded(&root.join("requirements.txt"), MAX_METADATA_BYTES);
    requirements.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default().trim();
        let name = line
            .split(['<', '>', '=', '!', '~', '[', ';'])
            .next()
            .unwrap_or_default()
            .trim();
        name.eq_ignore_ascii_case(package)
    })
}

fn typescript_commands(root: &Path) -> Vec<(Vec<String>, &'static str, &'static str)> {
    let package = read_optional_bounded(&root.join("package.json"), MAX_METADATA_BYTES);
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&package) else {
        return Vec::new();
    };
    let Some(scripts_object) = package
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    else {
        return Vec::new();
    };
    let manager = if root.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else if root.join("yarn.lock").is_file() {
        "yarn"
    } else if root.join("bun.lockb").is_file() || root.join("bun.lock").is_file() {
        "bun"
    } else {
        "npm"
    };
    let scripts = ["lint", "format", "typecheck", "test", "build"];
    scripts
        .into_iter()
        .filter(|script| scripts_object.contains_key(*script))
        .map(|script| {
            (
                vec![manager.to_string(), "run".to_string(), script.to_string()],
                script,
                "high",
            )
        })
        .collect()
}

fn rust_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    vec![
        (
            vec!["cargo", "fmt", "--check"]
                .into_iter()
                .map(String::from)
                .collect(),
            "format",
            "high",
        ),
        (
            vec!["cargo", "clippy", "--all-targets", "--", "-D", "warnings"]
                .into_iter()
                .map(String::from)
                .collect(),
            "lint",
            "high",
        ),
        (
            vec!["cargo", "test"]
                .into_iter()
                .map(String::from)
                .collect(),
            "test",
            "high",
        ),
        (
            vec!["cargo", "build"]
                .into_iter()
                .map(String::from)
                .collect(),
            "build",
            "high",
        ),
    ]
}

fn go_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    let mut commands = vec![
        (
            vec!["gofmt", "-l", "."]
                .into_iter()
                .map(String::from)
                .collect(),
            "format",
            "high",
        ),
        (
            vec!["go", "vet", "./..."]
                .into_iter()
                .map(String::from)
                .collect(),
            "lint",
            "high",
        ),
        (
            vec!["go", "test", "./..."]
                .into_iter()
                .map(String::from)
                .collect(),
            "test",
            "high",
        ),
    ];
    if command_on_path("staticcheck") {
        commands.push((
            vec!["staticcheck", "./..."]
                .into_iter()
                .map(String::from)
                .collect(),
            "static analysis",
            "high",
        ));
    }
    commands
}

fn jvm_commands(
    root: &Path,
    markers: &BTreeSet<String>,
) -> Vec<(Vec<String>, &'static str, &'static str)> {
    if markers.contains("pom.xml") && command_on_path("mvn") {
        return vec![
            (
                vec!["mvn", "test"].into_iter().map(String::from).collect(),
                "test",
                "high",
            ),
            (
                vec!["mvn", "verify"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "build",
                "high",
            ),
        ];
    }
    let gradle = if root.join("gradlew").is_file() {
        "./gradlew"
    } else if command_on_path("gradle") {
        "gradle"
    } else {
        return Vec::new();
    };
    vec![
        (
            vec![gradle, "test"].into_iter().map(String::from).collect(),
            "test",
            "high",
        ),
        (
            vec![gradle, "build"]
                .into_iter()
                .map(String::from)
                .collect(),
            "build",
            "high",
        ),
    ]
}

fn csharp_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    if !command_on_path("dotnet") {
        return Vec::new();
    }
    vec![
        (
            vec!["dotnet", "format"]
                .into_iter()
                .map(String::from)
                .collect(),
            "format",
            "high",
        ),
        (
            vec!["dotnet", "build"]
                .into_iter()
                .map(String::from)
                .collect(),
            "build",
            "high",
        ),
        (
            vec!["dotnet", "test"]
                .into_iter()
                .map(String::from)
                .collect(),
            "test",
            "high",
        ),
    ]
}

fn cpp_commands(
    root: &Path,
    markers: &BTreeSet<String>,
) -> Vec<(Vec<String>, &'static str, &'static str)> {
    if markers.contains("CMakeLists.txt") && command_on_path("cmake") {
        return vec![
            (
                vec!["cmake", "-S", ".", "-B", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "configure",
                "high",
            ),
            (
                vec!["cmake", "--build", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "build",
                "high",
            ),
            (
                vec!["ctest", "--test-dir", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "test",
                "high",
            ),
        ];
    }
    if markers.contains("meson.build") && command_on_path("meson") {
        return vec![
            (
                vec!["meson", "setup", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "configure",
                "high",
            ),
            (
                vec!["meson", "compile", "-C", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "build",
                "high",
            ),
            (
                vec!["meson", "test", "-C", "build"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                "test",
                "high",
            ),
        ];
    }
    if markers.contains("Makefile") && command_on_path("make") && root.join("Makefile").is_file() {
        return vec![(
            vec!["make", "test"].into_iter().map(String::from).collect(),
            "test",
            "medium",
        )];
    }
    Vec::new()
}

fn shell_commands(
    root: &Path,
    markers: &BTreeSet<String>,
) -> Vec<(Vec<String>, &'static str, &'static str)> {
    if !command_on_path("shellcheck") {
        return Vec::new();
    }
    let mut argv = vec!["shellcheck".to_string()];
    argv.extend(
        markers
            .iter()
            .filter(|marker| marker.ends_with(".sh"))
            .cloned(),
    );
    if argv.len() == 1 || !root.is_dir() {
        return Vec::new();
    }
    vec![(argv, "lint", "high")]
}

fn sql_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    if command_on_path("sqlfluff") {
        vec![(
            vec!["sqlfluff", "lint"]
                .into_iter()
                .map(String::from)
                .collect(),
            "lint",
            "high",
        )]
    } else {
        Vec::new()
    }
}

fn terraform_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    if !command_on_path("terraform") {
        return Vec::new();
    }
    vec![
        (
            vec!["terraform", "fmt", "-check"]
                .into_iter()
                .map(String::from)
                .collect(),
            "format",
            "high",
        ),
        (
            vec!["terraform", "validate"]
                .into_iter()
                .map(String::from)
                .collect(),
            "validate",
            "high",
        ),
    ]
}

fn command_on_path(command: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|directory| directory.join(command).is_file())
    })
}

fn has_table(text: &str, name: &str) -> bool {
    let header = format!("[{name}]");
    text.lines().any(|line| line.trim() == header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_nested_python_and_rust_with_workspace_cwds() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-{}", std::process::id()));
        std::fs::create_dir_all(root.join("backend")).expect("backend");
        std::fs::create_dir_all(root.join("crates/app")).expect("crate");
        std::fs::write(root.join("backend/pyproject.toml"), "[tool.ruff]\n")
            .expect("python marker");
        std::fs::write(
            root.join("crates/app/Cargo.toml"),
            "[package]\nname='app'\n",
        )
        .expect("rust marker");
        let workspaces = discover(&root).expect("discovery succeeds");
        assert_eq!(
            workspaces
                .iter()
                .map(|item| item.language.as_str())
                .collect::<Vec<_>>(),
            ["python", "rust"]
        );
        assert!(
            workspaces[0]
                .commands
                .iter()
                .all(|command| command.cwd == Path::new("backend"))
        );
        assert!(
            workspaces[1]
                .commands
                .iter()
                .all(|command| command.cwd == Path::new("crates/app"))
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn python_workspace_uses_uv_and_project_scoped_tools() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-lawsuit-{}", std::process::id()));
        std::fs::create_dir_all(root.join("backend")).expect("backend");
        std::fs::write(
            root.join("backend/pyproject.toml"),
            "[tool.ruff]\n[tool.mypy]\npackages = [\"records_assistant\"]\n[tool.pytest.ini_options]\n",
        )
        .expect("python config");
        std::fs::write(root.join("backend/uv.lock"), "version = 1\n").expect("uv lock");
        let workspace = discover(&root)
            .expect("discovery")
            .into_iter()
            .find(|workspace| workspace.language == "python")
            .expect("python workspace");
        let argv: Vec<Vec<String>> = workspace
            .commands
            .iter()
            .map(|command| command.argv.clone())
            .collect();
        assert!(argv.iter().any(|command| {
            command.iter().map(String::as_str).collect::<Vec<_>>() == ["uv", "run", "ruff", "check"]
        }));
        assert!(argv.iter().any(|command| {
            command.iter().map(String::as_str).collect::<Vec<_>>() == ["uv", "run", "mypy"]
        }));
        assert!(argv.iter().any(|command| {
            command.iter().map(String::as_str).collect::<Vec<_>>()
                == ["uv", "run", "ruff", "format", "--check"]
        }));
        assert!(argv.iter().any(|command| {
            command.iter().map(String::as_str).collect::<Vec<_>>() == ["uv", "run", "pytest"]
        }));
        assert!(
            argv.iter()
                .all(|command| !command.contains(&"--strict".to_string()))
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn python_requirements_and_poetry_markers_are_supported() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-poetry-{}", std::process::id()));
        std::fs::create_dir_all(root.join("service")).expect("service");
        std::fs::write(root.join("service/requirements.txt"), "pytest\n").expect("requirements");
        std::fs::write(root.join("service/poetry.lock"), "# lock\n").expect("poetry lock");
        let workspace = discover(&root)
            .expect("discovery")
            .into_iter()
            .find(|workspace| workspace.language == "python")
            .expect("python workspace");
        assert!(workspace.commands.iter().all(|command| {
            command
                .argv
                .iter()
                .take(2)
                .map(String::as_str)
                .collect::<Vec<_>>()
                == ["poetry", "run"]
        }));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn python_workspace_uses_declared_pytest_without_guessing_other_tools() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-pytest-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("pytest.ini"), "[pytest]\ntestpaths = tests\n")
            .expect("pytest config");
        std::fs::write(root.join("requirements.txt"), "pytest>=8\n").expect("requirements");
        let workspace = discover(&root)
            .expect("discovery")
            .into_iter()
            .find(|workspace| workspace.language == "python")
            .expect("python workspace");
        let commands: Vec<Vec<String>> = workspace
            .commands
            .into_iter()
            .map(|command| command.argv)
            .collect();
        assert_eq!(commands, vec![vec!["pytest".to_string()]]);
        std::fs::remove_dir_all(root).ok();
    }

    struct TemporaryDiscoveryRoot(PathBuf);

    impl std::ops::Deref for TemporaryDiscoveryRoot {
        type Target = Path;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl AsRef<Path> for TemporaryDiscoveryRoot {
        fn as_ref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryDiscoveryRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn unique_discovery_root(label: &str) -> TemporaryDiscoveryRoot {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        for attempt in 0..16 {
            let root = std::env::temp_dir().join(format!(
                "lgtm-discovery-{label}-{}-{id}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => return TemporaryDiscoveryRoot(root),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("temporary discovery root should be creatable: {error}"),
            }
        }
        panic!("could not reserve a unique temporary discovery root")
    }

    fn add_cargo_workspace(root: &Path, relative: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(&path).expect("workspace directory");
        std::fs::write(path.join("Cargo.toml"), "[package]\nname = \"fixture\"\n")
            .expect("workspace marker");
    }

    fn workspace_roots(root: &Path) -> Vec<String> {
        discover(root)
            .expect("discovery succeeds")
            .into_iter()
            .map(|workspace| workspace.root.to_string_lossy().replace('\\', "/"))
            .collect()
    }

    #[test]
    fn skips_build_artifacts_and_gitignored_workspace_markers() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-ignored-{}", std::process::id()));
        std::fs::create_dir_all(root.join("frontend/.next")).expect("next output");
        std::fs::create_dir_all(root.join("frontend/src")).expect("source");
        std::fs::write(root.join(".gitignore"), "generated/\n").expect("gitignore");
        std::fs::write(root.join("frontend/.next/package.json"), "{}").expect("artifact marker");
        std::fs::create_dir_all(root.join("generated")).expect("ignored output");
        std::fs::write(root.join("generated/package.json"), "{}").expect("ignored marker");
        assert!(discover(&root).expect("discovery").is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn applies_gitignore_literal_nested_anchored_and_wildcard_directory_rules() {
        let root = unique_discovery_root("gitignore-globs");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join(".gitignore"),
            "generated-*/\npackages/generated/\n/anchored/\nbuild-?/\nalpha-[a-z]/\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "generated-cache");
        add_cargo_workspace(&root, "generated");
        add_cargo_workspace(&root, "alpha-a");
        add_cargo_workspace(&root, "alpha-1");
        add_cargo_workspace(&root, "packages/generated");
        add_cargo_workspace(&root, "packages/kept");
        add_cargo_workspace(&root, "anchored");
        add_cargo_workspace(&root, "nested/anchored");
        add_cargo_workspace(&root, "build-a");
        add_cargo_workspace(&root, "build-aa");

        assert_eq!(
            workspace_roots(&root),
            [
                "alpha-1",
                "build-aa",
                "generated",
                "nested/anchored",
                "packages/kept"
            ]
        );
    }

    #[test]
    fn accepts_crlf_gitignore_lines_without_accepting_control_syntax() {
        let root = unique_discovery_root("gitignore-crlf");
        std::fs::write(root.join(".gitignore"), b"ignored/\r\n").expect("gitignore");
        add_cargo_workspace(&root, "ignored");
        add_cargo_workspace(&root, "visible");

        assert_eq!(workspace_roots(&root), ["visible"]);
    }

    #[test]
    fn fails_closed_for_unicode_wildcard_and_class_matching() {
        for (label, rule) in [("question", "caf?/\n"), ("class", "caf[a-z]/\n")] {
            let root = unique_discovery_root(&format!("gitignore-unicode-{label}"));
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, "café");

            assert!(
                workspace_roots(&root).is_empty(),
                "Unicode wildcard rule must fail closed: {rule}"
            );
        }
    }

    #[test]
    fn applies_nested_double_star_rules_and_ordered_negation() {
        let root = unique_discovery_root("gitignore-negation");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join(".gitignore"),
            "external/**/generated-*/\ngenerated-*/\n!/generated-cache/\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "external/generated-docs");
        add_cargo_workspace(&root, "external/packages/generated-cache");
        add_cargo_workspace(&root, "generated-other");
        add_cargo_workspace(&root, "generated-cache");
        add_cargo_workspace(&root, "service");

        assert_eq!(workspace_roots(&root), ["generated-cache", "service"]);
    }

    #[test]
    fn trailing_double_star_does_not_hide_parent_reopened_by_negation() {
        let root = unique_discovery_root("gitignore-trailing-double-star-negation");
        std::fs::write(root.join(".gitignore"), "foo/**\n!foo/bar/\n").expect("gitignore");
        add_cargo_workspace(&root, "foo/bar");

        assert_eq!(workspace_roots(&root), ["foo/bar"]);
    }

    #[test]
    fn trailing_double_star_keeps_complex_prefix_parents_traversable() {
        for (label, rule, workspace) in [
            ("leading-double-star", "**/foo/**\n", "foo"),
            ("repeated-double-star", "foo/**/**\n", "foo"),
            ("nested-double-star", "foo/**/bar/**\n", "foo/bar"),
        ] {
            let root = unique_discovery_root(&format!("gitignore-trailing-double-star-{label}"));
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            let mut matching_work = 0;
            let patterns = read_gitignore_patterns(&root, &mut matching_work);
            matching_work = 0;
            let parent = root.join(workspace);
            assert!(
                !gitignored(&root, &parent, &patterns, true, &mut matching_work,),
                "parent must remain traversable for rule: {rule}"
            );
            assert!(
                gitignored(
                    &root,
                    &parent.join("Cargo.toml"),
                    &patterns,
                    false,
                    &mut matching_work,
                ),
                "descendant must remain ignored for rule: {rule}"
            );
        }
    }

    #[test]
    fn negated_trailing_double_star_reopens_descendant_parent() {
        let root = unique_discovery_root("gitignore-trailing-double-star-descendant-negation");
        std::fs::write(root.join(".gitignore"), "foo/**\n!foo/bar/**\n").expect("gitignore");
        add_cargo_workspace(&root, "foo/bar");

        assert_eq!(workspace_roots(&root), ["foo/bar"]);
    }

    #[test]
    fn unsupported_gitignore_syntax_fails_closed() {
        for (label, rule, directory) in [
            ("brace", "generated-{cache,docs}/", "generated-cache"),
            ("escape", r"generated\*/", "generated-cache"),
            ("malformed", "[", "generated-cache"),
            ("reversed", "generated[z-a]/", "generatedx"),
        ] {
            let root = unique_discovery_root(label);
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, directory);
            assert!(
                workspace_roots(&root).is_empty(),
                "rule should fail closed: {rule}"
            );
        }

        let overlong_root = unique_discovery_root("overlong");
        let overlong = format!("{}/\n", "x".repeat(MAX_GITIGNORE_PATTERN_BYTES + 1));
        std::fs::write(overlong_root.join(".gitignore"), overlong).expect("gitignore");
        add_cargo_workspace(&overlong_root, "generated-cache");
        assert!(workspace_roots(&overlong_root).is_empty());

        let multi_segment_overlong_root = unique_discovery_root("overlong-multi-segment");
        let multi_segment_overlong = format!(
            "{}target/\n",
            "**/".repeat((MAX_GITIGNORE_PATTERN_BYTES / 3) + 1)
        );
        std::fs::write(
            multi_segment_overlong_root.join(".gitignore"),
            multi_segment_overlong,
        )
        .expect("gitignore");
        add_cargo_workspace(&multi_segment_overlong_root, "generated-cache");
        assert!(workspace_roots(&multi_segment_overlong_root).is_empty());
    }

    #[test]
    fn negated_pattern_length_bound_includes_negation_marker() {
        let root = unique_discovery_root("gitignore-negated-length-bound");
        let exact = format!("!{}", "x".repeat(MAX_GITIGNORE_PATTERN_BYTES - 1));
        std::fs::write(root.join(".gitignore"), exact).expect("gitignore");
        let mut matching_work = 0;
        assert_ne!(
            read_gitignore_patterns(&root, &mut matching_work),
            vec![GitignorePattern::fail_closed()]
        );

        let root = unique_discovery_root("gitignore-negated-length-overlong");
        let overlong = format!("!{}", "x".repeat(MAX_GITIGNORE_PATTERN_BYTES));
        std::fs::write(root.join(".gitignore"), overlong).expect("gitignore");
        let mut matching_work = 0;
        assert_eq!(
            read_gitignore_patterns(&root, &mut matching_work),
            vec![GitignorePattern::fail_closed()]
        );
    }

    #[test]
    fn control_byte_negation_cannot_reopen_ignored_directory() {
        let root = unique_discovery_root("gitignore-control-tab");
        std::fs::write(
            root.join(".gitignore"),
            "generated-*/\n!generated-cache/\t\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "generated-cache");

        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn gitignored_marker_files_do_not_create_workspaces() {
        for (label, rule, workspace) in [
            ("nested-file", "foo/**\n", "foo/service"),
            ("direct-file", "foo/*.toml\n", "foo"),
            ("basename-file", "*.toml\n", "service"),
        ] {
            let root = unique_discovery_root(&format!("gitignore-marker-files-{label}"));
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, workspace);
            assert!(
                workspace_roots(&root).is_empty(),
                "rule should ignore marker: {rule}"
            );
        }
    }

    #[test]
    fn ignored_marker_cannot_override_visible_marker_classification() {
        let root = unique_discovery_root("gitignore-marker-classification");
        std::fs::write(root.join(".gitignore"), "Cargo.toml\n").expect("gitignore");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n")
            .expect("ignored rust marker");
        std::fs::write(root.join("package.json"), "{}\n").expect("visible typescript marker");

        let workspaces = discover(&root).expect("discovery");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].language, "typescript");
    }

    #[test]
    fn marker_rescan_matching_budget_is_stable_across_creation_order() {
        let pattern = GitignorePattern {
            segments: vec!["x".to_string()],
            negated: false,
            anchored: false,
            directory_only: false,
            unsupported: false,
        };
        let mut probe_work = 0;
        assert!(!gitignored(
            Path::new("/root"),
            Path::new("/root/Cargo.toml"),
            std::slice::from_ref(&pattern),
            false,
            &mut probe_work,
        ));
        let initial_work = MAX_GITIGNORE_MATCHING_WORK - probe_work;

        let marker_names = |reverse: bool| {
            let root = unique_discovery_root("marker-rescan-order");
            let names = ["Cargo.toml", "package.json"];
            let order = if reverse { [names[1], names[0]] } else { names };
            for name in order {
                std::fs::write(root.join(name), "marker").expect("marker");
            }
            let mut matching_work = initial_work;
            let mut filesystem_entries_seen = 0;
            marker_set(
                &root,
                &root,
                std::slice::from_ref(&pattern),
                &mut matching_work,
                &mut filesystem_entries_seen,
                MAX_FILESYSTEM_ENTRIES,
            )
            .expect("marker rescan")
        };

        let expected = BTreeSet::from(["Cargo.toml".to_string()]);
        assert_eq!(marker_names(false), expected);
        assert_eq!(marker_names(true), expected);
    }

    #[cfg(unix)]
    #[test]
    fn marker_rescan_refuses_symlink_before_filtering() {
        let root = unique_discovery_root("marker-rescan-symlink");
        let outside = unique_discovery_root("marker-rescan-symlink-outside");
        std::fs::write(root.join("package.json"), "{}\n").expect("visible marker");
        std::os::unix::fs::symlink(outside.join("Cargo.toml"), root.join("Cargo.toml"))
            .expect("marker symlink");

        let mut matching_work = 0;
        let mut filesystem_entries_seen = 0;
        assert!(matches!(
            marker_set(
                &root,
                &root,
                &[],
                &mut matching_work,
                &mut filesystem_entries_seen,
                MAX_FILESYSTEM_ENTRIES,
            ),
            Err(DiscoveryError::SymlinkRefused { path }) if path == root.join("Cargo.toml")
        ));
    }

    #[test]
    fn directory_only_negation_does_not_clear_file_pattern_ignore() {
        for (label, rule) in [
            ("extension", "*.toml\n!service/\n"),
            ("generic", "*\n!service/\n"),
        ] {
            let root =
                unique_discovery_root(&format!("gitignore-directory-negation-file-rule-{label}"));
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, "service");

            assert!(
                workspace_roots(&root).is_empty(),
                "directory-only negation must not clear direct file rule: {rule}"
            );
        }
    }

    #[test]
    fn directory_only_negation_preserves_file_ignore_after_directory_rule() {
        let root = unique_discovery_root("gitignore-directory-negation-after-directory-rule");
        std::fs::write(
            root.join(".gitignore"),
            "*.toml\nfoo/**/bar/**\n!foo/x/bar/\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "foo/x/bar");

        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn directory_only_negation_preserves_multisegment_direct_file_ignore_after_directory_rule() {
        let root = unique_discovery_root("gitignore-directory-negation-multisegment-file-rule");
        std::fs::write(
            root.join(".gitignore"),
            "foo/x/bar/*.toml\nfoo/**/bar/**\n!foo/x/bar/\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "foo/x/bar");

        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn directory_only_negation_reopens_complex_trailing_double_star_descendant() {
        let root = unique_discovery_root("gitignore-directory-negation-complex-trailing-star");
        std::fs::write(root.join(".gitignore"), "foo/**/bar/**\n!foo/x/bar/\n").expect("gitignore");
        add_cargo_workspace(&root, "foo/x/bar");

        assert_eq!(workspace_roots(&root), ["foo/x/bar"]);
    }

    #[test]
    fn directory_only_gitignore_rules_do_not_hide_matching_files() {
        let root = unique_discovery_root("gitignore-directory-only-file");
        std::fs::write(root.join(".gitignore"), "generated-*/\n").expect("gitignore");
        std::fs::write(root.join("generated-check.sh"), "#!/bin/sh\n").expect("shell marker");

        let workspaces = discover(&root).expect("discovery");
        assert_eq!(
            workspaces
                .iter()
                .map(|workspace| workspace.language.as_str())
                .collect::<Vec<_>>(),
            ["shell"]
        );
    }

    #[test]
    fn ignored_directory_is_not_reopened_by_leading_space_negation() {
        let root = unique_discovery_root("gitignore-leading-space-negation");
        std::fs::write(
            root.join(".gitignore"),
            "generated-*/\n! generated-cache/\n",
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "generated-cache");
        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn standalone_unsupported_and_overlong_negations_fail_closed() {
        for (label, rule) in [
            ("standalone-malformed-negation", "![\n"),
            ("standalone-brace-negation", "!generated-{cache}/\n"),
            ("standalone-escape-negation", "!generated\\*/\n"),
            ("standalone-reversed-negation", "!generated[z-a]/\n"),
        ] {
            let root = unique_discovery_root(label);
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, "generated-cache");
            assert!(
                workspace_roots(&root).is_empty(),
                "rule should fail closed: {rule}"
            );
        }

        let root = unique_discovery_root("overlong-negated-multi-segment");
        let rule = format!(
            "!{}target/\n",
            "**/".repeat((MAX_GITIGNORE_PATTERN_BYTES / 3) + 1)
        );
        std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
        add_cargo_workspace(&root, "generated-cache");
        assert!(workspace_roots(&root).is_empty());

        let root = unique_discovery_root("overlong-separator-only");
        std::fs::write(
            root.join(".gitignore"),
            "/".repeat(MAX_GITIGNORE_PATTERN_BYTES + 1),
        )
        .expect("gitignore");
        add_cargo_workspace(&root, "generated-cache");
        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn oversized_or_invalid_gitignore_fails_closed() {
        let oversized_root = unique_discovery_root("oversized-gitignore");
        let mut oversized = b"generated-/\n".to_vec();
        oversized.resize(MAX_METADATA_BYTES as usize + 1, b'x');
        std::fs::write(oversized_root.join(".gitignore"), oversized).expect("gitignore");
        add_cargo_workspace(&oversized_root, "generated-cache");
        assert!(workspace_roots(&oversized_root).is_empty());

        let invalid_root = unique_discovery_root("invalid-gitignore");
        std::fs::write(invalid_root.join(".gitignore"), b"generated-/\n\xff").expect("gitignore");
        add_cargo_workspace(&invalid_root, "generated-cache");
        assert!(workspace_roots(&invalid_root).is_empty());
    }

    #[test]
    fn nul_in_gitignore_fails_closed() {
        let root = unique_discovery_root("nul-gitignore");
        std::fs::write(root.join(".gitignore"), b"ignored/\0\n").expect("gitignore");
        add_cargo_workspace(&root, "ignored");
        assert!(workspace_roots(&root).is_empty());
    }

    #[test]
    fn valid_character_class_classification_is_budgeted() {
        let mut matching_work = MAX_GITIGNORE_MATCHING_WORK - "[a-z]".len() - 1;
        assert_eq!(
            glob_match_segment("[a-z]", "a", &mut matching_work),
            GlobMatch::BudgetExceeded
        );
        assert_eq!(matching_work, MAX_GITIGNORE_MATCHING_WORK);
    }

    #[test]
    fn unsupported_negated_gitignore_syntax_cannot_reopen_ignored_directories() {
        for (label, rule) in [
            ("brace", "generated-*/\n!generated-{cache}/\n"),
            (
                "escape",
                r"generated-*/
!generated\*/
",
            ),
            ("malformed", "generated-*/\n![\n"),
            ("reversed", "generated-*/\n!generated[z-a]/\n"),
        ] {
            let root = unique_discovery_root(label);
            std::fs::write(root.join(".gitignore"), rule).expect("gitignore");
            add_cargo_workspace(&root, "generated-cache");
            assert!(
                workspace_roots(&root).is_empty(),
                "rule should remain ignored: {rule}"
            );
        }
    }

    #[test]
    fn ignored_directories_do_not_consume_entry_or_workspace_limits() {
        let root = unique_discovery_root("gitignore-entry-budget");
        std::fs::write(root.join(".gitignore"), "ignored-*/\n").expect("gitignore");
        for index in 0..=MAX_ENTRIES {
            add_cargo_workspace(&root, &format!("ignored-{index}"));
        }
        add_cargo_workspace(&root, "kept");
        assert_eq!(workspace_roots(&root), ["kept"]);
    }

    #[test]
    fn visible_entries_still_hit_entry_limit() {
        let root = unique_discovery_root("entry-limit");
        for index in 0..=MAX_ENTRIES {
            std::fs::write(root.join(format!("visible-{index}.txt")), "entry")
                .expect("visible entry");
        }
        assert!(matches!(
            discover(&root),
            Err(DiscoveryError::EntryLimit { limit: MAX_ENTRIES })
        ));
    }

    #[test]
    fn visible_workspace_markers_still_hit_workspace_limit() {
        let root = unique_discovery_root("workspace-limit");
        for index in 0..=MAX_WORKSPACES {
            add_cargo_workspace(&root, &format!("workspace-{index}"));
        }
        assert!(matches!(
            discover(&root),
            Err(DiscoveryError::WorkspaceLimit {
                limit: MAX_WORKSPACES
            })
        ));
    }

    #[test]
    fn matching_budget_advances_for_available_negation_and_fails_closed_when_exhausted() {
        let pattern = GitignorePattern {
            segments: vec!["*".to_string()],
            negated: true,
            anchored: false,
            directory_only: false,
            unsupported: false,
        };
        let mut matching_work = 0;
        assert!(!gitignored(
            Path::new("/root"),
            Path::new("/root/workspace"),
            std::slice::from_ref(&pattern),
            true,
            &mut matching_work,
        ));
        assert!(matching_work > 0);
        matching_work = MAX_GITIGNORE_MATCHING_WORK;
        assert!(gitignored(
            Path::new("/root"),
            Path::new("/root/workspace"),
            &[pattern],
            true,
            &mut matching_work,
        ));
    }

    #[test]
    fn directory_only_rules_consume_matching_budget_for_files() {
        let pattern = GitignorePattern {
            segments: vec!["generated".to_string()],
            negated: false,
            anchored: false,
            directory_only: true,
            unsupported: false,
        };
        let mut matching_work = MAX_GITIGNORE_MATCHING_WORK - 3;
        assert!(!gitignored(
            Path::new("/root"),
            Path::new("/root"),
            std::slice::from_ref(&pattern),
            false,
            &mut matching_work,
        ));
        assert_eq!(matching_work, MAX_GITIGNORE_MATCHING_WORK);
    }

    #[test]
    fn valid_nonmatching_rules_consume_matching_budget_during_discovery() {
        let discover_in_creation_order = |reverse: bool| {
            let root = unique_discovery_root("matching-budget");
            let rules = "x\n".repeat(1_000);
            std::fs::write(root.join(".gitignore"), rules).expect("gitignore");
            let mut indices: Vec<_> = (0..50).collect();
            if reverse {
                indices.reverse();
            }
            for index in indices {
                add_cargo_workspace(&root, &format!("workspace-{index:02}"));
            }
            workspace_roots(&root)
        };

        let forward = discover_in_creation_order(false);
        let reverse = discover_in_creation_order(true);
        assert_eq!(forward, reverse);
        assert!(!forward.is_empty());
        assert!(forward.len() < 50);
    }

    #[test]
    fn unsupported_rule_is_charged_before_fail_closed_sentinel() {
        let root = unique_discovery_root("unsupported-gitignore-budget");
        std::fs::write(root.join(".gitignore"), "generated-{cache,docs}/\n").expect("gitignore");
        let mut matching_work = 0;

        let patterns = read_gitignore_patterns(&root, &mut matching_work);
        assert_eq!(patterns, vec![GitignorePattern::fail_closed()]);
        assert!(matching_work > "generated-{cache,docs}/".len());
    }

    #[test]
    fn discover_scan_budget_counts_ignored_entries() {
        let root = unique_discovery_root("discover-ignored-scan-budget");
        std::fs::write(root.join(".gitignore"), "ignored-*/\n").expect("gitignore");
        std::fs::create_dir(root.join("ignored-a")).expect("ignored directory");
        std::fs::create_dir(root.join("ignored-b")).expect("ignored directory");
        assert!(matches!(
            discover_with_test_filesystem_limit(&root, 2),
            Err(DiscoveryError::FilesystemEntryLimit { limit: 2 })
        ));
    }

    #[test]
    fn discover_scan_budget_propagates_through_workspace_marker_rescan() {
        let root = unique_discovery_root("discover-marker-scan-budget");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n")
            .expect("workspace marker");
        assert!(matches!(
            discover_with_test_filesystem_limit(&root, 1),
            Err(DiscoveryError::FilesystemEntryLimit { limit: 1 })
        ));
    }

    #[test]
    fn matcher_cell_budget_exhaustion_fails_inside_the_matcher() {
        let mut matching_work = MAX_GITIGNORE_MATCHING_WORK - 5;
        assert_eq!(
            glob_match_path(
                &["**".to_string()],
                &["nested".to_string(), "child".to_string()],
                &mut matching_work,
            ),
            GlobMatch::BudgetExceeded
        );

        let pattern = GitignorePattern {
            segments: vec!["**".to_string(), "a*".to_string()],
            negated: false,
            anchored: false,
            directory_only: false,
            unsupported: false,
        };
        let relative = vec!["nested".to_string(), "aaaa".to_string()];
        let mut matching_work = MAX_GITIGNORE_MATCHING_WORK - 9;
        assert_eq!(
            gitignore_pattern_matches(&pattern, &relative, &mut matching_work),
            GlobMatch::BudgetExceeded
        );
    }

    #[test]
    fn filesystem_scan_budget_is_distinct_from_admitted_entry_budget() {
        let root = unique_discovery_root("filesystem-scan-budget");
        std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n")
            .expect("workspace marker");
        std::fs::write(root.join("README.md"), "fixture").expect("non-marker entry");
        let mut filesystem_entries_seen = MAX_FILESYSTEM_ENTRIES;
        let mut entries_seen = 0;
        let mut matching_work = 0;
        let mut candidates = Vec::new();
        let mut state = WalkState {
            entries_seen: &mut entries_seen,
            filesystem_entries_seen: &mut filesystem_entries_seen,
            filesystem_entry_limit: MAX_FILESYSTEM_ENTRIES,
            gitignore_matching_work: &mut matching_work,
            candidates: &mut candidates,
        };
        assert!(matches!(
            walk(&root, &root, 0, &[], &mut state),
            Err(DiscoveryError::FilesystemEntryLimit {
                limit: MAX_FILESYSTEM_ENTRIES
            })
        ));

        let mut marker_filesystem_entries_seen = MAX_FILESYSTEM_ENTRIES;
        let mut marker_matching_work = 0;
        assert!(matches!(
            marker_set(
                &root,
                &root,
                &[],
                &mut marker_matching_work,
                &mut marker_filesystem_entries_seen,
                MAX_FILESYSTEM_ENTRIES,
            ),
            Err(DiscoveryError::FilesystemEntryLimit {
                limit: MAX_FILESYSTEM_ENTRIES
            })
        ));

        let mut workspace_for_filesystem_entries_seen = MAX_FILESYSTEM_ENTRIES - 1;
        let mut workspace_for_matching_work = 0;
        assert!(matches!(
            workspace_for(
                &root,
                &root,
                &[],
                &mut workspace_for_matching_work,
                &mut workspace_for_filesystem_entries_seen,
                MAX_FILESYSTEM_ENTRIES,
            ),
            Err(DiscoveryError::FilesystemEntryLimit {
                limit: MAX_FILESYSTEM_ENTRIES
            })
        ));

        let mut filesystem_entries = MAX_FILESYSTEM_ENTRIES;
        assert!(matches!(
            consume_filesystem_entry(&mut filesystem_entries, MAX_FILESYSTEM_ENTRIES),
            Err(DiscoveryError::FilesystemEntryLimit {
                limit: MAX_FILESYSTEM_ENTRIES
            })
        ));
        let mut admitted_entries = MAX_ENTRIES;
        assert!(matches!(
            consume_admitted_entry(&mut admitted_entries),
            Err(DiscoveryError::EntryLimit { limit: MAX_ENTRIES })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn unix_backslash_path_is_not_reincluded_as_nested_path() {
        let root = unique_discovery_root("gitignore-backslash");
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join(".gitignore"), "*\n!safe/outside/\n").expect("gitignore");
        add_cargo_workspace(&root, "safe\\outside");
        assert!(workspace_roots(&root).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn wildcard_rules_fail_closed_for_invalid_native_path_components() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = unique_discovery_root("gitignore-invalid-native-component");
        std::fs::write(root.join(".gitignore"), "*\n!*\n").expect("gitignore");
        let invalid_name = OsString::from_vec(vec![0xff]);
        let invalid_directory = root.join(&invalid_name);
        std::fs::create_dir(&invalid_directory).expect("invalid native directory");
        std::fs::write(
            invalid_directory.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .expect("workspace marker");
        assert!(workspace_roots(&root).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_budget_counts_symlink_before_refusal() {
        let root = unique_discovery_root("symlink-budget-boundary");
        let outside = unique_discovery_root("symlink-budget-boundary-outside");
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("symlink");

        assert!(matches!(
            discover_with_test_filesystem_limit(&root, 0),
            Err(DiscoveryError::FilesystemEntryLimit { limit: 0 })
        ));
        assert!(matches!(
            discover(&root),
            Err(DiscoveryError::SymlinkRefused { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_even_when_name_is_gitignored() {
        let root = unique_discovery_root("ignored-symlink");
        let outside = unique_discovery_root("ignored-symlink-outside");
        std::fs::write(root.join(".gitignore"), "ignored/\n").expect("gitignore");
        std::os::unix::fs::symlink(&outside, root.join("ignored")).expect("symlink");
        assert!(matches!(
            discover(&root),
            Err(DiscoveryError::SymlinkRefused { .. })
        ));
    }

    #[test]
    fn skips_fixture_and_testdata_trees() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-fixtures-{}", std::process::id()));
        std::fs::create_dir_all(root.join("tests/fixtures/broken-python")).expect("fixture tree");
        std::fs::write(
            root.join("tests/fixtures/broken-python/pyproject.toml"),
            "[project]\nname = \"broken\"\n",
        )
        .expect("fixture marker");
        std::fs::create_dir_all(root.join("testdata/sample-go")).expect("testdata tree");
        std::fs::write(root.join("testdata/sample-go/go.mod"), "module sample\n")
            .expect("testdata marker");
        assert!(discover(&root).expect("discovery").is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    fn typescript_commands_for(package: &str) -> Vec<Vec<String>> {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "lgtm-discovery-ts-regression-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("package.json"), package).expect("package");
        let commands = discover(&root)
            .expect("discovery")
            .into_iter()
            .find(|workspace| workspace.language == "typescript")
            .expect("typescript workspace")
            .commands
            .into_iter()
            .map(|command| command.argv)
            .collect();
        std::fs::remove_dir_all(root).expect("temporary discovery root removed");
        commands
    }

    #[test]
    fn ignores_recognized_names_outside_top_level_scripts() {
        let package = r#"{
            "keywords": ["test"],
            "dependencies": {"lint": "latest"},
            "devDependencies": {"build": "latest"},
            "metadata": {"format": true, "typecheck": "example"},
            "scripts": {}
        }"#;

        assert!(typescript_commands_for(package).is_empty());
    }

    #[test]
    fn emits_only_present_recognized_top_level_scripts() {
        let package = r#"{
            "scripts": {"test": "vitest run", "custom": "node custom.js"}
        }"#;

        assert_eq!(
            typescript_commands_for(package),
            vec![vec![
                "npm".to_string(),
                "run".to_string(),
                "test".to_string()
            ]]
        );
    }

    #[test]
    fn non_object_or_missing_scripts_do_not_create_guessed_scripts() {
        for package in [
            r#"{"scripts":["test"]}"#,
            r#"{"scripts":"test"}"#,
            r#"{"scripts":null}"#,
            r#"{}"#,
        ] {
            assert!(
                typescript_commands_for(package).is_empty(),
                "package shape should not produce commands: {package}"
            );
        }
    }

    #[test]
    fn malformed_package_json_does_not_create_guessed_scripts() {
        let package = r#"{"scripts":{"test":"vitest run"}"#;

        assert!(typescript_commands_for(package).is_empty());
    }

    #[test]
    fn oversized_package_json_does_not_create_guessed_scripts() {
        let package = format!(
            "{{\"scripts\":{{\"test\":\"vitest run\"}},\"padding\":\"{}\"}}",
            "x".repeat(MAX_METADATA_BYTES as usize)
        );

        assert!(typescript_commands_for(&package).is_empty());
    }

    #[test]
    fn typescript_workspace_uses_lockfile_manager_and_configured_scripts() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-ts-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join("package.json"),
            "{\"workspaces\":[\"apps/*\"],\"scripts\":{\"lint\":\"eslint .\",\"format\":\"prettier --check .\",\"typecheck\":\"tsc --noEmit\",\"test\":\"vitest run\",\"build\":\"next build\"}}\n",
        )
        .expect("package");
        std::fs::write(root.join("yarn.lock"), "# lockfile\n").expect("yarn lock");
        let workspace = discover(&root)
            .expect("discovery")
            .into_iter()
            .find(|workspace| workspace.language == "typescript")
            .expect("typescript workspace");
        assert_eq!(workspace.commands.len(), 5);
        assert!(workspace.commands.iter().any(|command| {
            command.argv.iter().map(String::as_str).collect::<Vec<_>>() == ["yarn", "run", "lint"]
        }));
        assert!(workspace.commands.iter().any(|command| {
            command.argv.iter().map(String::as_str).collect::<Vec<_>>() == ["yarn", "run", "build"]
        }));
        for script in ["format", "typecheck", "test"] {
            assert!(workspace.commands.iter().any(|command| {
                command.argv.iter().map(String::as_str).collect::<Vec<_>>()
                    == ["yarn", "run", script]
            }));
        }
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn shell_and_terraform_markers_are_discovered_without_guessing_tools() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-infra-{}", std::process::id()));
        std::fs::create_dir_all(root.join("scripts")).expect("scripts");
        std::fs::create_dir_all(root.join("infra")).expect("infra");
        std::fs::write(root.join("scripts/check.sh"), "#!/bin/sh\nset -eu\n")
            .expect("shell marker");
        std::fs::write(root.join("infra/main.tf"), "terraform {}\n").expect("terraform marker");
        let workspaces = discover(&root).expect("discovery");
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "shell")
        );
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "terraform")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn discovers_jvm_build_markers_without_guessing_missing_tools() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-jvm-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("pom.xml"), "<project/>\n").expect("maven marker");
        let workspaces = discover(&root).expect("discovery");
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "jvm")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn discovers_csharp_project_markers_without_guessing_missing_dotnet() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-csharp-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("app.csproj"), "<Project/>\n").expect("project marker");
        let workspaces = discover(&root).expect("discovery");
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "csharp")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn discovers_cpp_build_markers_without_guessing_missing_tools() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-cpp-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.20)\n",
        )
        .expect("cmake marker");
        let workspaces = discover(&root).expect("discovery");
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "cpp")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn discovers_sql_migration_files_without_guessing_database_tools() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-sql-{}", std::process::id()));
        std::fs::create_dir_all(root.join("migrations")).expect("root");
        std::fs::write(
            root.join("migrations/001_init.sql"),
            "CREATE TABLE items(id INT);\n",
        )
        .expect("sql marker");
        let workspaces = discover(&root).expect("discovery");
        assert!(
            workspaces
                .iter()
                .any(|workspace| workspace.language == "sql")
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn ignored_trees_are_not_scanned() {
        let root =
            std::env::temp_dir().join(format!("lgtm-discovery-ignore-{}", std::process::id()));
        std::fs::create_dir_all(root.join("node_modules/pkg")).expect("ignored dir");
        std::fs::write(root.join("node_modules/pkg/package.json"), "{}\n").expect("marker");
        assert!(discover(&root).expect("discovery succeeds").is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_tree_instead_of_following_it() {
        let root = std::env::temp_dir().join(format!("lgtm-discovery-link-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("lgtm-discovery-outside-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, root.join("linked")).expect("symlink");
        assert!(matches!(
            discover(&root),
            Err(DiscoveryError::SymlinkRefused { .. })
        ));
        std::fs::remove_dir_all(root).ok();
        std::fs::remove_dir_all(outside).ok();
    }
}
