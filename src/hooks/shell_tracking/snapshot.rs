use std::collections::{BTreeMap, BTreeSet};
use std::fs::Metadata;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_PATHS: usize = 4_096;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CAPTURE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CHANGED_PATHS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Snapshot {
    pub(super) files: BTreeMap<String, Fingerprint>,
    pub(super) head: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Fingerprint {
    Present { sha256: String, executable: bool },
    Missing,
}

mod git;
use git::{collect_dirty_paths, head_identity};

struct ReadBudget {
    bytes_read: u64,
}

pub(super) fn capture(root: &Path, deadline: Instant) -> Result<Snapshot, String> {
    let root = canonical_root(root, deadline)?;
    let head = head_identity(&root, deadline)?;
    let mut budget = ReadBudget { bytes_read: 0 };
    let mut files = BTreeMap::new();
    for path in collect_dirty_paths(&root, deadline)? {
        check_deadline(deadline)?;
        files.insert(
            path.clone(),
            fingerprint_path(&root, &path, deadline, &mut budget)?,
        );
    }
    if head_identity(&root, deadline)? != head {
        return Err("HEAD changed while capturing the repository snapshot".to_string());
    }
    Ok(Snapshot { files, head })
}

pub(super) fn changed(
    root: &Path,
    before: &Snapshot,
    after: &Snapshot,
    deadline: Instant,
) -> Result<Vec<String>, String> {
    validate_snapshot(before)?;
    validate_snapshot(after)?;
    if before.head != after.head {
        return Err("HEAD changed between repository snapshots".to_string());
    }
    let root = canonical_root(root, deadline)?;
    if head_identity(&root, deadline)? != before.head {
        return Err("HEAD no longer matches repository snapshots".to_string());
    }

    let mut paths = BTreeSet::new();
    for path in before.files.keys().chain(after.files.keys()) {
        if !is_evidence_path(path)? {
            inspect_repo_path(&root, path, deadline)?;
            paths.insert(path.clone());
        }
    }
    if paths.len() > MAX_PATHS {
        return Err(format!("snapshot path union exceeds {MAX_PATHS}"));
    }

    let mut budget = ReadBudget { bytes_read: 0 };
    let mut changed = Vec::new();
    for path in paths {
        check_deadline(deadline)?;
        let is_changed = match (before.files.get(&path), after.files.get(&path)) {
            (None, Some(_)) => true,
            (Some(before), Some(after)) => before != after,
            (Some(before), None) => {
                fingerprint_path(&root, &path, deadline, &mut budget)? != *before
            }
            (None, None) => false,
        };
        if is_changed {
            if changed.len() == MAX_CHANGED_PATHS {
                return Err(format!("changed path count exceeds {MAX_CHANGED_PATHS}"));
            }
            changed.push(path);
        }
    }
    if head_identity(&root, deadline)? != before.head {
        return Err("HEAD changed while comparing repository snapshots".to_string());
    }
    Ok(changed)
}

fn canonical_root(root: &Path, deadline: Instant) -> Result<PathBuf, String> {
    check_deadline(deadline)?;
    let root = std::fs::canonicalize(root)
        .map_err(|error| format!("could not resolve repository root ({error})"))?;
    let metadata = std::fs::metadata(&root)
        .map_err(|error| format!("could not inspect repository root ({error})"))?;
    if !metadata.is_dir() {
        return Err("repository root is not a directory".to_string());
    }
    check_deadline(deadline)?;
    Ok(root)
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.files.len() > MAX_PATHS {
        return Err(format!("snapshot exceeds the {MAX_PATHS}-path limit"));
    }
    validate_head_identity(&snapshot.head)?;
    for (path, fingerprint) in &snapshot.files {
        validate_relative_path(path)?;
        if let Fingerprint::Present { sha256, .. } = fingerprint
            && (sha256.len() != 64
                || !sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(format!("snapshot has an invalid SHA-256 for path {path:?}"));
        }
    }
    Ok(())
}

fn validate_head_identity(head: &str) -> Result<(), String> {
    if let Some(reference) = head.strip_prefix("unborn:") {
        if reference.starts_with("refs/heads/") && !reference.chars().any(char::is_control) {
            return Ok(());
        }
    } else if (40..=64).contains(&head.len())
        && head
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err("snapshot has an invalid HEAD identity".to_string())
}

fn validate_relative_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
        return Err(format!(
            "snapshot path is empty or exceeds {MAX_PATH_BYTES} bytes"
        ));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "snapshot path is not a normalized repository path: {path:?}"
        ));
    }
    #[cfg(windows)]
    if path.contains('\\') {
        return Err(format!(
            "snapshot path contains a Windows separator: {path:?}"
        ));
    }

    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("snapshot path escapes the repository: {path:?}"));
    }
    Ok(relative.to_path_buf())
}

fn is_evidence_path(path: &str) -> Result<bool, String> {
    let relative = validate_relative_path(path)?;
    let mut components = relative.components();
    Ok(
        matches!(components.next(), Some(Component::Normal(name)) if name == ".lgtm")
            && matches!(components.next(), Some(Component::Normal(name)) if name == "evidence"),
    )
}

fn fingerprint_path(
    root: &Path,
    relative: &str,
    deadline: Instant,
    budget: &mut ReadBudget,
) -> Result<Fingerprint, String> {
    let Some((path, path_metadata)) = inspect_repo_path(root, relative, deadline)? else {
        return Ok(Fingerprint::Missing);
    };
    let file = crate::fsutil::open_regular_file(&path)
        .map_err(|error| format!("could not open snapshot path {relative:?} ({error})"))?
        .ok_or_else(|| format!("snapshot path changed or is not a regular file: {relative:?}"))?;
    let metadata_before = file
        .metadata()
        .map_err(|error| format!("could not inspect snapshot file {relative:?} ({error})"))?;
    if !metadata_matches(&path_metadata, &metadata_before) {
        return Err(format!(
            "snapshot path changed while it was opened: {relative:?}"
        ));
    }
    let file_bytes = metadata_before.len();
    if file_bytes > MAX_FILE_BYTES {
        return Err(format!(
            "snapshot file exceeds the {MAX_FILE_BYTES}-byte limit: {relative:?}"
        ));
    }
    if budget
        .bytes_read
        .checked_add(file_bytes)
        .is_none_or(|total| total > MAX_CAPTURE_BYTES)
    {
        return Err(format!(
            "snapshot exceeds the {MAX_CAPTURE_BYTES}-byte read budget"
        ));
    }

    let mut reader = file.take(file_bytes);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut bytes_read = 0_u64;
    while bytes_read < file_bytes {
        check_deadline(deadline)?;
        let remaining = file_bytes - bytes_read;
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "snapshot read size is not representable".to_string())?;
        let count = reader
            .read(&mut buffer[..read_limit])
            .map_err(|error| format!("could not read snapshot path {relative:?} ({error})"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes_read += count as u64;
        budget.bytes_read += count as u64;
    }

    let metadata_after = reader
        .get_ref()
        .metadata()
        .map_err(|error| format!("could not recheck snapshot file {relative:?} ({error})"))?;
    let path_after = inspect_repo_path(root, relative, deadline)?;
    let Some((_, path_metadata_after)) = path_after else {
        return Err(format!(
            "snapshot path disappeared while it was read: {relative:?}"
        ));
    };
    if !metadata_matches(&metadata_before, &metadata_after)
        || !metadata_matches(&metadata_before, &path_metadata_after)
        || bytes_read != file_bytes
    {
        return Err(format!(
            "snapshot file changed while it was read: {relative:?}"
        ));
    }
    check_deadline(deadline)?;

    Ok(Fingerprint::Present {
        sha256: format!("{:x}", hasher.finalize()),
        executable: executable_mode(&metadata_after)?,
    })
}

fn inspect_repo_path(
    root: &Path,
    relative: &str,
    deadline: Instant,
) -> Result<Option<(PathBuf, Metadata)>, String> {
    let relative = validate_relative_path(relative)?;
    let components: Vec<_> = relative.components().collect();
    let mut path = root.to_path_buf();

    for (index, component) in components.iter().enumerate() {
        check_deadline(deadline)?;
        let Component::Normal(name) = component else {
            return Err("snapshot path contains a non-normal component".to_string());
        };
        path.push(name);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "could not inspect snapshot path {relative:?} ({error})"
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(format!("snapshot path contains a symlink: {relative:?}"));
        }
        let is_final = index + 1 == components.len();
        if is_final && !metadata.file_type().is_file() {
            return Err(format!("snapshot path is not a regular file: {relative:?}"));
        }
        if !is_final && !metadata.is_dir() {
            return Err(format!(
                "snapshot path has a non-directory ancestor: {relative:?}"
            ));
        }
    }
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("could not recheck snapshot path {relative:?} ({error})"))?;
    Ok(Some((path, metadata)))
}

fn metadata_matches(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mode() == right.mode()
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
            && left.permissions().readonly() == right.permissions().readonly()
            && left.modified().ok() == right.modified().ok()
    }
}

#[cfg(unix)]
fn executable_mode(metadata: &Metadata) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt;
    Ok(metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn executable_mode(_metadata: &Metadata) -> Result<bool, String> {
    Err("executable file mode is unsupported on this platform".to_string())
}

fn check_deadline(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("repository snapshot deadline expired".to_string())
    } else {
        Ok(())
    }
}
