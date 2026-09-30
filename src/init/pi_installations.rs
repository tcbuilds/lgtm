//! Track managed Pi extensions without searching unrelated repositories.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fs::{
    commit_write, create_private_dir_all, preflight_file_targets, preflight_targets,
    stage_private_write, stage_write,
};
use super::pi::{self, ExtensionScope};
use super::{InitError, read_if_exists};

const MAX_INSTALLATIONS: usize = 4096;
const REFRESH_BUDGET: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    version: u8,
    target: PathBuf,
    binary: PathBuf,
    global: bool,
}

fn registry(home: &Path) -> PathBuf {
    home.join(".local/state/lgtm/pi-installations")
}

pub(crate) fn register(
    home: &Path,
    target: &Path,
    binary: &str,
    scope: ExtensionScope,
) -> Result<(), InitError> {
    if !home.is_absolute() || !Path::new(binary).is_absolute() {
        return Err(InitError::UnwritableTarget {
            path: target.to_path_buf(),
            reason: "Pi installation HOME and executable must be absolute paths".to_string(),
        });
    }
    preflight_file_targets(&[target])?;
    let target = std::fs::canonicalize(target).map_err(|source| InitError::Read {
        path: target.to_path_buf(),
        source,
    })?;
    let directory = registry(home);
    preflight_targets(home, &[&directory.join("installation.json")])?;
    create_private_dir_all(&directory)?;
    let key = Sha256::digest(target.as_os_str().as_encoded_bytes());
    let path = directory.join(format!("{key:x}.json"));
    let installation = Installation {
        version: 1,
        target,
        binary: PathBuf::from(binary),
        global: scope == ExtensionScope::Global,
    };
    let bytes = serde_json::to_vec(&installation).map_err(|error| InitError::UnwritableTarget {
        path: path.clone(),
        reason: format!("serialize Pi installation ({error})"),
    })?;
    let existing = read_if_exists(&path)?;
    if existing.as_deref().map(str::as_bytes) == Some(bytes.as_slice()) {
        return Ok(());
    }
    if existing.is_none() {
        require_registry_capacity(&directory)?;
    }
    commit_write(stage_private_write(&path, &bytes)?)
}

fn require_registry_capacity(directory: &Path) -> Result<(), InitError> {
    let entries = std::fs::read_dir(directory).map_err(|source| InitError::Read {
        path: directory.to_path_buf(),
        source,
    })?;
    let deadline = Instant::now() + REFRESH_BUDGET;
    for (index, entry) in entries.enumerate() {
        entry.map_err(|source| InitError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        if index >= MAX_INSTALLATIONS - 1 || Instant::now() >= deadline {
            return Err(InitError::UnwritableTarget {
                path: directory.to_path_buf(),
                reason: "Pi installation registry is full or its traversal timed out; remove stale registrations before retrying".to_string(),
            });
        }
    }
    Ok(())
}

pub(crate) fn register_project(target: &Path, binary: &str) -> Result<(), InitError> {
    let home = std::env::var_os("HOME").ok_or_else(|| InitError::UnwritableTarget {
        path: target.to_path_buf(),
        reason: "HOME is required to track Pi installations".to_string(),
    })?;
    register(Path::new(&home), target, binary, ExtensionScope::Project)
}

/// Refresh only registered, still-present, canonical managed extensions.
/// Never install a missing extension: absence may mean deliberate disablement.
pub fn refresh() -> Result<String, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is required to refresh Pi installations")?;
    let binary =
        std::env::current_exe().map_err(|error| format!("resolve executable ({error})"))?;
    refresh_at(Path::new(&home), &binary)
}

fn refresh_at(home: &Path, binary: &Path) -> Result<String, String> {
    if !home.is_absolute() {
        return Err("Pi installation HOME must be an absolute path".to_string());
    }
    let directory = registry(home);
    preflight_targets(home, &[&directory.join("installation.json")])
        .map_err(|error| error.to_string())?;
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok("No tracked Pi extensions. Register existing repositories once with lgtm init --agent pi.".to_string());
        }
        Err(error) => return Err(format!("read Pi installation registry ({error})")),
    };
    let deadline = Instant::now() + REFRESH_BUDGET;
    let mut refreshed = 0;
    let mut preserved = 0;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_INSTALLATIONS || Instant::now() >= deadline {
            return Err(
                "Pi extension refresh exceeded its bounded installation budget".to_string(),
            );
        }
        let path = entry
            .map_err(|error| format!("read Pi installation entry ({error})"))?
            .path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let installation = read_installation(&path)?;
        if std::fs::canonicalize(&installation.binary).ok().as_deref() != Some(binary) {
            preserved += 1;
            continue;
        }
        match refresh_one(&installation) {
            Ok(true) => refreshed += 1,
            Ok(false) => preserved += 1,
            Err(error) => {
                return Err(format!(
                    "refresh Pi extension {} ({error}); binary is installed, repair and run lgtm refresh-pi",
                    installation.target.display()
                ));
            }
        }
    }
    Ok(format!(
        "Pi extensions: {refreshed} refreshed, {preserved} unchanged or preserved. Reload running Pi sessions. Register untracked repositories once with lgtm init --agent pi."
    ))
}

fn read_installation(path: &Path) -> Result<Installation, String> {
    let raw = read_if_exists(path)
        .map_err(|error| error.to_string())?
        .ok_or("Pi installation disappeared during refresh")?;
    let installation: Installation = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid Pi installation {} ({error})", path.display()))?;
    if installation.version != 1
        || !installation.target.is_absolute()
        || !installation.binary.is_absolute()
    {
        return Err(format!(
            "invalid Pi installation identity: {}",
            path.display()
        ));
    }
    Ok(installation)
}

fn refresh_one(installation: &Installation) -> Result<bool, String> {
    let target = &installation.target;
    let suffix = if installation.global {
        ".pi/agent/extensions/lgtm.ts"
    } else {
        ".pi/extensions/lgtm.ts"
    };
    if !target.ends_with(suffix) {
        return Err("registered path is not a Pi extension location".to_string());
    }
    let root = target
        .ancestors()
        .nth(if installation.global { 4 } else { 3 })
        .ok_or("registered extension has no installation root")?;
    preflight_targets(root, &[target]).map_err(|error| error.to_string())?;
    preflight_file_targets(&[target]).map_err(|error| error.to_string())?;
    let binary = &installation.binary;
    let Some(existing) = read_if_exists(target).map_err(|error| error.to_string())? else {
        return Ok(false);
    };
    // A tracked path must still reference the same executable. Do not repoint
    // extensions that the owner deliberately moved to a different installation.
    let declared_binary = existing.lines().find_map(|line| {
        line.strip_prefix("const LGTM_BINARY = ")
            .and_then(|value| value.strip_suffix(';'))
            .and_then(|value| serde_json::from_str::<String>(value).ok())
    });
    if declared_binary.as_deref().map(Path::new) != Some(binary) {
        return Ok(false);
    }
    let scope = if installation.global {
        ExtensionScope::Global
    } else {
        ExtensionScope::Project
    };
    let binary = binary.to_str().ok_or("Pi executable path is not UTF-8")?;
    let generated = pi::render(binary, scope).map_err(|error| error.to_string())?;
    if !pi::owned_template(&existing, &generated, scope) {
        return Ok(false);
    }
    let backup = target.with_file_name("lgtm.ts.bak");
    preflight_file_targets(&[&backup]).map_err(|error| error.to_string())?;
    let plan = pi::plan(target, &backup, binary, scope).map_err(|error| error.to_string())?;
    if let Some(bytes) = plan.backup_contents {
        commit_write(stage_private_write(&backup, &bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    }
    if let Some(bytes) = plan.target_contents {
        commit_write(stage_write(target, &bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        return Ok(true);
    }
    Ok(false)
}
