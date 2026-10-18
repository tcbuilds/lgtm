//! Personal Pi checkpoint extension installed by every CLI init variant.

use std::path::{Path, PathBuf};

use super::{InitError, fs};

const TEMPLATE: &str = include_str!("../../templates/pi/checkpoint.ts");
const LABEL: &str = ".pi/agent/extensions/lgtm-checkpoint.ts";

/// Validate or install the checkpoint without replacing a user-authored file.
///
/// Dry runs validate the destination but do not create directories or files.
/// Existing different content is an owner override, even if it carries a marker.
pub fn install(home: &Path, dry_run: bool) -> Result<String, InitError> {
    if !home.is_absolute() {
        return Err(InitError::UnwritableTarget {
            path: home.to_path_buf(),
            reason: "HOME must be an absolute path".to_string(),
        });
    }
    let target = home.join(LABEL);
    fs::preflight_targets(home, &[&target])?;
    fs::preflight_file_targets(&[&target])?;
    if let Some(existing) = fs::read_if_exists(&target)? {
        return Ok(if existing == TEMPLATE {
            format!("Pi checkpoint already current: {}", target.display())
        } else {
            format!(
                "preserved existing Pi checkpoint override: {}",
                target.display()
            )
        });
    }
    if dry_run {
        return Ok(format!(
            "would install global Pi checkpoint: {}",
            target.display()
        ));
    }
    let parent = target.parent().ok_or_else(|| InitError::UnwritableTarget {
        path: target.clone(),
        reason: "checkpoint has no parent directory".to_string(),
    })?;
    fs::create_dir_all(parent)?;
    let staged = fs::stage_private_write(&target, TEMPLATE.as_bytes())?;
    // Another init may have installed an owner override while this write staged.
    if fs::read_if_exists(&target)?.is_none() {
        fs::commit_write(staged)?;
        return Ok(format!(
            "installed global Pi checkpoint: {}",
            target.display()
        ));
    }
    Ok(format!(
        "preserved concurrent Pi checkpoint install: {}",
        target.display()
    ))
}

/// Resolve the same home directory used by global harness initialization.
pub fn home() -> Result<PathBuf, InitError> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| InitError::UnwritableTarget {
            path: PathBuf::from("$HOME"),
            reason: "HOME is missing or empty".to_string(),
        })
}
