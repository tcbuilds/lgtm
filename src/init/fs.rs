use super::*;

pub(super) fn read_if_exists(path: &Path) -> Result<Option<String>, InitError> {
    let file = match open_regular_file(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(source) => {
            return Err(InitError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mut contents = String::new();
    if let Err(source) = file.take(MAX_READ_BYTES + 1).read_to_string(&mut contents) {
        return Err(InitError::Read {
            path: path.to_path_buf(),
            source,
        });
    }
    if contents.len() as u64 > MAX_READ_BYTES {
        return Err(InitError::FileTooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_READ_BYTES,
        });
    }
    Ok(Some(contents))
}

/// Create a directory and all parents, mapping failure to a typed error.
pub(super) fn create_dir_all(path: &Path) -> Result<(), InitError> {
    std::fs::create_dir_all(path).map_err(|source| InitError::CreateDir {
        path: path.to_path_buf(),
        source,
    })
}

/// Validate every destination path and its parents before any write occurs.
///
/// For each target this rejects: a target that already exists as a symlink (a
/// write would follow it out of the repo), and any existing ancestor along the
/// path that is not a directory (a required parent that is a regular file or a
/// symlink would make directory creation or the final write fail partway
/// through). Running this preflight before the first `create_dir_all` keeps a
/// later failure — e.g. an unwritable `.gitignore` — from leaving partial
/// scaffolding behind.
pub(super) fn preflight_targets(paths: &[&Path]) -> Result<(), InitError> {
    for path in paths {
        if let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            return Err(InitError::SymlinkTarget {
                path: path.to_path_buf(),
            });
        }
        preflight_ancestors(path)?;
    }
    Ok(())
}

/// Reject any existing ancestor of `path` that is not a usable directory.
///
/// Walks each parent directory of `path` from the root down; the first ancestor
/// that exists but is not a directory (a regular file or a symlink) is a hard
/// error, because both directory creation under it and the eventual atomic write
/// would fail. Ancestors that do not yet exist are fine — they will be created.
fn preflight_ancestors(path: &Path) -> Result<(), InitError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    for ancestor in parent.ancestors() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            return Err(InitError::SymlinkTarget {
                path: ancestor.to_path_buf(),
            });
        }
        if !metadata.is_dir() {
            return Err(InitError::UnwritableTarget {
                path: ancestor.to_path_buf(),
                reason: "parent path exists and is not a directory".to_string(),
            });
        }
    }
    Ok(())
}

/// Process-local counter feeding temp file name entropy so two writes in the
/// same process (or same nanosecond) never collide on a temp name.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temp file that has been written and fsynced but not yet renamed over its
/// target, forming the staging half of the two-phase staged-commit write.
///
/// Holding the handle proves the destination directory was writable (the temp
/// write succeeded there). [`commit_write`] renames it over `final_path`; the
/// [`Drop`] impl removes it when the batch is abandoned before commit.
///
/// The [`Drop`] impl removes the temp file unless the write was committed, so
/// any early return or failure mid-batch discards every still-staged temp
/// automatically — a leaked temp can never survive on disk carrying preserved,
/// restrictively-permissioned content. `commit_write` sets `committed` before
/// the rename so the successfully renamed file is not targeted by Drop.
pub(super) struct StagedWrite {
    /// The final destination the temp file will be renamed over.
    pub(super) final_path: PathBuf,
    /// The sibling temp file already written and fsynced.
    pub(super) temp_path: PathBuf,
    /// Set once the temp has been renamed over its target, so [`Drop`] does not
    /// try to remove an already-committed (renamed-away) path.
    committed: bool,
}

impl Drop for StagedWrite {
    /// Remove any temp file that was staged but never committed, so an early
    /// return or a failed ritual in the batch never leaves a temp behind.
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

/// Stage a write for `path`: write its bytes to a uniquely named sibling temp
/// file and fsync it, without renaming over the target yet.
///
/// The temp file lives in the target's own directory so a later rename is a
/// same-filesystem atomic replace — a reader either sees the old file or the new
/// one, never a partially written file. The temp file is fsynced here so its
/// contents are durable before it replaces the target at commit time. A
/// successful stage also proves the destination directory is writable, which is
/// what lets the caller stage every output before committing any of them.
///
/// The temp name mixes the PID, nanoseconds since the epoch, and a
/// process-local counter so concurrent inits do not race on a shared, guessable
/// name, and the file is opened with `create_new(true)` so an attacker-planted
/// or leftover file of the same name causes a failure rather than a clobber or
/// symlink-followed write. Before staging, the final target is checked with
/// `symlink_metadata`: if it is a symlink, init refuses so a write can never be
/// redirected outside the repo.
///
/// On Unix the temp file is created with mode `0600` from the start, so
/// sensitive bytes are never world-readable even for the brief window between
/// the write and the mode fixup — a preserved `0600` `.claude/settings.json`
/// never leaves preserved content sitting in a default-`0644` temp. After the
/// content is fsynced the mode is relaxed to its final value: the target's own
/// bits when the target already exists (so a hardened `0600` file stays
/// `0600`), or `0644` for a brand-new project file that is not secret and
/// should be normally readable. The commit step reasserts the mode as a safety
/// net in case the target's mode changed between stage and commit.
pub(super) fn stage_write(path: &Path, bytes: &[u8]) -> Result<StagedWrite, InitError> {
    ensure_not_symlink(path)?;
    let temp_path = build_temp_path(path);
    write_temp_file(&temp_path, bytes).map_err(|source| {
        let _ = std::fs::remove_file(&temp_path);
        InitError::Write {
            path: temp_path.clone(),
            source,
        }
    })?;
    set_final_permissions(path, &temp_path)?;
    Ok(StagedWrite {
        final_path: path.to_path_buf(),
        temp_path,
        committed: false,
    })
}

fn ensure_not_symlink(path: &Path) -> Result<(), InitError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(InitError::SymlinkTarget {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn build_temp_path(path: &Path) -> PathBuf {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "settings".to_string());
    dir.join(temp_file_name(&file_name))
}

fn write_temp_file(temp_path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(temp_path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn set_final_permissions(path: &Path, temp_path: &Path) -> Result<(), InitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let final_permissions = match std::fs::metadata(path) {
            Ok(metadata) => metadata.permissions(),
            Err(_) => std::fs::Permissions::from_mode(0o644),
        };
        if let Err(source) = std::fs::set_permissions(temp_path, final_permissions) {
            let _ = std::fs::remove_file(temp_path);
            return Err(InitError::Write {
                path: temp_path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

/// Commit a staged write by renaming its temp file over the final target.
///
/// When the target already exists, its permission bits are copied onto the temp
/// file before the rename so the mode of an existing file (for example a
/// hand-hardened `0600` `.claude/settings.json`) survives the atomic replace
/// rather than being reset to the temp file's default mode. This is Unix-only;
/// on other platforms the rename simply replaces the file. On any failure the
/// staged temp is left for [`StagedWrite`]'s [`Drop`] to remove, so no staged
/// residue is left behind; on success `committed` is set before the rename so
/// Drop does not target the already-renamed path.
pub(super) fn commit_write(mut staged: StagedWrite) -> Result<(), InitError> {
    #[cfg(unix)]
    {
        if let Ok(metadata) = std::fs::metadata(&staged.final_path) {
            let permissions = metadata.permissions();
            if let Err(source) = std::fs::set_permissions(&staged.temp_path, permissions) {
                return Err(InitError::Write {
                    path: staged.final_path.clone(),
                    source,
                });
            }
        }
    }

    staged.committed = true;
    std::fs::rename(&staged.temp_path, &staged.final_path).map_err(|source| {
        staged.committed = false;
        InitError::Write {
            path: staged.final_path.clone(),
            source,
        }
    })
}

/// Build a hard-to-guess, collision-resistant temp file name for a target file.
///
/// Combines the target name, PID, nanoseconds since the epoch, and a
/// process-local counter. Std-only entropy is sufficient here because the temp
/// file is opened with `create_new(true)`: uniqueness prevents accidental
/// collisions and the exclusive open closes the symlink-following race.
fn temp_file_name(file_name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{file_name}.tmp-{}-{nanos}-{counter}", std::process::id())
}
