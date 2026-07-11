use std::path::{Component, Path, PathBuf};

pub(super) fn resolve(root: &Path, value: &str) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err("target escapes repository".to_string());
    }
    let target = root.join(relative);
    verify_components(&root, relative)?;
    if target.exists() {
        let canonical = target.canonicalize().map_err(|error| error.to_string())?;
        if !canonical.starts_with(&root) {
            return Err("target escapes repository through symlink".to_string());
        }
        return Ok(canonical);
    }
    Ok(target)
}

fn verify_components(root: &Path, relative: &Path) -> Result<(), String> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_) | Component::CurDir) {
            return Err("target has invalid path component".to_string());
        }
        current.push(component);
        if std::fs::symlink_metadata(&current)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("target path contains symlink".to_string());
        }
    }
    Ok(())
}
