use std::path::{Component, Path, PathBuf};

pub(super) fn resolve(root: &Path, value: &str) -> Result<PathBuf, String> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    let supplied = Path::new(value);
    let relative = if supplied.is_absolute() {
        absolute_relative(&root, supplied)?
    } else {
        supplied.to_path_buf()
    };
    if relative
        .components()
        .any(|part| part == Component::ParentDir)
    {
        return Err("target escapes repository".to_string());
    }
    let target = root.join(&relative);
    verify_components(&root, &relative)?;
    if target.exists() {
        let canonical = target.canonicalize().map_err(|error| error.to_string())?;
        if !canonical.starts_with(&root) {
            return Err("target escapes repository through symlink".to_string());
        }
        return Ok(canonical);
    }
    Ok(target)
}

fn absolute_relative(root: &Path, supplied: &Path) -> Result<PathBuf, String> {
    let canonical = if supplied.exists() {
        supplied
            .canonicalize()
            .map_err(|_| "target escapes repository".to_string())?
    } else {
        let parent = supplied
            .parent()
            .ok_or_else(|| "target escapes repository".to_string())?
            .canonicalize()
            .map_err(|_| "target escapes repository".to_string())?;
        parent.join(
            supplied
                .file_name()
                .ok_or_else(|| "target escapes repository".to_string())?,
        )
    };
    canonical
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| "target escapes repository".to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_absolute_path_inside_root_and_rejects_outside() {
        let root = std::env::temp_dir().join(format!("lgtm-pre-target-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("root");
        let file = root.join("README.md");
        std::fs::write(&file, "ok\n").expect("file");
        assert_eq!(
            resolve(&root, &file.to_string_lossy()).expect("inside"),
            file.canonicalize().expect("canonical file")
        );
        let outside = std::env::temp_dir().join(format!("lgtm-pre-outside-{}", std::process::id()));
        std::fs::write(&outside, "outside\n").expect("outside");
        assert!(resolve(&root, &outside.to_string_lossy()).is_err());
        std::fs::remove_file(outside).ok();
        std::fs::remove_dir_all(root).ok();
    }
}
