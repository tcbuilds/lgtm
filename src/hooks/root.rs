//! Resolve hook cwd to the repository root, even when harness runs in a workspace.

use std::path::PathBuf;

pub(crate) fn resolve(cwd: Option<&str>) -> Result<PathBuf, String> {
    let candidate = cwd
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|error| format!("resolve cwd ({error})"))?;
    let original =
        std::fs::canonicalize(candidate).map_err(|error| format!("canonicalize cwd ({error})"))?;
    let mut current = original.clone();
    if !current.is_dir() {
        return Err("cwd is not a directory".to_string());
    }
    loop {
        if current.join(".git/HEAD").is_file()
            || current.join(".git").is_file()
            || current.join(".lgtm/config.json").is_file()
        {
            return Ok(current);
        }
        let Some(parent) = current.parent() else {
            return Ok(original);
        };
        if parent == current {
            return Ok(original);
        }
        current = parent.to_path_buf();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn climbs_workspace_to_git_root() {
        let root = std::env::temp_dir().join(format!("lgtm-hook-root-{}", std::process::id()));
        std::fs::create_dir_all(root.join("backend")).expect("workspace");
        std::fs::create_dir_all(root.join(".git")).expect("git marker");
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").expect("git head");
        assert_eq!(
            resolve(Some(&root.join("backend").display().to_string())).unwrap(),
            root
        );
        std::fs::remove_dir_all(root).ok();
    }
}
