//! Bounded, deterministic discovery of nested workspaces and quality gates.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::fsutil::read_optional_bounded;

const MAX_DEPTH: usize = 8;
const MAX_WORKSPACES: usize = 64;
const MAX_ENTRIES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Workspace {
    pub id: String,
    pub language: String,
    pub root: PathBuf,
    pub commands: Vec<CommandSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    #[error("discovery exceeded {limit} filesystem entries")]
    EntryLimit { limit: usize },
    #[error("discovery found more than {limit} workspaces")]
    WorkspaceLimit { limit: usize },
}

/// Find supported nested workspaces without executing repository code.
pub fn discover(root: &Path) -> Result<Vec<Workspace>, DiscoveryError> {
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
    walk(root, root, 0, &mut entries_seen, &mut candidates)?;
    candidates.sort();
    candidates.dedup();

    let mut workspaces = Vec::new();
    for path in candidates {
        if let Some(workspace) = workspace_for(root, &path) {
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

fn walk(
    root: &Path,
    current: &Path,
    depth: usize,
    entries_seen: &mut usize,
    candidates: &mut Vec<PathBuf>,
) -> Result<(), DiscoveryError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let entries = std::fs::read_dir(current).map_err(|_| DiscoveryError::RootNotDirectory {
        path: current.to_path_buf(),
    })?;
    for entry in entries {
        *entries_seen += 1;
        if *entries_seen > MAX_ENTRIES {
            return Err(DiscoveryError::EntryLimit { limit: MAX_ENTRIES });
        }
        let entry = entry.map_err(|_| DiscoveryError::RootNotDirectory {
            path: current.to_path_buf(),
        })?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| DiscoveryError::RootNotDirectory { path: path.clone() })?;
        if metadata.file_type().is_symlink() {
            return Err(DiscoveryError::SymlinkRefused { path });
        }
        if metadata.is_dir() {
            if !ignored_dir(entry.file_name().to_string_lossy().as_ref()) {
                walk(root, &path, depth + 1, entries_seen, candidates)?;
            }
        } else if metadata.is_file() && is_marker(path.file_name().and_then(|name| name.to_str())) {
            candidates.push(path.parent().unwrap_or(root).to_path_buf());
        }
    }
    Ok(())
}

fn ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
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
    )
}

fn is_marker(name: Option<&str>) -> bool {
    matches!(
        name,
        Some("pyproject.toml" | "package.json" | "tsconfig.json" | "Cargo.toml" | "go.mod")
    )
}

fn workspace_for(root: &Path, path: &Path) -> Option<Workspace> {
    let relative = path.strip_prefix(root).ok()?.to_path_buf();
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative
    };
    let markers = marker_set(path);
    let (language, commands) = if markers.contains("pyproject.toml") {
        ("python", python_commands(path))
    } else if markers.contains("package.json") || markers.contains("tsconfig.json") {
        ("typescript", typescript_commands(path))
    } else if markers.contains("Cargo.toml") {
        ("rust", rust_commands())
    } else if markers.contains("go.mod") {
        ("go", go_commands())
    } else {
        return None;
    };
    let id = if relative == Path::new(".") {
        language.to_string()
    } else {
        relative.to_string_lossy().replace(['/', '\\'], "-")
    };
    Some(Workspace {
        id,
        language: language.to_string(),
        root: relative.clone(),
        commands: commands
            .into_iter()
            .map(|(argv, purpose, confidence)| CommandSpec {
                argv,
                cwd: relative.clone(),
                timeout_seconds: 300,
                tier: "full".to_string(),
                purpose: purpose.to_string(),
                source: "discovery".to_string(),
                confidence: confidence.to_string(),
            })
            .collect(),
    })
}

fn marker_set(path: &Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .collect()
}

fn python_commands(root: &Path) -> Vec<(Vec<String>, &'static str, &'static str)> {
    let pyproject = read_optional_bounded(&root.join("pyproject.toml"), MAX_METADATA_BYTES);
    let uv =
        root.join("uv.lock").is_file() || pyproject.lines().any(|line| line.trim() == "[tool.uv]");
    let prefix: Vec<String> = if uv { vec!["uv", "run"] } else { Vec::new() }
        .into_iter()
        .map(String::from)
        .collect();
    let configured = has_table(&pyproject, "tool.ruff")
        || has_table(&pyproject, "tool.mypy")
        || pyproject
            .lines()
            .any(|line| line.trim().starts_with("[tool.pytest"));
    let mut commands = Vec::new();
    for (tool, args, purpose) in [
        ("ruff", vec!["check"], "lint"),
        ("ruff", vec!["format", "--check"], "format"),
        ("mypy", vec![], "types"),
        ("pytest", vec![], "test"),
    ] {
        let mut argv = prefix.clone();
        argv.push(tool.to_string());
        argv.extend(args.into_iter().map(String::from));
        if !configured || tool == "pytest" || has_table(&pyproject, &format!("tool.{tool}")) {
            commands.push((argv, purpose, if configured { "high" } else { "medium" }));
        }
    }
    commands
}

fn typescript_commands(root: &Path) -> Vec<(Vec<String>, &'static str, &'static str)> {
    let package = read_optional_bounded(&root.join("package.json"), MAX_METADATA_BYTES);
    let manager = if root.join("pnpm-lock.yaml").is_file() {
        "pnpm"
    } else {
        "npm"
    };
    let scripts = ["lint", "typecheck", "test"];
    scripts
        .into_iter()
        .filter(|script| package.contains(&format!("\"{script}\"")))
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
    ]
}

fn go_commands() -> Vec<(Vec<String>, &'static str, &'static str)> {
    vec![
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
    ]
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
