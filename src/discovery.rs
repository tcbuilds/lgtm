//! Bounded, deterministic discovery of nested workspaces and quality gates.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::fsutil::read_optional_bounded;

const MAX_DEPTH: usize = 8;
const MAX_WORKSPACES: usize = 64;
const MAX_ENTRIES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 256 * 1024;

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
    )
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
    ) || name.ends_with(".sh")
        || name.ends_with(".tf")
}

fn workspace_for(root: &Path, path: &Path) -> Option<Workspace> {
    let relative = path.strip_prefix(root).ok()?.to_path_buf();
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative
    };
    let markers = marker_set(path);
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
    } else if markers.iter().any(|marker| marker.ends_with(".sh")) {
        ("shell", shell_commands(path, &markers))
    } else if markers.iter().any(|marker| marker.ends_with(".tf")) {
        ("terraform", terraform_commands())
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
        coverage: Vec::new(),
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
