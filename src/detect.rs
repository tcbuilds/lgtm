//! Deterministic repository detection shared across commands.
//!
//! Detects a target repo's languages and the check commands available for each,
//! plus whether the root is a git repository. Detection is file-presence based
//! and performs no process execution — it reads only project metadata files, so
//! it is safe to run inside a hook on every session start as well as during
//! `lgtm init`.
//!
//! This module is the single source of truth for detection: both `init` (which
//! writes the detected commands into `.lgtm/config.json`) and the SessionStart
//! hook (which reports them in the harness contract) call [`detect`], so the two
//! never drift.

use std::path::Path;

use crate::fsutil::read_optional_bounded;

/// Byte cap for reading repo-controlled metadata (`pyproject.toml`). A file
/// larger than this is treated as absent so a hostile or accidentally huge
/// project file cannot force an unbounded read during detection. 256 KiB is far
/// above any legitimate `pyproject.toml`.
const MAX_METADATA_BYTES: u64 = 256 * 1024;

/// Which languages a target repo appears to use, and the checks available for
/// each. Detection is deterministic and file-presence based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Detected languages, e.g. `["python"]`. Empty when nothing is recognized.
    pub languages: Vec<String>,
    /// Detected check commands keyed by language, e.g. `{"python": [...]}`.
    pub required_commands: Vec<(String, Vec<String>)>,
    /// Whether the root directory directly contains a `.git` directory.
    pub is_git_repo: bool,
}

/// Detect languages and available check commands under `root`.
///
/// MVP scope: only Python is detected. Rules ship for Python first; TypeScript
/// is a fast-follow. No other language is recognized here by design, so a repo
/// in an unsupported language scaffolds with an empty command set rather than
/// guessing.
///
/// Python is recognized by the presence of `pyproject.toml`, `setup.py`,
/// `setup.cfg`, `requirements.txt`, or any top-level `.py` file. Check commands
/// are chosen by parsing `pyproject.toml` for tool tables and otherwise
/// defaulting to the standard trio. Detection performs no process execution and
/// reads only project metadata files. Git presence checks `root/.git` only; no
/// upward walk is performed (an MVP simplification — init is expected to run at
/// the repo root).
pub fn detect(root: &Path) -> Detection {
    let is_git_repo = root.join(".git").exists();
    let mut languages = Vec::new();
    let mut required_commands = Vec::new();

    if detects_python(root) {
        languages.push("python".to_string());
        required_commands.push(("python".to_string(), python_commands(root)));
    }

    Detection {
        languages,
        required_commands,
        is_git_repo,
    }
}

/// True when the root contains any recognized Python project marker.
fn detects_python(root: &Path) -> bool {
    if root.join("pyproject.toml").exists()
        || root.join("setup.py").exists()
        || root.join("setup.cfg").exists()
        || root.join("requirements.txt").exists()
    {
        return true;
    }
    has_top_level_python_file(root)
}

/// True when at least one entry directly under `root` is a `.py` file.
fn has_top_level_python_file(root: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "py")
    })
}

/// The check commands to require for Python, derived from detected tooling.
///
/// A tool is included when its configuration table is present in
/// A tool is included when its configuration table or dependency declaration is
/// present. `pytest.ini` and `tox.ini` also prove pytest. Unknown tools are not
/// guessed; users can add explicit commands in `.lgtm/config.json`.
fn python_commands(root: &Path) -> Vec<String> {
    let config_text = read_optional_bounded(&root.join("pyproject.toml"), MAX_METADATA_BYTES);
    let pytest_command = if uses_uv(root, &config_text) {
        "uv run pytest"
    } else {
        "pytest"
    };
    let mypy_command = if root.join("src").is_dir() {
        "mypy --strict src".to_string()
    } else {
        "mypy --strict .".to_string()
    };

    let mut commands = Vec::new();
    if has_toml_table(&config_text, "tool.ruff") || has_dependency(root, "ruff") {
        commands.push("ruff check .".to_string());
        commands.push("ruff format --check".to_string());
    }
    if has_toml_table(&config_text, "tool.mypy") || has_dependency(root, "mypy") {
        commands.push(mypy_command.clone());
    }
    if has_pytest_table(&config_text)
        || root.join("pytest.ini").is_file()
        || root.join("tox.ini").is_file()
        || has_dependency(root, "pytest")
    {
        commands.push(pytest_command.to_string());
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

fn uses_uv(root: &Path, pyproject: &str) -> bool {
    std::fs::symlink_metadata(root.join("uv.lock")).is_ok_and(|metadata| metadata.is_file())
        || has_toml_table(pyproject, "tool.uv")
}

/// True when `text` contains a TOML table header for exactly `name`, i.e. a
/// line that is `[name]` after trimming surrounding whitespace.
fn has_toml_table(text: &str, name: &str) -> bool {
    let header = format!("[{name}]");
    text.lines().any(|line| line.trim() == header)
}

/// True when `text` contains any pytest configuration table, i.e. a line whose
/// trimmed form is a `[tool.pytest...]` table header (e.g.
/// `[tool.pytest.ini_options]`).
fn has_pytest_table(text: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("[tool.pytest") && trimmed.ends_with(']')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_toml_table_is_line_anchored() {
        let text = "[tool.ruff]\nline-length = 88\n";
        assert!(has_toml_table(text, "tool.ruff"));
        assert!(!has_toml_table("# ruff is great\n", "tool.ruff"));
        assert!(!has_toml_table("[tool.ruff.lint]\n", "tool.ruff"));
    }

    #[test]
    fn has_pytest_table_matches_ini_options() {
        assert!(has_pytest_table("[tool.pytest.ini_options]\n"));
        assert!(!has_pytest_table("dependencies = [\"pytest\"]\n"));
    }

    #[test]
    fn oversized_pyproject_does_not_invent_commands() {
        let unique = format!(
            "lgtm-detect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root).expect("temp dir creatable");

        let table = "[tool.ruff]\n";
        let padding = "#".repeat((MAX_METADATA_BYTES as usize) + 1);
        std::fs::write(root.join("pyproject.toml"), format!("{table}{padding}"))
            .expect("write oversized pyproject");

        let commands = python_commands(&root);

        std::fs::remove_dir_all(&root).ok();

        assert!(commands.is_empty());
    }

    #[test]
    fn uv_repo_prefers_uv_run_pytest_but_plain_repo_keeps_pytest() {
        let root = std::env::temp_dir().join(format!("lgtm-detect-uv-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temp dir");
        std::fs::write(root.join("pyproject.toml"), "[tool.pytest.ini_options]\n")
            .expect("pyproject");
        assert_eq!(python_commands(&root), ["pytest"]);
        std::fs::write(root.join("uv.lock"), "version = 1\n").expect("uv lock");
        assert_eq!(python_commands(&root), ["uv run pytest"]);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn pytest_ini_and_requirements_prove_pytest_only() {
        let root = std::env::temp_dir().join(format!("lgtm-detect-pytest-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temp dir");
        std::fs::write(root.join("pytest.ini"), "[pytest]\n").expect("pytest config");
        std::fs::write(root.join("requirements.txt"), "pytest>=8\n").expect("requirements");
        assert_eq!(python_commands(&root), ["pytest"]);
        std::fs::remove_dir_all(root).ok();
    }
}
