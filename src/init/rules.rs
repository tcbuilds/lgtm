//! Binary-free rules mode.
//!
//! Writes the standards templates into `.claude/rules/` without registering any
//! hooks. Everything lands under that directory so an existing `CLAUDE.md` is
//! never touched; the entry document carries no `paths:` frontmatter, which
//! Claude Code loads every session.

use std::path::Path;

const PREFIX: &str = ".claude/rules";

/// Embedded templates as (path relative to `.claude/rules`, contents).
const TEMPLATES: &[(&str, &str)] = &[
    (
        "standards.md",
        include_str!("../../templates/claude-rules/CLAUDE.md"),
    ),
    (
        "c-cpp.md",
        include_str!("../../templates/claude-rules/rules/c-cpp.md"),
    ),
    (
        "config.md",
        include_str!("../../templates/claude-rules/rules/config.md"),
    ),
    (
        "csharp.md",
        include_str!("../../templates/claude-rules/rules/csharp.md"),
    ),
    (
        "go.md",
        include_str!("../../templates/claude-rules/rules/go.md"),
    ),
    (
        "infrastructure.md",
        include_str!("../../templates/claude-rules/rules/infrastructure.md"),
    ),
    (
        "jvm.md",
        include_str!("../../templates/claude-rules/rules/jvm.md"),
    ),
    (
        "python.md",
        include_str!("../../templates/claude-rules/rules/python.md"),
    ),
    (
        "react.md",
        include_str!("../../templates/claude-rules/rules/react.md"),
    ),
    (
        "rust.md",
        include_str!("../../templates/claude-rules/rules/rust.md"),
    ),
    (
        "shell.md",
        include_str!("../../templates/claude-rules/rules/shell.md"),
    ),
    (
        "sql.md",
        include_str!("../../templates/claude-rules/rules/sql.md"),
    ),
    (
        "testing.md",
        include_str!("../../templates/claude-rules/rules/testing.md"),
    ),
    (
        "typescript.md",
        include_str!("../../templates/claude-rules/rules/typescript.md"),
    ),
    (
        "web-ui.md",
        include_str!("../../templates/claude-rules/rules/web-ui.md"),
    ),
    (
        "patterns/core.md",
        include_str!("../../templates/claude-rules/rules/patterns/core.md"),
    ),
    (
        "patterns/go.md",
        include_str!("../../templates/claude-rules/rules/patterns/go.md"),
    ),
    (
        "patterns/python.md",
        include_str!("../../templates/claude-rules/rules/patterns/python.md"),
    ),
    (
        "patterns/react.md",
        include_str!("../../templates/claude-rules/rules/patterns/react.md"),
    ),
    (
        "patterns/rust.md",
        include_str!("../../templates/claude-rules/rules/patterns/rust.md"),
    ),
    (
        "patterns/sql.md",
        include_str!("../../templates/claude-rules/rules/patterns/sql.md"),
    ),
    (
        "patterns/testing.md",
        include_str!("../../templates/claude-rules/rules/patterns/testing.md"),
    ),
    (
        "patterns/typescript.md",
        include_str!("../../templates/claude-rules/rules/patterns/typescript.md"),
    ),
];

/// Outcome of a rules-only installation.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Installed {
    pub written: Vec<String>,
    pub unchanged: Vec<String>,
    pub kept: Vec<String>,
}

/// Write the templates under `.claude/rules`, preserving edited files.
///
/// A file whose contents already match the template is reported as unchanged. A
/// file that differs is left alone and reported as kept, so local edits survive
/// re-running the command.
pub fn install(root: &Path) -> Result<Installed, String> {
    let mut outcome = Installed::default();
    for (relative, contents) in TEMPLATES {
        let target = root.join(PREFIX).join(relative);
        match read_existing(&target)? {
            Some(existing) if existing == *contents => {
                outcome.unchanged.push((*relative).to_string())
            }
            Some(_) => outcome.kept.push((*relative).to_string()),
            None => {
                write_template(&target, contents)?;
                outcome.written.push((*relative).to_string());
            }
        }
    }
    Ok(outcome)
}

fn read_existing(target: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(target) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("read {}: {error}", target.display())),
    }
}

fn write_template(target: &Path, contents: &str) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent", target.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {}: {error}", parent.display()))?;
    std::fs::write(target, contents).map_err(|error| format!("write {}: {error}", target.display()))
}

#[cfg(test)]
#[path = "rules/tests.rs"]
mod tests;
