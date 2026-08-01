//! Binary-free rules mode.
//!
//! Writes the standards templates into `.claude/rules/` without registering any
//! hooks. Everything lands under that directory so an existing `CLAUDE.md` is
//! never touched; the entry document carries no `paths:` frontmatter, which
//! Claude Code loads every session.
//!
//! Codex has no path-scoped rule mechanism and does not read `.claude/rules/`,
//! so it gets [`install_agents_md`] instead: every template concatenated into a
//! single `AGENTS.md`. That trades away lazy loading — the whole document enters
//! every session — which the CLI states plainly rather than hiding.

use std::path::Path;

const PREFIX: &str = ".claude/rules";

/// The single file Codex reads for repository guidance.
const AGENTS_FILE: &str = "AGENTS.md";

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

/// Write every template concatenated into `AGENTS.md`, preserving an edited file.
///
/// Codex loads one repository document and has no `paths:` mechanism, so the
/// standards cannot be lazily scoped the way `.claude/rules/` scopes them for
/// Claude Code. The entry document leads and the path-scoped templates follow in
/// [`TEMPLATES`] order. Per-template `paths:` frontmatter is stripped, because it
/// is Claude-specific metadata that would both render as stray YAML and imply a
/// lazy-loading behavior this file does not have.
///
/// An existing `AGENTS.md` is never overwritten: it is reported as kept, exactly
/// as [`install`] treats an edited rules file.
pub fn install_agents_md(root: &Path) -> Result<Installed, String> {
    let mut outcome = Installed::default();
    let target = root.join(AGENTS_FILE);
    let document = agents_document();
    match read_existing(&target)? {
        Some(existing) if existing == document => outcome.unchanged.push(AGENTS_FILE.to_string()),
        Some(_) => outcome.kept.push(AGENTS_FILE.to_string()),
        None => {
            write_template(&target, &document)?;
            outcome.written.push(AGENTS_FILE.to_string());
        }
    }
    Ok(outcome)
}

/// Number of lines in the rendered `AGENTS.md`, so the CLI can state the cost of
/// inlining every standard without re-deriving it.
pub fn agents_document_lines() -> usize {
    agents_document().lines().count()
}

/// Preamble correcting the entry document's Claude-specific loading claim.
///
/// The entry template tells the reader that language rules live in
/// `.claude/rules/` and load on demand. That is true for Claude Code and false
/// here, so the concatenated document opens by saying what it actually is
/// instead of leaving a reader to trust a lazy-loading promise nothing keeps.
const AGENTS_PREAMBLE: &str = "<!-- Generated by `lgtm init --rules-only --agent codex`. -->\n\nEvery standard below is inlined because this agent has no path-scoped rule\nloading. Sections that name `.claude/rules/` describe the Claude Code layout,\nnot this file: here the rules are already present and always in context. Apply\nthe section matching the file you are editing.\n";

/// Concatenate every template into the single Codex guidance document.
fn agents_document() -> String {
    let mut document = AGENTS_PREAMBLE.to_string();
    for (_, contents) in TEMPLATES {
        document.push_str("\n---\n\n");
        document.push_str(strip_frontmatter(contents).trim_end());
        document.push('\n');
    }
    document
}

/// Remove a leading `---`-delimited YAML frontmatter block, if present.
///
/// Returns the input unchanged when it does not open with a frontmatter block or
/// when the block is unterminated, so a malformed template degrades to being
/// included verbatim rather than being silently truncated.
fn strip_frontmatter(contents: &str) -> &str {
    let Some(rest) = contents.strip_prefix("---\n") else {
        return contents;
    };
    match rest.split_once("\n---\n") {
        Some((_, body)) => body.trim_start_matches('\n'),
        None => contents,
    }
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
