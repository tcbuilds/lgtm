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

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::fs::{
    commit_write, create_dir_all, preflight_file_targets, preflight_targets, read_if_exists,
    stage_write,
};
use super::template_digests::LEGACY_TEMPLATE_DIGESTS;
use super::{InitAgent, InitError};

const PREFIX: &str = ".claude/rules";

/// Exact marker written into the shipped entry document and required by the
/// native Claude hook before it suppresses fallback guidance.
pub const ENTRY_DOCUMENT_MARKER: &str = "<!-- lgtm-entry-document: standards-v1 -->";

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
        "anti-slop.md",
        include_str!("../../templates/claude-rules/rules/anti-slop.md"),
    ),
    (
        "code-organization.md",
        include_str!("../../templates/claude-rules/rules/code-organization.md"),
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
        "error-handling.md",
        include_str!("../../templates/claude-rules/rules/error-handling.md"),
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
        "naming.md",
        include_str!("../../templates/claude-rules/rules/naming.md"),
    ),
    (
        "observability.md",
        include_str!("../../templates/claude-rules/rules/observability.md"),
    ),
    (
        "performance.md",
        include_str!("../../templates/claude-rules/rules/performance.md"),
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
        "security.md",
        include_str!("../../templates/claude-rules/rules/security.md"),
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

/// Compact always-loaded guidance shared by non-Claude global harnesses.
pub(super) fn entry_document() -> String {
    strip_frontmatter(TEMPLATES[0].1).trim().to_string()
}

/// Outcome of a rules-only installation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installed {
    pub written: Vec<String>,
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    pub kept: Vec<String>,
}

/// One rule document that is ready to enter init's staged-write batch.
pub(super) struct PlannedRuleWrite {
    pub(super) path: PathBuf,
    pub(super) label: String,
    pub(super) contents: Vec<u8>,
}

/// Return every guidance destination for an agent, including locally edited files.
pub(super) fn target_paths(root: &Path, agent: InitAgent) -> Vec<PathBuf> {
    match agent {
        InitAgent::Claude => TEMPLATES
            .iter()
            .map(|(relative, _)| root.join(PREFIX).join(relative))
            .collect(),
        InitAgent::Codex => vec![root.join(AGENTS_FILE)],
    }
}

/// Plan missing guidance files without changing the repository.
pub(super) fn plan(
    root: &Path,
    agent: InitAgent,
) -> Result<(Vec<PlannedRuleWrite>, Installed), InitError> {
    let mut planned = Vec::new();
    let mut outcome = Installed::default();
    match agent {
        InitAgent::Claude => {
            for (relative, contents) in TEMPLATES {
                let target = root.join(PREFIX).join(relative);
                plan_one(
                    &target,
                    (*relative).to_string(),
                    contents.as_bytes(),
                    &mut planned,
                    &mut outcome,
                )?;
            }
        }
        InitAgent::Codex => {
            let document = agents_document();
            let target = root.join(AGENTS_FILE);
            plan_one(
                &target,
                AGENTS_FILE.to_string(),
                document.as_bytes(),
                &mut planned,
                &mut outcome,
            )?;
        }
    }
    Ok((planned, outcome))
}

/// Classify one destination and add it to the staged batch when it is new or stale.
fn plan_one(
    target: &Path,
    label: String,
    contents: &[u8],
    planned: &mut Vec<PlannedRuleWrite>,
    outcome: &mut Installed,
) -> Result<(), InitError> {
    match read_if_exists(target)? {
        Some(existing) if existing.as_bytes() == contents => outcome.unchanged.push(label),
        Some(existing) if same_template_line_endings(existing.as_bytes(), contents) => {
            outcome.unchanged.push(label);
        }
        Some(existing) if matches_legacy_template(&label, existing.as_bytes()) => {
            planned.push(PlannedRuleWrite {
                path: target.to_path_buf(),
                label: label.clone(),
                contents: contents.to_vec(),
            });
            outcome.updated.push(label);
        }
        Some(_) => outcome.kept.push(label),
        None => {
            planned.push(PlannedRuleWrite {
                path: target.to_path_buf(),
                label: label.clone(),
                contents: contents.to_vec(),
            });
            outcome.written.push(label);
        }
    }
    Ok(())
}

fn same_template_line_endings(left: &[u8], right: &[u8]) -> bool {
    normalized_template_digest(left) == normalized_template_digest(right)
}

/// Recognize only bytes previously emitted for this exact generated path.
fn matches_legacy_template(path: &str, contents: &[u8]) -> bool {
    let mut candidates = LEGACY_TEMPLATE_DIGESTS
        .iter()
        .filter(|record| record.path == path);
    if candidates.clone().next().is_none() {
        return false;
    }
    let digest = normalized_template_digest(contents);
    candidates.any(|record| record.sha256 == format!("{digest:x}"))
}

fn normalized_template_digest(contents: &[u8]) -> Sha256Digest {
    let mut normalized = Vec::with_capacity(contents.len());
    let mut index = 0;
    while index < contents.len() {
        if contents[index] == b'\r' && contents.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        normalized.push(contents[index]);
        index += 1;
    }
    Sha256::digest(normalized)
}

type Sha256Digest = sha2::digest::Output<Sha256>;

/// Describe the files a fresh Claude rules installation would write.
pub fn planned() -> Installed {
    Installed {
        written: TEMPLATES
            .iter()
            .map(|(relative, _)| (*relative).to_string())
            .collect(),
        updated: Vec::new(),
        unchanged: Vec::new(),
        kept: Vec::new(),
    }
}

/// Describe the file a fresh Codex guidance installation would write.
pub fn planned_agents_md() -> Installed {
    Installed {
        written: vec![AGENTS_FILE.to_string()],
        updated: Vec::new(),
        unchanged: Vec::new(),
        kept: Vec::new(),
    }
}

/// Write the templates under `.claude/rules`, preserving edited files.
///
/// A file whose contents already match the template is reported as unchanged. A
/// file that differs is left alone and reported as kept, so local edits survive
/// re-running the command.
pub fn install(root: &Path) -> Result<Installed, String> {
    install_transaction(root, InitAgent::Claude).map_err(|error| error.to_string())
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
    install_transaction(root, InitAgent::Codex).map_err(|error| error.to_string())
}

/// Apply guidance files only after every destination has passed preflight.
fn install_transaction(root: &Path, agent: InitAgent) -> Result<Installed, InitError> {
    let targets = target_paths(root, agent);
    let target_refs: Vec<&Path> = targets.iter().map(PathBuf::as_path).collect();
    preflight_targets(root, &target_refs)?;
    preflight_file_targets(&target_refs)?;
    let (planned, outcome) = plan(root, agent)?;

    for write in &planned {
        if let Some(parent) = write.path.parent() {
            create_dir_all(parent)?;
        }
    }

    let mut staged = Vec::new();
    for write in &planned {
        staged.push((
            stage_write(&write.path, &write.contents)?,
            write.label.as_str(),
        ));
    }
    for (handle, _) in staged {
        commit_write(handle)?;
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
    crate::policy::frontmatter::body(contents)
        .map(|body| body.trim_start_matches(['\n', '\r']))
        .unwrap_or(contents)
}

#[cfg(test)]
#[path = "rules/tests.rs"]
mod tests;
