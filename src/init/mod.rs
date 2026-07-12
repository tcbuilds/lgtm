//! `lgtm init` command: scaffold repo-local config and merge Claude Code hooks.
//!
//! Detects target-repo characteristics (languages, available commands, git
//! presence) in a given root directory, writes `.lgtm/config.json`, ensures
//! `.lgtm/evidence/` exists and is gitignored, and merges the five lifecycle
//! hook entries into `.claude/settings.json` without clobbering existing
//! settings. Every operation is idempotent: re-running init must not duplicate
//! config, gitignore lines, or hook entries, and must never discard a
//! user-edited `.lgtm/config.json`.
//!
//! Detection and merge logic are pure functions over owned inputs so they can
//! be exercised directly in tests; filesystem effects live at the boundary in
//! [`run`]. All validation (settings and existing config) happens before any
//! write, so a rejected input leaves the repo untouched.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::detect::{Detection, detect};
use crate::discovery::{DiscoveryError, Workspace};
use crate::fsutil::open_regular_file;

mod config;
mod fs;
mod gitignore;
mod runner;
mod settings;

use config::{ValidatedSettings, render_config, validate_config, validate_settings};
use fs::{commit_write, create_dir_all, preflight_targets, read_if_exists, stage_write};
#[cfg(test)]
use gitignore::evidence_is_ignored;
use gitignore::{render_gitignore, render_settings};
pub use runner::{migrate_config, preview, run, run_with_options};
pub use settings::{build_config, merge_settings};
#[cfg(test)]
use settings::{commands_match, entry_runs_command};

#[cfg(test)]
mod tests;

/// The single line appended to `.gitignore` to exclude evidence records.
const EVIDENCE_GITIGNORE_LINE: &str = ".lgtm/evidence/";

/// The maximum size init will read from an existing config, settings, or
/// `.gitignore` file. These are small hand- or tool-authored text files; capping
/// the read protects init from an unbounded or hostile repo-controlled file that
/// would otherwise be buffered whole. Anything past the cap is rejected as a
/// non-retryable [`InitError::FileTooLarge`] rather than silently truncated, so a
/// planted oversized file surfaces to the operator instead of corrupting a merge.
const MAX_READ_BYTES: u64 = 256 * 1024;

/// The five Claude Code lifecycle events wired by init, paired with the hook
/// subcommand each invokes.
///
/// Commands are the bare `lgtm ...` form and assume `lgtm` is reachable on the
/// `PATH` of the shell Claude Code spawns hooks in. `lgtm doctor` is
/// responsible for verifying that reachability; init only writes the wiring.
const HOOK_EVENTS: [HookWiring; 5] = [
    HookWiring {
        event: "SessionStart",
        command: "lgtm hook session-start",
        matcher: None,
    },
    HookWiring {
        event: "UserPromptSubmit",
        command: "lgtm hook user-prompt-submit",
        matcher: None,
    },
    HookWiring {
        event: "PreToolUse",
        command: "lgtm hook pre-tool-use",
        matcher: Some("Edit|Write"),
    },
    HookWiring {
        event: "PostToolUse",
        command: "lgtm hook post-tool-use",
        matcher: Some("Edit|Write"),
    },
    HookWiring {
        event: "Stop",
        command: "lgtm hook stop",
        matcher: None,
    },
];

/// Static description of one lifecycle hook entry to be merged.
struct HookWiring {
    /// Claude Code settings key, e.g. `PreToolUse`.
    event: &'static str,
    /// The command an entry runs, e.g. `lgtm hook pre-tool-use`.
    command: &'static str,
    /// Optional tool matcher; `None` means the entry omits the `matcher` key.
    matcher: Option<&'static str>,
}

/// Failure modes of `lgtm init`.
///
/// Each variant carries enough context to emit an actionable, single-line
/// operator message following the standard
/// `action failed: entity=<id> reason=<cause> retryable=<bool>` shape.
/// Filesystem errors name the path that failed; a malformed existing settings
/// or config file is reported without being overwritten.
#[derive(Debug, Error)]
pub enum InitError {
    /// Workspace discovery could not safely inspect the repository.
    #[error("workspace discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    /// Discovery produced fallback commands that require explicit acceptance.
    #[error(
        "low-confidence commands detected; rerun with --accept-guesses or inspect `lgtm init --dry-run`: {details}"
    )]
    LowConfidence { details: String },
    /// Creating a directory under the target repo failed.
    #[error("create directory failed: path={path} reason={source} retryable=true")]
    CreateDir {
        /// The directory that could not be created.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Reading an existing file failed for a reason other than absence.
    #[error("read failed: path={path} reason={source} retryable=true")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// An existing file init must read (config, settings, or `.gitignore`)
    /// exceeds [`MAX_READ_BYTES`]. Init refuses to buffer an unbounded
    /// repo-controlled file, so an implausibly large file is rejected rather than
    /// read whole. Non-retryable: the file must be shrunk before init can proceed.
    #[error("file exceeds maximum size: path={path} max_bytes={max_bytes} retryable=false")]
    FileTooLarge {
        /// The file whose size exceeds the cap.
        path: PathBuf,
        /// The byte cap the file exceeded.
        max_bytes: u64,
    },
    /// Writing a file failed.
    #[error("write failed: path={path} reason={source} retryable=true")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// An existing `.claude/settings.json` is not valid JSON; init refuses to
    /// overwrite it so hand-authored settings are never lost.
    #[error("existing settings are malformed: path={path} reason={reason} retryable=false")]
    MalformedSettings {
        /// The settings file that could not be parsed.
        path: PathBuf,
        /// The parse error describing why it is invalid.
        reason: String,
    },
    /// An existing `.claude/settings.json` is valid JSON but not a JSON object,
    /// so hook entries cannot be merged into it.
    #[error("existing settings are not a JSON object: path={path} retryable=false")]
    SettingsNotObject {
        /// The settings file whose root is not an object.
        path: PathBuf,
    },
    /// An existing `.claude/settings.json` has a `hooks` key whose value is not
    /// a JSON object, so hook entries cannot be merged without discarding it.
    #[error("existing settings have a non-object hooks value: path={path} retryable=false")]
    SettingsHooksNotObject {
        /// The settings file whose `hooks` value is not an object.
        path: PathBuf,
    },
    /// An event entry under `hooks` is not a JSON array, so a hook cannot be
    /// appended to it without discarding the existing value.
    #[error(
        "existing settings have a non-array hooks event: path={path} event={event} retryable=false"
    )]
    SettingsEventNotArray {
        /// The settings file with the malformed event.
        path: PathBuf,
        /// The event key whose value is not an array.
        event: String,
    },
    /// An existing `.lgtm/config.json` is not valid JSON; init refuses to
    /// overwrite it so user-edited policy is never lost.
    #[error("existing config is malformed: path={path} reason={reason} retryable=false")]
    MalformedConfig {
        /// The config file that could not be parsed.
        path: PathBuf,
        /// The parse error describing why it is invalid.
        reason: String,
    },
    /// An existing `.lgtm/config.json` is valid JSON but not a JSON object.
    #[error("existing config is not a JSON object: path={path} retryable=false")]
    ConfigNotObject {
        /// The config file whose root is not an object.
        path: PathBuf,
    },
    /// An existing `.lgtm/config.json` has a field whose JSON type is wrong for
    /// preservation (e.g. `languages` that is not an array), so re-init refuses
    /// rather than silently overwriting hand-edited policy.
    #[error("existing config field has the wrong type: path={path} field={field} retryable=false")]
    ConfigFieldWrongType {
        /// The config file with the mistyped field.
        path: PathBuf,
        /// The field whose JSON type is wrong.
        field: String,
    },
    /// A destination path that must be written is a symlink; init refuses to
    /// follow it so a write can never land outside the repo.
    #[error("refusing to write through a symlink: path={path} retryable=false")]
    SymlinkTarget {
        /// The symlinked path init declined to write.
        path: PathBuf,
    },
    /// A destination path or a required parent already exists as the wrong file
    /// type (e.g. a parent that must be a directory is a regular file), so init
    /// refuses before writing anything.
    #[error("destination path is not writable: path={path} reason={reason} retryable=false")]
    UnwritableTarget {
        /// The path whose existing type blocks the write.
        path: PathBuf,
        /// Why the path cannot be written.
        reason: String,
    },
}

/// Outcome of a completed init, summarizing what was detected and written so the
/// CLI can print a concise report without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitSummary {
    /// What init detected about the target repo.
    pub detection: Detection,
    /// Nested workspaces discovered without executing repository commands.
    pub workspaces: Vec<Workspace>,
    /// Repo-relative paths init created or modified, in write order.
    pub files_written: Vec<String>,
    /// Extra human-readable notes for stdout, e.g. preserved config or skipped
    /// gitignore append. Empty when nothing noteworthy happened.
    pub notes: Vec<String>,
}
