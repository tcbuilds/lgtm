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
use crate::fsutil::open_regular_file;

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
    /// Repo-relative paths init created or modified, in write order.
    pub files_written: Vec<String>,
    /// Extra human-readable notes for stdout, e.g. preserved config or skipped
    /// gitignore append. Empty when nothing noteworthy happened.
    pub notes: Vec<String>,
}

/// Build the `.lgtm/config.json` document for a detection result.
///
/// Produces the repository-local policy shape: `profile` defaults to `default`,
/// `disabled_rules` and `severity_overrides` start empty, and
/// `required_commands` carries the detected per-language check commands.
pub fn build_config(detection: &Detection) -> Value {
    let mut required = Map::new();
    for (language, commands) in &detection.required_commands {
        required.insert(language.clone(), json!(commands));
    }
    json!({
        "profile": "default",
        "languages": detection.languages,
        "disabled_rules": [],
        "severity_overrides": {},
        "required_commands": required,
    })
}

/// Merge the five lgtm hook entries into an existing settings object.
///
/// `existing` is the parsed settings object (an empty object for a fresh repo).
/// Existing hooks and unrelated top-level settings are preserved; lgtm entries
/// are appended only when a matching entry is not already present for that
/// event, making repeated merges idempotent. A pre-existing lgtm entry whose
/// matcher no longer matches the expected wiring is corrected in place rather
/// than skipped or duplicated. Returns the merged object.
///
/// Callers must have validated the shape of `existing` (via
/// [`validate_settings`]) before calling: a non-object `hooks` value or a
/// non-array event value is treated as empty here, but the boundary rejects
/// those inputs before any write so a malformed file is never silently
/// replaced.
pub fn merge_settings(existing: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = existing.clone();

    let hooks_entry = merged
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(hooks) = hooks_entry else {
        let mut replacement = Map::new();
        insert_hook_events(&mut replacement);
        merged.insert("hooks".to_string(), Value::Object(replacement));
        return merged;
    };

    insert_hook_events(hooks);
    merged
}

/// Add each lgtm hook entry to the hooks map, reconciling any existing lgtm
/// entry for the same event: if one is found with the wrong matcher, its matcher
/// is corrected; if found and already correct, it is left exactly as authored
/// (preserving a path-qualified command); if absent, the entry is appended.
fn insert_hook_events(hooks: &mut Map<String, Value>) {
    for wiring in &HOOK_EVENTS {
        let entries = hooks
            .entry(wiring.event.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let Value::Array(entries) = entries else {
            continue;
        };
        match entries
            .iter_mut()
            .find(|entry| entry_runs_command(entry, wiring.command))
        {
            Some(existing_entry) => reconcile_matcher(existing_entry, wiring),
            None => entries.push(hook_entry(wiring)),
        }
    }
}

/// Correct an existing lgtm hook entry's matcher to the wiring's expected value
/// without disturbing anything else about it.
///
/// The entry's command (which may be a path-qualified binary) and nested hook
/// objects are left untouched; only the top-level `matcher` key is reconciled.
/// For a wiring that expects a matcher, the key is set when missing or wrong;
/// for a wiring with no matcher, a stray `matcher` key is removed. This keeps
/// re-init from clobbering a hand-adjusted command while still enforcing the
/// tool matcher the runtime depends on.
fn reconcile_matcher(entry: &mut Value, wiring: &HookWiring) {
    let Value::Object(object) = entry else {
        return;
    };
    match wiring.matcher {
        Some(matcher) => {
            let expected = Value::String(matcher.to_string());
            if object.get("matcher") != Some(&expected) {
                object.insert("matcher".to_string(), expected);
            }
        }
        None => {
            object.remove("matcher");
        }
    }
}

/// Build a single Claude Code hook entry for a wiring.
fn hook_entry(wiring: &HookWiring) -> Value {
    let inner = json!({
        "type": "command",
        "command": wiring.command,
    });
    match wiring.matcher {
        Some(matcher) => json!({ "matcher": matcher, "hooks": [inner] }),
        None => json!({ "hooks": [inner] }),
    }
}

/// True when a hook entry contains a nested command that runs `command`.
///
/// Inspects the entry's `hooks` array for a `command`-typed object whose
/// `command` invokes the wiring's subcommand, which is how Claude Code nests the
/// executable under each event entry. A hook whose `type` is not `command` is
/// ignored even if its `command` string matches, so a non-command hook that
/// happens to carry the same string never suppresses adding the required
/// executable hook. Matching tolerates a path-qualified binary: an existing
/// command such as `/usr/local/bin/lgtm hook stop` is recognized as the same
/// lgtm hook as the bare `lgtm hook stop` wiring.
fn entry_runs_command(entry: &Value, command: &str) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|inner| {
            inner.iter().any(|hook| {
                hook.get("type").and_then(Value::as_str) == Some("command")
                    && hook
                        .get("command")
                        .and_then(Value::as_str)
                        .is_some_and(|found| commands_match(found, command))
            })
        })
}

/// True when `found` is the same lgtm hook invocation as the expected wiring
/// `command`, tolerating a path-qualified binary.
///
/// The expected form is `lgtm <args>`; a found command matches when it is
/// exactly that, or when it ends with `/<expected>` (a path-qualified binary
/// such as `./bin/lgtm <args>` or `/usr/bin/lgtm <args>`).
fn commands_match(found: &str, expected: &str) -> bool {
    if found == expected {
        return true;
    }
    let Some(suffix) = expected.strip_prefix("lgtm ") else {
        return false;
    };
    found.rsplit_once("lgtm ").is_some_and(|(prefix, rest)| {
        rest == suffix && (prefix.is_empty() || prefix.ends_with('/'))
    })
}

/// Run `lgtm init` against `root`, performing all filesystem effects.
///
/// Creates `.lgtm/` and `.lgtm/evidence/`, writes `.lgtm/config.json` (only when
/// absent — an existing valid config is preserved), appends the evidence path to
/// `.gitignore` (creating it if absent), and merges hook entries into
/// `.claude/settings.json`. Returns a summary of what was written.
///
/// All validation runs before any write: an existing malformed or non-object
/// `.claude/settings.json` (including a malformed `hooks` shape) or an existing
/// malformed `.lgtm/config.json` causes init to refuse, leaving every file
/// untouched.
///
/// Writes use a staged-commit strategy: every output is rendered in memory
/// first, then each changed output is written to a sibling temp file (which
/// proves its destination directory is writable), and only when every temp
/// write has succeeded are the temp files renamed over their targets. A failure
/// during staging removes any temp files already written and leaves every target
/// untouched. This narrows the partial-write window to the sequence of renames
/// at the very end: a rename can still fail mid-batch (e.g. the filesystem
/// disappears), but by then writability of every destination has already been
/// proven, so a partial commit is limited to the rename step rather than being
/// possible at any earlier write.
pub fn run(root: &Path) -> Result<InitSummary, InitError> {
    let detection = detect(root);

    let settings_path = root.join(".claude").join("settings.json");
    let validated_settings = validate_settings(&settings_path)?;

    let config_path = root.join(".lgtm").join("config.json");
    let existing_config = validate_config(&config_path)?;
    let existing_config_contents = existing_config
        .as_ref()
        .map(|(_, contents)| contents.clone())
        .unwrap_or_default();
    let existing_config = existing_config.map(|(object, _)| object);

    let evidence_dir = root.join(".lgtm").join("evidence");
    let gitignore_path = root.join(".gitignore");
    preflight_targets(&[&evidence_dir, &config_path, &gitignore_path, &settings_path])?;

    let mut files_written = Vec::new();
    let mut notes = Vec::new();

    if detection.languages.is_empty() {
        notes.push("no MVP-supported languages detected (python only in MVP)".to_string());
    }

    let config_render = render_config(
        &detection,
        existing_config,
        &existing_config_contents,
        &mut notes,
    );
    let gitignore_render = render_gitignore(&gitignore_path, &mut notes)?;
    let settings_render = render_settings(validated_settings);

    create_dir_all(&evidence_dir)?;
    if let Some(parent) = settings_path.parent() {
        create_dir_all(parent)?;
    }

    let planned = [
        (&config_path, ".lgtm/config.json", config_render),
        (&gitignore_path, ".gitignore", gitignore_render),
        (&settings_path, ".claude/settings.json", settings_render),
    ];

    let mut staged = Vec::new();
    for (path, label, render) in planned {
        let Some(bytes) = render else {
            continue;
        };
        match stage_write(path, &bytes) {
            Ok(handle) => staged.push((handle, label.to_string())),
            Err(error) => {
                return Err(error);
            }
        }
    }

    for (handle, label) in staged {
        commit_write(handle)?;
        files_written.push(label);
    }

    Ok(InitSummary {
        detection,
        files_written,
        notes,
    })
}

/// The validated, parsed `.claude/settings.json` object, or `None` when the file
/// is absent or empty (treated as a fresh object).
type ValidatedSettings = Option<Map<String, Value>>;

/// Read and validate `.claude/settings.json` without writing anything.
///
/// Returns `Ok(None)` when the file is absent or blank, `Ok(Some(object))` when
/// it parses to a well-shaped settings object, and an error when it is
/// malformed, not an object, or carries a `hooks` value whose shape would be
/// discarded by a merge (non-object `hooks`, or a non-array event value).
fn validate_settings(path: &Path) -> Result<ValidatedSettings, InitError> {
    let contents = match read_if_exists(path)? {
        None => return Ok(None),
        Some(contents) if contents.trim().is_empty() => return Ok(None),
        Some(contents) => contents,
    };

    let value: Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedSettings {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;

    let Value::Object(object) = value else {
        return Err(InitError::SettingsNotObject {
            path: path.to_path_buf(),
        });
    };

    if let Some(hooks) = object.get("hooks") {
        let Value::Object(hooks) = hooks else {
            return Err(InitError::SettingsHooksNotObject {
                path: path.to_path_buf(),
            });
        };
        for (event, entries) in hooks {
            if !entries.is_array() {
                return Err(InitError::SettingsEventNotArray {
                    path: path.to_path_buf(),
                    event: event.clone(),
                });
            }
        }
    }

    Ok(Some(object))
}

/// The validated, parsed `.lgtm/config.json` object paired with the exact bytes
/// read from disk, or `None` when the file is absent or blank. The raw bytes are
/// threaded to [`render_config`] for its skip-if-identical comparison so the file
/// is never re-read after validation.
type ValidatedConfig = Option<(Map<String, Value>, String)>;

/// Read and validate an existing `.lgtm/config.json` without writing anything.
///
/// Returns `Ok(None)` when the file is absent or blank, `Ok(Some((object,
/// contents)))` when it parses to a well-typed JSON object (a user-edited config
/// to preserve) paired with the exact bytes read from disk, and an error when it
/// is malformed, not an object, or carries a preserved field whose JSON type is
/// wrong. The raw contents are returned so [`render_config`] can perform its
/// skip-if-identical comparison against the bytes validated here rather than
/// re-reading the file, which both avoids a second unbounded read and closes the
/// swap-between-validate-and-render race. The type check exists because
/// [`merge_config`] preserves fields it does not overwrite: a preserved field
/// whose type is wrong would otherwise be silently discarded and overwritten,
/// violating preservation. Every preserved field is checked to the depth the
/// runtime relies on: `profile` must be a string, `languages` an array of
/// strings, `disabled_rules`
/// an array of strings, `severity_overrides` an object of string values, and
/// `required_commands` an object whose every value is an array of strings.
/// Refusing here keeps that consistent with the malformed-config handling above.
fn validate_config(path: &Path) -> Result<ValidatedConfig, InitError> {
    let contents = match read_if_exists(path)? {
        None => return Ok(None),
        Some(contents) if contents.trim().is_empty() => return Ok(None),
        Some(contents) => contents,
    };

    let value: Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedConfig {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;

    let Value::Object(object) = value else {
        return Err(InitError::ConfigNotObject {
            path: path.to_path_buf(),
        });
    };

    if let Some(profile) = object.get("profile")
        && !profile.is_string()
    {
        return Err(InitError::ConfigFieldWrongType {
            path: path.to_path_buf(),
            field: "profile".to_string(),
        });
    }
    if let Some(languages) = object.get("languages")
        && !is_string_array(languages)
    {
        return Err(InitError::ConfigFieldWrongType {
            path: path.to_path_buf(),
            field: "languages".to_string(),
        });
    }
    if let Some(disabled) = object.get("disabled_rules")
        && !is_string_array(disabled)
    {
        return Err(InitError::ConfigFieldWrongType {
            path: path.to_path_buf(),
            field: "disabled_rules".to_string(),
        });
    }
    if let Some(overrides) = object.get("severity_overrides")
        && !is_string_valued_object(overrides)
    {
        return Err(InitError::ConfigFieldWrongType {
            path: path.to_path_buf(),
            field: "severity_overrides".to_string(),
        });
    }
    if let Some(required) = object.get("required_commands") {
        let Value::Object(commands) = required else {
            return Err(InitError::ConfigFieldWrongType {
                path: path.to_path_buf(),
                field: "required_commands".to_string(),
            });
        };
        if !commands.values().all(is_string_array) {
            return Err(InitError::ConfigFieldWrongType {
                path: path.to_path_buf(),
                field: "required_commands".to_string(),
            });
        }
    }

    Ok(Some((object, contents)))
}

/// True when `value` is a JSON array whose every element is a string.
///
/// Used to validate preserved `disabled_rules` and each `required_commands`
/// entry, both of which [`merge_config`] carries forward verbatim and therefore
/// must be well-typed to avoid silently preserving a nonsense value.
fn is_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

/// True when `value` is a JSON object whose every value is a string.
///
/// Used to validate a preserved `severity_overrides` map, which maps rule ids to
/// string severities; a non-object map or a non-string severity is a
/// preservation hazard and is refused.
fn is_string_valued_object(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.values().all(Value::is_string))
}

/// Render the desired `.lgtm/config.json` bytes, preserving any existing
/// user-edited config, or `None` when the file is already up to date.
///
/// On a fresh repo (`existing_config` is `None`) the detected config is
/// produced. When a valid config already exists it is preserved verbatim:
/// user-edited `disabled_rules` and `severity_overrides` are never overwritten.
/// Newly detected languages and their commands are merged only into fields that
/// are still empty in the existing config, so re-init can enrich a bare config
/// without clobbering deliberate edits. Returns `None` when the serialized
/// contents already match `existing_contents` (the exact bytes
/// [`validate_config`] read from disk) so no write is staged; reusing those
/// already-validated bytes avoids a second unbounded read and closes the
/// swap-between-validate-and-render race.
fn render_config(
    detection: &Detection,
    existing_config: Option<Map<String, Value>>,
    existing_contents: &str,
    notes: &mut Vec<String>,
) -> Option<Vec<u8>> {
    let desired = match existing_config {
        None => build_config(detection),
        Some(existing) => {
            notes.push("preserved existing .lgtm/config.json".to_string());
            Value::Object(merge_config(existing, detection))
        }
    };

    let mut serialized = serde_json::to_string_pretty(&desired)
        .expect("config value is a plain JSON object and always serializes");
    serialized.push('\n');

    if existing_contents == serialized {
        return None;
    }

    Some(serialized.into_bytes())
}

/// Merge newly detected languages and commands into an existing config object,
/// filling only empty fields.
///
/// User-set keys are preserved. `languages` is populated from detection only
/// when the existing list is missing or empty; each detected language's commands
/// are added under `required_commands` only when that language has no entry yet.
/// Everything else in the existing object is left exactly as authored.
fn merge_config(mut existing: Map<String, Value>, detection: &Detection) -> Map<String, Value> {
    let languages_empty = existing
        .get("languages")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    if languages_empty {
        existing.insert("languages".to_string(), json!(detection.languages));
    }

    let required = existing
        .entry("required_commands".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(required) = required {
        for (language, commands) in &detection.required_commands {
            if !required.contains_key(language) {
                required.insert(language.clone(), json!(commands));
            }
        }
    }

    existing
}

/// Render the `.gitignore` bytes needed to exclude the evidence directory, or
/// `None` when the file already ignores it and no write is required.
///
/// Produces a freshly created file when absent; otherwise appends the evidence
/// line only when the evidence directory is not already ignored, so repeated
/// runs never duplicate it. Ignore status is evaluated with gitignore's
/// last-matching-rule semantics: a wholesale `.lgtm/` rule that is later negated
/// for the evidence path (e.g. `!.lgtm/evidence/`) leaves evidence tracked, so
/// init still appends the explicit rule; only when the final effect is "ignored"
/// is the append skipped, with a note that `.lgtm/config.json` may be untracked.
/// A CRLF-terminated file keeps its CRLF style on append.
fn render_gitignore(path: &Path, notes: &mut Vec<String>) -> Result<Option<Vec<u8>>, InitError> {
    let existing = read_if_exists(path)?;

    match existing {
        Some(contents) if evidence_is_ignored(&contents) => {
            if !gitignore_has_explicit_evidence_rule(&contents) {
                notes.push(
                    ".gitignore ignores .lgtm/ wholesale; .lgtm/config.json will be untracked"
                        .to_string(),
                );
            }
            Ok(None)
        }
        Some(contents) => {
            let newline = if contents.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let mut updated = contents;
            if !updated.is_empty() && !updated.ends_with('\n') {
                updated.push_str(newline);
            }
            updated.push_str(EVIDENCE_GITIGNORE_LINE);
            updated.push_str(newline);
            Ok(Some(updated.into_bytes()))
        }
        None => {
            let contents = format!("{EVIDENCE_GITIGNORE_LINE}\n");
            Ok(Some(contents.into_bytes()))
        }
    }
}

/// True when `.lgtm/evidence/` is ignored after applying every matching rule in
/// order, honoring negation.
///
/// Evaluates the file with gitignore last-matching-rule semantics restricted to
/// the `.lgtm/evidence/` path: each line either ignores or (with a leading `!`)
/// re-includes the path, and the final matching rule wins. A wholesale `.lgtm/`
/// rule matches the evidence path, but a later `!.lgtm/evidence/` negation flips
/// the outcome back to "not ignored" — in which case init must still append its
/// explicit rule. Returns `false` when no rule matches the evidence path.
fn evidence_is_ignored(contents: &str) -> bool {
    let mut ignored = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (negated, pattern) = match trimmed.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, trimmed),
        };
        if gitignore_pattern_matches_evidence(pattern) {
            ignored = !negated;
        }
    }
    ignored
}

/// True when a gitignore pattern (already stripped of a leading `!`) matches the
/// `.lgtm/evidence/` path, either directly or via a wholesale `.lgtm/` rule.
///
/// Trailing slashes are tolerated so `.lgtm`, `.lgtm/`, `.lgtm/evidence`, and
/// `.lgtm/evidence/` are all recognized.
fn gitignore_pattern_matches_evidence(pattern: &str) -> bool {
    let normalized = pattern.trim_end_matches('/');
    normalized == ".lgtm" || normalized == ".lgtm/evidence"
}

/// True when the file carries an explicit, non-negated evidence rule (as opposed
/// to only matching via a wholesale `.lgtm/` rule), so the untracked-config note
/// is suppressed when the evidence directory is ignored by its own line.
fn gitignore_has_explicit_evidence_rule(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == EVIDENCE_GITIGNORE_LINE || trimmed == ".lgtm/evidence"
    })
}

/// Render the merged `.claude/settings.json` bytes from a pre-validated object,
/// or `None` when the merge leaves the settings unchanged.
///
/// `validated` is the result of [`validate_settings`]: `None` for a fresh repo,
/// or the parsed object when one already exists. Returns `None` when the merge
/// does not change the object, keeping repeated runs idempotent; the caller is
/// responsible for creating the parent `.claude/` directory before staging.
fn render_settings(validated: ValidatedSettings) -> Option<Vec<u8>> {
    let existing_object = validated.unwrap_or_default();
    let merged = merge_settings(&existing_object);
    if merged == existing_object {
        return None;
    }

    let mut serialized = serde_json::to_string_pretty(&Value::Object(merged))
        .expect("settings map serializes as a JSON object");
    serialized.push('\n');
    Some(serialized.into_bytes())
}

/// Read a file to a string, returning `None` when it does not exist and a typed
/// error for any other read failure.
///
/// The open is atomic: it refuses to follow a final-component symlink and does
/// not block on a FIFO (see [`open_regular_file`]), closing the TOCTOU window a
/// prior "stat then open" sequence left open. A path that exists but is not a
/// regular file (FIFO, device, socket, or symlink) is treated the same as
/// absence and reported as `None`, since init never needs to read one.
///
/// The read is bounded at [`MAX_READ_BYTES`]: a file larger than the cap is
/// rejected with a non-retryable [`InitError::FileTooLarge`] rather than buffered
/// whole, so an unbounded repo-controlled config, settings, or `.gitignore`
/// cannot force an arbitrarily large allocation.
fn read_if_exists(path: &Path) -> Result<Option<String>, InitError> {
    let file = match open_regular_file(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(source) => {
            return Err(InitError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mut contents = String::new();
    if let Err(source) = file.take(MAX_READ_BYTES + 1).read_to_string(&mut contents) {
        return Err(InitError::Read {
            path: path.to_path_buf(),
            source,
        });
    }
    if contents.len() as u64 > MAX_READ_BYTES {
        return Err(InitError::FileTooLarge {
            path: path.to_path_buf(),
            max_bytes: MAX_READ_BYTES,
        });
    }
    Ok(Some(contents))
}

/// Create a directory and all parents, mapping failure to a typed error.
fn create_dir_all(path: &Path) -> Result<(), InitError> {
    std::fs::create_dir_all(path).map_err(|source| InitError::CreateDir {
        path: path.to_path_buf(),
        source,
    })
}

/// Validate every destination path and its parents before any write occurs.
///
/// For each target this rejects: a target that already exists as a symlink (a
/// write would follow it out of the repo), and any existing ancestor along the
/// path that is not a directory (a required parent that is a regular file or a
/// symlink would make directory creation or the final write fail partway
/// through). Running this preflight before the first `create_dir_all` keeps a
/// later failure — e.g. an unwritable `.gitignore` — from leaving partial
/// scaffolding behind.
fn preflight_targets(paths: &[&Path]) -> Result<(), InitError> {
    for path in paths {
        if let Ok(metadata) = std::fs::symlink_metadata(path)
            && metadata.file_type().is_symlink()
        {
            return Err(InitError::SymlinkTarget {
                path: path.to_path_buf(),
            });
        }
        preflight_ancestors(path)?;
    }
    Ok(())
}

/// Reject any existing ancestor of `path` that is not a usable directory.
///
/// Walks each parent directory of `path` from the root down; the first ancestor
/// that exists but is not a directory (a regular file or a symlink) is a hard
/// error, because both directory creation under it and the eventual atomic write
/// would fail. Ancestors that do not yet exist are fine — they will be created.
fn preflight_ancestors(path: &Path) -> Result<(), InitError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    for ancestor in parent.ancestors() {
        let Ok(metadata) = std::fs::symlink_metadata(ancestor) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            return Err(InitError::SymlinkTarget {
                path: ancestor.to_path_buf(),
            });
        }
        if !metadata.is_dir() {
            return Err(InitError::UnwritableTarget {
                path: ancestor.to_path_buf(),
                reason: "parent path exists and is not a directory".to_string(),
            });
        }
    }
    Ok(())
}

/// Process-local counter feeding temp file name entropy so two writes in the
/// same process (or same nanosecond) never collide on a temp name.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temp file that has been written and fsynced but not yet renamed over its
/// target, forming the staging half of the two-phase staged-commit write.
///
/// Holding the handle proves the destination directory was writable (the temp
/// write succeeded there). [`commit_write`] renames it over `final_path`; the
/// [`Drop`] impl removes it when the batch is abandoned before commit.
///
/// The [`Drop`] impl removes the temp file unless the write was committed, so
/// any early return or failure mid-batch discards every still-staged temp
/// automatically — a leaked temp can never survive on disk carrying preserved,
/// restrictively-permissioned content. `commit_write` sets `committed` before
/// the rename so the successfully renamed file is not targeted by Drop.
struct StagedWrite {
    /// The final destination the temp file will be renamed over.
    final_path: PathBuf,
    /// The sibling temp file already written and fsynced.
    temp_path: PathBuf,
    /// Set once the temp has been renamed over its target, so [`Drop`] does not
    /// try to remove an already-committed (renamed-away) path.
    committed: bool,
}

impl Drop for StagedWrite {
    /// Remove any temp file that was staged but never committed, so an early
    /// return or a failed ritual in the batch never leaves a temp behind.
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

/// Stage a write for `path`: write its bytes to a uniquely named sibling temp
/// file and fsync it, without renaming over the target yet.
///
/// The temp file lives in the target's own directory so a later rename is a
/// same-filesystem atomic replace — a reader either sees the old file or the new
/// one, never a partially written file. The temp file is fsynced here so its
/// contents are durable before it replaces the target at commit time. A
/// successful stage also proves the destination directory is writable, which is
/// what lets the caller stage every output before committing any of them.
///
/// The temp name mixes the PID, nanoseconds since the epoch, and a
/// process-local counter so concurrent inits do not race on a shared, guessable
/// name, and the file is opened with `create_new(true)` so an attacker-planted
/// or leftover file of the same name causes a failure rather than a clobber or
/// symlink-followed write. Before staging, the final target is checked with
/// `symlink_metadata`: if it is a symlink, init refuses so a write can never be
/// redirected outside the repo.
///
/// On Unix the temp file is created with mode `0600` from the start, so
/// sensitive bytes are never world-readable even for the brief window between
/// the write and the mode fixup — a preserved `0600` `.claude/settings.json`
/// never leaves preserved content sitting in a default-`0644` temp. After the
/// content is fsynced the mode is relaxed to its final value: the target's own
/// bits when the target already exists (so a hardened `0600` file stays
/// `0600`), or `0644` for a brand-new project file that is not secret and
/// should be normally readable. The commit step reasserts the mode as a safety
/// net in case the target's mode changed between stage and commit.
fn stage_write(path: &Path, bytes: &[u8]) -> Result<StagedWrite, InitError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(InitError::SymlinkTarget {
            path: path.to_path_buf(),
        });
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "settings".to_string());
    let temp_path = dir.join(temp_file_name(&file_name));

    let write_result = (|| -> std::io::Result<()> {
        let mut options = std::fs::File::options();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(source) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(InitError::Write {
            path: temp_path,
            source,
        });
    }

    // The temp is created 0600 so sensitive bytes are never world-readable
    // during the write. Once the content is durable, relax to the final mode:
    // the target's own bits when it already exists (so a hardened 0600 file
    // stays 0600), or 0644 for a brand-new project file (config.json,
    // .gitignore) that is not secret and should be normally readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let final_permissions = match std::fs::metadata(path) {
            Ok(metadata) => metadata.permissions(),
            Err(_) => std::fs::Permissions::from_mode(0o644),
        };
        if let Err(source) = std::fs::set_permissions(&temp_path, final_permissions) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(InitError::Write {
                path: temp_path,
                source,
            });
        }
    }

    Ok(StagedWrite {
        final_path: path.to_path_buf(),
        temp_path,
        committed: false,
    })
}

/// Commit a staged write by renaming its temp file over the final target.
///
/// When the target already exists, its permission bits are copied onto the temp
/// file before the rename so the mode of an existing file (for example a
/// hand-hardened `0600` `.claude/settings.json`) survives the atomic replace
/// rather than being reset to the temp file's default mode. This is Unix-only;
/// on other platforms the rename simply replaces the file. On any failure the
/// staged temp is left for [`StagedWrite`]'s [`Drop`] to remove, so no staged
/// residue is left behind; on success `committed` is set before the rename so
/// Drop does not target the already-renamed path.
fn commit_write(mut staged: StagedWrite) -> Result<(), InitError> {
    #[cfg(unix)]
    {
        if let Ok(metadata) = std::fs::metadata(&staged.final_path) {
            let permissions = metadata.permissions();
            if let Err(source) = std::fs::set_permissions(&staged.temp_path, permissions) {
                return Err(InitError::Write {
                    path: staged.final_path.clone(),
                    source,
                });
            }
        }
    }

    staged.committed = true;
    std::fs::rename(&staged.temp_path, &staged.final_path).map_err(|source| {
        staged.committed = false;
        InitError::Write {
            path: staged.final_path.clone(),
            source,
        }
    })
}

/// Build a hard-to-guess, collision-resistant temp file name for a target file.
///
/// Combines the target name, PID, nanoseconds since the epoch, and a
/// process-local counter. Std-only entropy is sufficient here because the temp
/// file is opened with `create_new(true)`: uniqueness prevents accidental
/// collisions and the exclusive open closes the symlink-following race.
fn temp_file_name(file_name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{file_name}.tmp-{}-{nanos}-{counter}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_uses_default_profile_and_empty_overrides() {
        let detection = Detection {
            languages: vec!["python".to_string()],
            required_commands: vec![("python".to_string(), vec!["pytest".to_string()])],
            is_git_repo: true,
        };
        let config = build_config(&detection);
        assert_eq!(config["profile"], json!("default"));
        assert_eq!(config["languages"], json!(["python"]));
        assert_eq!(config["disabled_rules"], json!([]));
        assert_eq!(config["severity_overrides"], json!({}));
        assert_eq!(config["required_commands"]["python"], json!(["pytest"]));
    }

    #[test]
    fn merge_settings_into_empty_adds_all_five_events() {
        let merged = merge_settings(&Map::new());
        let hooks = merged["hooks"].as_object().expect("hooks object");
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "PreToolUse",
            "PostToolUse",
            "Stop",
        ] {
            assert!(hooks.contains_key(event), "missing event {event}");
        }
    }

    #[test]
    fn merge_settings_preserves_unrelated_settings_and_hooks() {
        let existing = json!({
            "permissions": {"allow": ["Bash"]},
            "hooks": {
                "SessionStart": [
                    {"hooks": [{"type": "command", "command": "other tool"}]}
                ]
            }
        });
        let existing = existing.as_object().expect("object").clone();

        let merged = merge_settings(&existing);
        assert_eq!(merged["permissions"], json!({"allow": ["Bash"]}));

        let session_start = merged["hooks"]["SessionStart"]
            .as_array()
            .expect("SessionStart array");
        assert_eq!(
            session_start.len(),
            2,
            "unrelated hook preserved, lgtm added"
        );
        assert!(entry_runs_command(&session_start[0], "other tool"));
        assert!(entry_runs_command(
            &session_start[1],
            "lgtm hook session-start"
        ));
    }

    #[test]
    fn merge_settings_is_idempotent() {
        let once = merge_settings(&Map::new());
        let twice = merge_settings(&once);
        assert_eq!(once, twice, "second merge must not add duplicate entries");
    }

    #[test]
    fn pre_tool_use_entry_carries_matcher() {
        let merged = merge_settings(&Map::new());
        let pre = &merged["hooks"]["PreToolUse"][0];
        assert_eq!(pre["matcher"], json!("Edit|Write"));
        assert_eq!(pre["hooks"][0]["command"], json!("lgtm hook pre-tool-use"));
    }

    #[test]
    fn session_start_entry_omits_matcher() {
        let merged = merge_settings(&Map::new());
        let entry = &merged["hooks"]["SessionStart"][0];
        assert!(
            entry.get("matcher").is_none(),
            "unmatched events omit matcher"
        );
    }

    #[test]
    fn merge_settings_corrects_wrong_matcher_on_existing_lgtm_entry() {
        let existing = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "lgtm hook pre-tool-use"}]}
                ]
            }
        });
        let existing = existing.as_object().expect("object").clone();

        let merged = merge_settings(&existing);
        let entries = merged["hooks"]["PreToolUse"].as_array().expect("array");
        assert_eq!(
            entries.len(),
            1,
            "existing lgtm entry corrected, not duplicated"
        );
        assert_eq!(entries[0]["matcher"], json!("Edit|Write"));
    }

    #[test]
    fn merge_settings_recognizes_path_qualified_lgtm_command() {
        let existing = json!({
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "command", "command": "/usr/local/bin/lgtm hook stop"}]}
                ]
            }
        });
        let existing = existing.as_object().expect("object").clone();

        let merged = merge_settings(&existing);
        let entries = merged["hooks"]["Stop"].as_array().expect("array");
        assert_eq!(
            entries.len(),
            1,
            "path-qualified lgtm hook must not be duplicated"
        );
        assert_eq!(
            entries[0]["hooks"][0]["command"],
            json!("/usr/local/bin/lgtm hook stop"),
            "already-correct path-qualified entry is left as authored"
        );
    }

    #[test]
    fn commands_match_tolerates_path_qualified_binary() {
        assert!(commands_match("lgtm hook stop", "lgtm hook stop"));
        assert!(commands_match("/usr/bin/lgtm hook stop", "lgtm hook stop"));
        assert!(commands_match("./bin/lgtm hook stop", "lgtm hook stop"));
        assert!(!commands_match("mylgtm hook stop", "lgtm hook stop"));
        assert!(!commands_match("lgtm hook start", "lgtm hook stop"));
    }

    #[test]
    fn non_command_type_hook_does_not_suppress_lgtm_entry() {
        let existing = json!({
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "notification", "command": "lgtm hook stop"}]}
                ]
            }
        });
        let existing = existing.as_object().expect("object").clone();

        let merged = merge_settings(&existing);
        let entries = merged["hooks"]["Stop"].as_array().expect("Stop array");
        assert_eq!(
            entries.len(),
            2,
            "a non-command hook with the same command must not suppress the required command hook"
        );
        let has_command_hook = entries.iter().any(|entry| {
            entry["hooks"][0]["type"] == json!("command")
                && entry["hooks"][0]["command"] == json!("lgtm hook stop")
        });
        assert!(
            has_command_hook,
            "the executable command-typed lgtm hook must be added"
        );
    }

    #[test]
    fn entry_runs_command_requires_command_type() {
        let command_hook = json!({"hooks": [{"type": "command", "command": "lgtm hook stop"}]});
        assert!(entry_runs_command(&command_hook, "lgtm hook stop"));

        let non_command_hook =
            json!({"hooks": [{"type": "notification", "command": "lgtm hook stop"}]});
        assert!(!entry_runs_command(&non_command_hook, "lgtm hook stop"));
    }

    #[cfg(unix)]
    #[test]
    fn stage_write_copies_target_mode_onto_temp_before_commit() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicU32;

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lgtm-stage-mode-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir creatable");

        let target = dir.join("settings.json");
        std::fs::write(&target, "{}\n").expect("target writable");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 must succeed");

        let staged = stage_write(&target, b"{\"changed\": true}\n").expect("stage must succeed");

        let temp_mode = std::fs::metadata(&staged.temp_path)
            .expect("temp metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            temp_mode, 0o600,
            "the staged temp must inherit the existing target's restrictive mode before commit"
        );

        let temp_path = staged.temp_path.clone();
        drop(staged);
        assert!(
            !temp_path.exists(),
            "dropping an uncommitted StagedWrite must remove its temp file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn stage_write_creates_temp_at_0600_then_committed_new_file_is_0644() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicU32;

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lgtm-stage-fresh-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir creatable");

        let target = dir.join("config.json");

        let staged = stage_write(&target, b"{\"fresh\": true}\n").expect("stage must succeed");

        let temp_mode = std::fs::metadata(&staged.temp_path)
            .expect("temp metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            temp_mode, 0o644,
            "a freshly-created target's temp must relax to the readable default after the 0600 write"
        );

        commit_write(staged).expect("commit must succeed");

        let committed_mode = std::fs::metadata(&target)
            .expect("committed metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            committed_mode, 0o644,
            "a committed file with no prior target must end at the readable 0644 default"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_is_ignored_honors_negation_ordering() {
        assert!(evidence_is_ignored(".lgtm/\n"));
        assert!(evidence_is_ignored(".lgtm/evidence/\n"));
        assert!(
            !evidence_is_ignored(".lgtm/\n!.lgtm/evidence/\n"),
            "a later negation of the evidence path flips the final effect to not-ignored"
        );
        assert!(
            evidence_is_ignored(".lgtm/\n!.lgtm/evidence/\n.lgtm/evidence/\n"),
            "a re-ignore after the negation restores the ignored effect"
        );
        assert!(!evidence_is_ignored("target/\n"));
    }

    /// Create a unique temporary directory for a `read_if_exists` test.
    fn read_test_dir(label: &str) -> PathBuf {
        use std::sync::atomic::AtomicU32;

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lgtm-read-{label}-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir creatable");
        dir
    }

    #[test]
    fn read_if_exists_returns_contents_for_a_regular_file() {
        let dir = read_test_dir("regular");
        let path = dir.join("config.json");
        std::fs::write(&path, "{\"profile\": \"default\"}\n").expect("target writable");

        let contents = read_if_exists(&path).expect("read must succeed");
        assert_eq!(contents.as_deref(), Some("{\"profile\": \"default\"}\n"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_if_exists_reports_absent_as_none() {
        let dir = read_test_dir("absent");
        let path = dir.join("config.json");

        let result = read_if_exists(&path).expect("absence is not an error");
        assert_eq!(result, None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_if_exists_rejects_oversized_file() {
        let dir = read_test_dir("oversized");
        let path = dir.join("config.json");
        let payload = "x".repeat((MAX_READ_BYTES as usize) + 1);
        std::fs::write(&path, payload).expect("target writable");

        let error = read_if_exists(&path).expect_err("oversized file must be rejected");
        assert!(
            matches!(
                error,
                InitError::FileTooLarge { max_bytes, .. } if max_bytes == MAX_READ_BYTES
            ),
            "an oversized file must map to a non-retryable FileTooLarge, got {error:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file exactly at the cap must still be read; only strictly-larger files
    /// are rejected, matching the `max + 1` read window.
    #[test]
    fn read_if_exists_accepts_file_at_the_cap() {
        let dir = read_test_dir("atcap");
        let path = dir.join("config.json");
        let payload = "x".repeat(MAX_READ_BYTES as usize);
        std::fs::write(&path, &payload).expect("target writable");

        let contents = read_if_exists(&path).expect("a file at the cap must be read");
        assert_eq!(contents.as_deref(), Some(payload.as_str()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO planted where init expects a config must not hang and must not be
    /// read: the atomic open treats a non-regular path as absent (`None`).
    #[cfg(unix)]
    #[test]
    fn read_if_exists_treats_fifo_as_absent_without_hanging() {
        let dir = read_test_dir("fifo");
        let path = dir.join("config.json");
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .expect("path has no interior NUL");
        let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo must create the FIFO");

        let result = read_if_exists(&path).expect("a FIFO must not surface as an error");
        assert_eq!(
            result, None,
            "a planted FIFO must be treated as absent, never opened or blocked on"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink planted where init expects a config must not be followed: the
    /// atomic `O_NOFOLLOW` open treats it as absent (`None`) rather than reading
    /// the target out of the repo.
    #[cfg(unix)]
    #[test]
    fn read_if_exists_does_not_follow_symlink() {
        let dir = read_test_dir("symlink");
        let real = dir.join("real.json");
        std::fs::write(&real, "{\"secret\": true}\n").expect("target writable");
        let link = dir.join("config.json");
        std::os::unix::fs::symlink(&real, &link).expect("symlink creatable");

        let result = read_if_exists(&link).expect("a symlink must not surface as an error");
        assert_eq!(
            result, None,
            "a symlinked config must be treated as absent, never followed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
