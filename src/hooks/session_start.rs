//! SessionStart hook: emit the persistent harness contract.
//!
//! Claude Code invokes this at the start of every session (and on resume, clear,
//! and compact). The handler reads the SessionStart hook payload from stdin,
//! resolves the consumer repo root from `cwd`, detects languages and check
//! commands, loads `.lgtm/config.json` for the active profile, and emits the
//! harness contract to stdout as SessionStart `additionalContext`.
//!
//! Fail-safe is non-negotiable (idea.md §Design Constraints): any internal error
//! — malformed stdin, an unreadable or malformed config, a detection failure —
//! exits 0 with a diagnostic on stderr and no contract on stdout. A broken
//! harness must never corrupt or block an agent session, so a hook failure is
//! silent to the agent and visible only to the operator via stderr.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;

use crate::detect::detect;
mod config;
mod context;
mod input;

use config::load_config;
use context::build_context;
use input::{MAX_PAYLOAD_BYTES, parse_input};

/// Handle a SessionStart hook invocation, reading the payload from `input` and
/// writing the contract to `output`.
///
/// Returns [`ExitCode::SUCCESS`] in every case: on success the contract is
/// written to `output`; on any fail-safe path (malformed stdin, unreadable or
/// malformed config, or a stdout write failure) a diagnostic is written to
/// stderr and nothing is written to `output`. The exit code is always success so
/// the hook can never block or corrupt the agent session.
pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    // Fail-safe totality: any panic in the handler is caught and turned into a
    // diagnostic plus a success exit, so an unexpected panic can never crash the
    // hook and corrupt or block the agent session. The unwind-safety assertion is
    // sound because a caught panic leaves nothing observable half-updated: the
    // only side effect is a possible partial write to `output`, and the harness
    // ignores a truncated contract line.
    match catch_unwind(AssertUnwindSafe(|| run_inner(input, output))) {
        Ok(code) => code,
        Err(_) => {
            diagnostic(
                "run",
                "session-start",
                "handler panicked; failing safe",
                false,
            );
            ExitCode::SUCCESS
        }
    }
}

/// The handler body, wrapped by [`run`] in a panic guard.
fn run_inner(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let mut raw = String::new();
    if let Err(error) = input.take(MAX_PAYLOAD_BYTES + 1).read_to_string(&mut raw) {
        diagnostic("read", "stdin", &error.to_string(), true);
        return ExitCode::SUCCESS;
    }
    if raw.len() as u64 > MAX_PAYLOAD_BYTES {
        diagnostic("read", "stdin", "payload exceeds maximum size", false);
        return ExitCode::SUCCESS;
    }

    let hook_input = match parse_input(&raw) {
        Ok(hook_input) => hook_input,
        Err(error) => {
            diagnostic("parse", "stdin", &error.to_string(), false);
            return ExitCode::SUCCESS;
        }
    };

    let root = repo_root(hook_input.cwd.as_deref());
    if !root.exists() {
        diagnostic(
            "resolve",
            &root.display().to_string(),
            "repo root does not exist",
            false,
        );
        return ExitCode::SUCCESS;
    }

    let detection = detect(&root);
    let config_state = load_config(&root);

    let context = build_context(&detection, &config_state, hook_input.source.as_deref());
    let payload = contract_payload(&context);

    let serialized = match serde_json::to_string(&payload) {
        Ok(serialized) => serialized,
        Err(error) => {
            diagnostic("serialize", "contract", &error.to_string(), false);
            return ExitCode::SUCCESS;
        }
    };

    if let Err(error) = writeln!(output, "{serialized}") {
        diagnostic("write", "contract", &error.to_string(), true);
        return ExitCode::SUCCESS;
    }

    ExitCode::SUCCESS
}

/// Emit one operator diagnostic to stderr in the standard shape
/// `action failed: entity=<id> reason=<cause> retryable=<bool>`.
///
/// Written with `writeln!` on a discarded result so a closed or broken stderr
/// (EPIPE) can never panic the hook: fail-safe must remain total even when the
/// diagnostic itself cannot be delivered.
fn diagnostic(action: &str, entity: &str, reason: &str, retryable: bool) {
    let _ = writeln!(
        io::stderr(),
        "{action} failed: entity={entity} reason={reason} retryable={retryable}"
    );
}

/// Parse the SessionStart payload from raw stdin text.
///
/// Blank stdin is accepted as an empty payload (the fields all default), so a
/// hook fired without input still produces a contract from the working
/// directory. Non-blank text that is not a JSON object is a parse error the
/// caller treats as malformed stdin (exit 0, no contract).
/// Resolve the repo root from the hook payload's `cwd`.
///
/// A present, non-empty `cwd` is used verbatim; otherwise the process working
/// directory is used, falling back to `.` when even that is unavailable so
/// detection always has a path to inspect.
fn repo_root(cwd: Option<&str>) -> PathBuf {
    match cwd {
        Some(cwd) if !cwd.trim().is_empty() => PathBuf::from(cwd),
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

/// Wrap the contract text in the Claude Code SessionStart JSON envelope.
fn contract_payload(context: &str) -> serde_json::Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context,
        }
    })
}

#[cfg(test)]
mod tests;
