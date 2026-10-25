//! PreToolUse observer for Bash, Edit, and Write operations.
//!
//! This handler captures best-effort edit baselines and shell tracking. LGTM
//! never answers the host agent's permission decision from this path.

mod baseline;
mod config;
mod input;
mod target;

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use crate::adapter::{ClaudeAdapter, HookAdapter, HookEvent};
use crate::compile::compile_selected;
use crate::context;
use crate::policy::ChangeType;
use crate::select::select_rules;

pub(crate) fn validate_policy_files(root: &Path) -> Result<(), String> {
    config::validate_policy_files(root)
}

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let adapter = ClaudeAdapter;
    run_with_adapter(input, output, &adapter)
}

/// Run PreToolUse with an explicitly selected harness adapter.
pub fn run_with_adapter(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    run_for_event(input, output, adapter, HookEvent::PreToolUse)
}

/// Run the same observations for a Codex permission request.
pub fn run_permission_request(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    run_for_event(input, output, adapter, HookEvent::PermissionRequest)
}

/// Observe one hook request and leave the permission decision to the host agent.
///
/// LGTM never emits a permission response here, so every path returns success.
/// Missing or malformed input, unresolved roots or targets, and baseline errors
/// become bounded diagnostics on stderr instead of denials.
fn run_for_event(
    input: &mut impl Read,
    _output: &mut impl Write,
    _adapter: &dyn HookAdapter,
    event: HookEvent,
) -> ExitCode {
    let Some(parsed) = read_input(input) else {
        eprintln!(
            "pre-tool-use failed: entity=stdin reason=malformed or oversized payload retryable=false"
        );
        return ExitCode::SUCCESS;
    };
    let root = match crate::hooks::root::resolve(parsed.cwd.as_deref()) {
        Ok(root) => root,
        Err(reason) => {
            report_unverified("root", &reason);
            return ExitCode::SUCCESS;
        }
    };
    if let Some(command) = input::requested_command(&parsed) {
        if event == HookEvent::PreToolUse {
            super::shell_tracking::begin(
                &root,
                parsed.session_id.as_deref(),
                parsed.tool_use_id.as_deref(),
                command,
            );
        }
        return ExitCode::SUCCESS;
    }
    let Some(file) = input::edited_file(&parsed) else {
        return ExitCode::SUCCESS;
    };
    let target = match target::resolve(&root, file) {
        Ok(target) => target,
        Err(reason) => {
            report_unverified("target", &reason);
            return ExitCode::SUCCESS;
        }
    };
    super::shell_tracking::observe_edit(&root, parsed.session_id.as_deref());
    if let Err(reason) = capture(&root, &target, parsed.session_id.as_deref()) {
        report_unverified("baseline", &reason);
    }
    ExitCode::SUCCESS
}

fn report_unverified(entity: &str, reason: &str) {
    eprintln!(
        "pre-tool-use unverified: entity={entity} reason={} retryable=false",
        bounded_reason(reason)
    );
}

fn bounded_reason(reason: &str) -> String {
    const MAX_CHARS: usize = 2_048;
    let sanitized: String = reason
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .collect();
    if sanitized.chars().count() <= MAX_CHARS {
        return sanitized;
    }
    let mut bounded: String = sanitized.chars().take(MAX_CHARS - 1).collect();
    bounded.push('…');
    bounded
}

fn read_input(input: &mut impl Read) -> Option<input::HookInput> {
    let mut raw = String::new();
    input
        .take(input::MAX_PAYLOAD_BYTES + 1)
        .read_to_string(&mut raw)
        .ok()?;
    if raw.len() as u64 > input::MAX_PAYLOAD_BYTES {
        return None;
    }
    serde_json::from_str(&raw).ok()
}

fn capture(root: &Path, target: &Path, session: Option<&str>) -> Result<(), String> {
    let relative = target
        .strip_prefix(root)
        .unwrap_or(target)
        .to_string_lossy()
        .to_string();
    let context = context::build(root, &[relative], "");
    let (_, registry, _, _, compatibility, _) = crate::policy::load_profiled_registry(root)?;
    if compatibility == crate::policy::config_version::Compatibility::LegacyMissing {
        eprintln!(
            "validate failed: entity=config-version reason=version missing; legacy compatibility accepted, run lgtm init retryable=false"
        );
    }
    let selected = select_rules(&context, &registry, ChangeType::Modify);
    let compiled = compile_selected(&selected, &context.files_touched);
    baseline::capture(root, target, session, &compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_input_parses_supported_hook_fields() {
        let mut raw = "{\"cwd\":\"repo\",\"session_id\":\"session\",\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"src/lib.rs\"}}".as_bytes();
        let parsed = read_input(&mut raw).expect("valid hook input");
        assert_eq!(parsed.cwd.as_deref(), Some("repo"));
        assert_eq!(parsed.session_id.as_deref(), Some("session"));
        assert_eq!(parsed.tool_name.as_deref(), Some("Write"));
        assert_eq!(parsed.tool_input.file_path.as_deref(), Some("src/lib.rs"));
    }

    #[test]
    fn read_input_rejects_malformed_and_oversized_payloads() {
        assert!(read_input(&mut "not json".as_bytes()).is_none());
        let mut oversized = vec![b'a'; (input::MAX_PAYLOAD_BYTES + 1) as usize];
        assert!(read_input(&mut std::io::Cursor::new(&mut oversized)).is_none());
    }

    #[test]
    fn read_input_accepts_the_exact_payload_limit() {
        let limit = 256 * 1_024;
        let prefix = "{\"tool_name\":\"";
        let suffix = "\"}";
        let padding = "a".repeat(limit - prefix.len() - suffix.len());
        let raw = format!("{prefix}{padding}{suffix}");
        assert_eq!(raw.len(), limit);
        let parsed = read_input(&mut std::io::Cursor::new(raw)).expect("limit is accepted");
        assert_eq!(parsed.tool_name.as_deref(), Some(padding.as_str()));

        let oversized = format!("{prefix}{padding}{suffix} ");
        assert!(read_input(&mut std::io::Cursor::new(oversized)).is_none());
    }

    #[test]
    fn diagnostic_reasons_are_sanitized_and_bounded() {
        let reason = format!("{}\rsecret", "x".repeat(2_048));
        let bounded = bounded_reason(&reason);
        assert_eq!(bounded.chars().count(), 2_048);
        assert!(bounded.ends_with('…'));
        assert!(!bounded.contains('\r'));
    }
}
