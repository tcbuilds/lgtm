//! PreToolUse guard for Edit and Write operations.

mod baseline;
mod config;
mod input;
mod target;

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use crate::adapter::{self, ClaudeAdapter, HookAdapter, HookEvent, HookResponse};
use crate::compile::compile_selected;
use crate::context;
use crate::policy::ChangeType;
use crate::select::select_rules;

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

/// Run the same path-policy checks for a Codex permission request.
pub fn run_permission_request(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    run_for_event(input, output, adapter, HookEvent::PermissionRequest)
}

fn run_for_event(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
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
        Err(reason) => return deny(output, adapter, event, &reason),
    };
    if event == HookEvent::PermissionRequest
        && let Some(command) = input::requested_command(&parsed)
    {
        match config::is_prohibited_command(&root, command) {
            Ok(true) => {
                return deny(
                    output,
                    adapter,
                    event,
                    "command matches prohibited_commands policy",
                );
            }
            Ok(false) => {}
            Err(reason) => {
                return deny(
                    output,
                    adapter,
                    event,
                    &format!("prohibited command policy unverified: {reason}"),
                );
            }
        }
        return ExitCode::SUCCESS;
    }
    let Some(file) = input::edited_file(&parsed) else {
        return ExitCode::SUCCESS;
    };
    let target = match target::resolve(&root, file) {
        Ok(target) => target,
        Err(reason) => return deny(output, adapter, event, &reason),
    };
    let relative = target.strip_prefix(&root).unwrap_or(&target);
    let patterns = match config::prohibited_patterns(&root) {
        Ok(patterns) => patterns,
        Err(reason) => {
            return deny(
                output,
                adapter,
                event,
                &format!("prohibited path policy unverified: {reason}"),
            );
        }
    };
    if config::is_prohibited(&relative.to_string_lossy(), &patterns) {
        return deny(
            output,
            adapter,
            event,
            "target matches prohibited_paths policy",
        );
    }
    if let Err(reason) = capture(&root, &target, parsed.session_id.as_deref()) {
        return deny(
            output,
            adapter,
            event,
            &format!("verification baseline failed: {reason}"),
        );
    }
    ExitCode::SUCCESS
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

fn deny(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: HookEvent,
    reason: &str,
) -> ExitCode {
    let encoded = match adapter.encode_response(
        event,
        HookResponse::Deny {
            reason: reason.to_string(),
        },
    ) {
        Ok(encoded) => encoded,
        Err(_) => return ExitCode::SUCCESS,
    };
    let _ = adapter::emit(output, &mut std::io::stderr(), &encoded);
    ExitCode::from(encoded.exit_code)
}
