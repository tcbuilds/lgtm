//! PreToolUse guard for Edit and Write operations.

mod baseline;
mod config;
mod input;
mod target;

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use crate::compile::compile_selected;
use crate::context;
use crate::policy::ChangeType;
use crate::select::select_rules;

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let Some(parsed) = read_input(input) else {
        return ExitCode::SUCCESS;
    };
    let Some(file) = input::edited_file(&parsed) else {
        return ExitCode::SUCCESS;
    };
    let root = parsed
        .cwd
        .as_deref()
        .map_or_else(|| Path::new("."), Path::new);
    let target = match target::resolve(root, file) {
        Ok(target) => target,
        Err(reason) => return deny(output, &reason),
    };
    let relative = target
        .strip_prefix(root.canonicalize().unwrap_or_default())
        .unwrap_or(&target);
    let patterns = match config::prohibited_patterns(root) {
        Ok(patterns) => patterns,
        Err(reason) => {
            return deny(
                output,
                &format!("prohibited path policy unverified: {reason}"),
            );
        }
    };
    if config::is_prohibited(&relative.to_string_lossy(), &patterns) {
        return deny(output, "target matches prohibited_paths policy");
    }
    if let Err(reason) = capture(root, &target, parsed.session_id.as_deref()) {
        return deny(output, &format!("verification baseline failed: {reason}"));
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
    let (_, registry, _) = crate::policy::load_profiled_registry(root)?;
    let selected = select_rules(&context, &registry, ChangeType::Modify);
    let compiled = compile_selected(&selected, &context.files_touched);
    baseline::capture(root, target, session, &compiled)
}

fn deny(output: &mut impl Write, reason: &str) -> ExitCode {
    let payload = json!({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }, "systemMessage": reason});
    let _ = writeln!(output, "{}", payload);
    ExitCode::SUCCESS
}
