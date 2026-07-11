//! PostToolUse hook: run fast checks on the file an edit just touched.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use crate::checks::gitleaks;
use crate::checks::{EnforcementResult, Status};

mod evidence;
mod input;
mod target;

use evidence::append_evidence;
use input::{MAX_PAYLOAD_BYTES, edited_file, parse_input};
use target::{repo_root, resolve_target, unverified_target};

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    match catch_unwind(AssertUnwindSafe(|| run_inner(input, output))) {
        Ok(code) => code,
        Err(_) => {
            diagnostic(
                "run",
                "post-tool-use",
                "handler panicked; failing safe",
                false,
            );
            ExitCode::SUCCESS
        }
    }
}

fn run_inner(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let Some(hook_input) = read_input(input) else {
        return ExitCode::SUCCESS;
    };
    let Some(file_path) = edited_file(&hook_input) else {
        return ExitCode::SUCCESS;
    };
    let Some(root) = repo_root(hook_input.cwd.as_deref()) else {
        return ExitCode::SUCCESS;
    };
    let result = scan_target(&root, &file_path);
    persist(&root, hook_input.session_id.as_deref(), &result);
    handle_result(output, &result)
}

fn read_input(input: &mut impl Read) -> Option<input::HookInput> {
    let mut raw = String::new();
    if let Err(error) = input.take(MAX_PAYLOAD_BYTES + 1).read_to_string(&mut raw) {
        diagnostic("read", "stdin", &error.to_string(), true);
        return None;
    }
    if raw.len() as u64 > MAX_PAYLOAD_BYTES {
        diagnostic("read", "stdin", "payload exceeds maximum size", false);
        return None;
    }
    parse_input(&raw)
        .map_err(|error| diagnostic("parse", "stdin", &error.to_string(), false))
        .ok()
}

fn scan_target(root: &Path, file_path: &str) -> EnforcementResult {
    let Some(resolved) = resolve_target(root, file_path) else {
        return unverified_target(file_path);
    };
    let mut result = gitleaks::scan(std::slice::from_ref(&resolved));
    if result.locations.is_empty() {
        result.locations.push(crate::checks::Location {
            file: resolved,
            line: None,
        });
    }
    result
}

fn handle_result(output: &mut impl Write, result: &EnforcementResult) -> ExitCode {
    match result.status {
        Status::Failed => emit_block(output, result),
        Status::Unverified => {
            diagnostic(
                "scan",
                &result.rule_id,
                "secret scan unverified; not blocking",
                false,
            );
            ExitCode::SUCCESS
        }
        _ => ExitCode::SUCCESS,
    }
}

fn emit_block(output: &mut impl Write, result: &EnforcementResult) -> ExitCode {
    let payload = json!({ "decision": "block", "reason": block_reason(result) });
    let serialized = match serde_json::to_string(&payload) {
        Ok(serialized) => serialized,
        Err(error) => {
            diagnostic("serialize", "decision", &error.to_string(), false);
            return ExitCode::SUCCESS;
        }
    };
    if let Err(error) = writeln!(output, "{serialized}") {
        diagnostic("write", "decision", &error.to_string(), true);
    }
    ExitCode::SUCCESS
}

fn block_reason(result: &EnforcementResult) -> String {
    let mut reason = result.message.clone();
    if let Some(remediation) = &result.remediation {
        reason.push(' ');
        reason.push_str(remediation);
    }
    reason
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .collect()
}

fn diagnostic(action: &str, entity: &str, reason: &str, retryable: bool) {
    let _ = writeln!(
        io::stderr(),
        "{action} failed: entity={entity} reason={reason} retryable={retryable}"
    );
}

fn persist(root: &Path, session_id: Option<&str>, result: &EnforcementResult) {
    if let Err(reason) = append_evidence(root, session_id, result) {
        diagnostic("persist", "evidence", &reason, true);
    }
}

#[cfg(test)]
mod tests;
