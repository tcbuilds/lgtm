//! PostToolUse hook: run fast checks on the file an edit just touched.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::ExitCode;

use serde_json::json;

use crate::checks::tiers::{self, Check, Hook};
use crate::checks::{EnforcementResult, Status};
use crate::checks::{gitleaks, languages, ruff, structure};

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
    let mut results = scan_target(&root, &file_path);
    let (_, registry, overrides, waivers, compatibility, _) =
        match crate::policy::load_profiled_registry(&root) {
            Ok(profile) => profile,
            Err(reason) => {
                diagnostic("load", "profile", &reason, false);
                return ExitCode::SUCCESS;
            }
        };
    if compatibility == crate::policy::config_version::Compatibility::LegacyMissing {
        diagnostic(
            "validate",
            "config-version",
            "version missing; legacy compatibility accepted, run lgtm init",
            false,
        );
    }
    crate::policy::profile::apply_resolved_results(&registry, &mut results);
    crate::policy::overrides::apply_results(&overrides, &mut results);
    crate::policy::waivers::apply(&waivers, &mut results);
    for result in &results {
        persist(&root, hook_input.session_id.as_deref(), result);
    }
    handle_results(output, &results)
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

fn scan_target(root: &Path, file_path: &str) -> Vec<EnforcementResult> {
    let Some(resolved) = resolve_target(root, file_path) else {
        return vec![unverified_target(file_path)];
    };
    let mut results = Vec::new();
    for check in tiers::checks(tiers::for_hook(Hook::PostToolUse)) {
        match check {
            Check::Secrets => results.push(scan_secrets(&resolved)),
            Check::Diff => results.extend(scan_diff(root, &resolved)),
            Check::Ruff if resolved.ends_with(".py") => {
                results.extend(ruff::scan(std::slice::from_ref(&resolved)));
            }
            Check::Ruff => {}
            Check::NativeLanguages => {
                results.extend(languages::scan(std::slice::from_ref(&resolved)));
                results.extend(structure::scan(std::slice::from_ref(&resolved)));
                results.extend(crate::checks::modules::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::naming::scan(std::slice::from_ref(&resolved)));
                results.extend(crate::checks::boundary::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::logging::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::determinism::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::ui::scan(std::slice::from_ref(&resolved)));
                results.extend(crate::checks::justification::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::construction::scan(std::slice::from_ref(
                    &resolved,
                )));
                results.extend(crate::checks::endpoints::scan(std::slice::from_ref(
                    &resolved,
                )));
            }
            _ => unreachable!("fast tier contains only fast checks"),
        }
    }
    results
}

fn scan_secrets(resolved: &str) -> EnforcementResult {
    let mut result = gitleaks::scan(&[resolved.to_string()]);
    if result.locations.is_empty() {
        result.locations.push(crate::checks::Location {
            file: resolved.to_string(),
            line: None,
        });
    }
    result
}

fn scan_diff(root: &Path, resolved: &str) -> Vec<EnforcementResult> {
    let touched = Path::new(&resolved)
        .strip_prefix(root)
        .ok()
        .map(|path| BTreeSet::from([path.to_string_lossy().into_owned()]))
        .unwrap_or_default();
    crate::checks::diff::evaluate_at(
        root,
        &touched,
        None,
        None,
        crate::checks::diff::Stage::PostToolUse,
    )
}

fn handle_results(output: &mut impl Write, results: &[EnforcementResult]) -> ExitCode {
    let failures: Vec<_> = results
        .iter()
        .filter(|result| result.status == Status::Failed)
        .collect();
    for result in results
        .iter()
        .filter(|result| result.status == Status::Unverified)
    {
        diagnostic(
            "scan",
            &result.rule_id,
            "check unverified; not blocking",
            false,
        );
    }
    for result in results
        .iter()
        .filter(|result| result.status == Status::Warning)
    {
        diagnostic("review", &result.rule_id, &result.message, false);
    }
    if failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        emit_blocks(output, &failures)
    }
}

fn emit_blocks(output: &mut impl Write, results: &[&EnforcementResult]) -> ExitCode {
    let reason = results
        .iter()
        .map(|result| block_reason(result))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = json!({ "decision": "block", "reason": reason });
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
