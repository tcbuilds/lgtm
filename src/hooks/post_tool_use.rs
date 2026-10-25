//! PostToolUse hook: run fast checks on the file an edit just touched.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::process::ExitCode;

use crate::adapter::{self, ClaudeAdapter, HookAdapter, HookEvent, HookResponse};
use crate::checks::tiers::{self, Check, Hook};
use crate::checks::{EnforcementResult, Status};
use crate::checks::{gitleaks, languages, ruff, structure};
use crate::policy::Severity;
#[cfg(test)]
use serde_json::json;

mod evidence;
mod input;
mod target;

use evidence::append_evidence;
pub(super) use evidence::append_evidence as append_tracking_evidence;
use input::{MAX_PAYLOAD_BYTES, edited_file, parse_input};
use target::{repo_root, resolve_read_path, resolve_target, unverified_target};

const MAX_REVIEW_FEEDBACK_CHARS: usize = 1_024;
const REVIEW_FEEDBACK_PREFIX: &str = "PostToolUse review feedback: ";
const REVIEW_REMEDIATION_SEPARATOR: &str = " Remediation: ";

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let adapter = ClaudeAdapter;
    run_with_adapter(input, output, &adapter)
}

/// Run PostToolUse with an explicitly selected harness adapter.
pub fn run_with_adapter(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    match catch_unwind(AssertUnwindSafe(|| run_inner(input, output, adapter))) {
        Ok(code) => code,
        Err(_) => {
            diagnostic(
                "run",
                "post-tool-use",
                "handler panicked; failing safe",
                false,
            );
            fail_open(adapter)
        }
    }
}

fn run_inner(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    let Some(hook_input) = read_input(input) else {
        return fail_open(adapter);
    };
    let Some(root) = repo_root(hook_input.cwd.as_deref()) else {
        return ExitCode::SUCCESS;
    };
    if adapter.harness_name() == "pi" && hook_input.tool_name.as_deref() == Some("Read") {
        return run_pi_read_guidance(&root, &hook_input, output, adapter);
    }
    let (edited_file, mut results) = if hook_input.tool_name.as_deref() == Some("Bash") {
        let command = hook_input
            .tool_input
            .as_ref()
            .and_then(|input| input.command.as_deref().or(input.cmd.as_deref()))
            .unwrap_or_default();
        let paths = match super::shell_tracking::finish(
            &root,
            hook_input.session_id.as_deref(),
            hook_input.tool_use_id.as_deref(),
            command,
        ) {
            Ok(paths) => paths,
            Err(_) => return fail_open(adapter),
        };
        if paths.is_empty() {
            return ExitCode::SUCCESS;
        }
        let existing = paths
            .iter()
            .filter_map(|path| resolve_target(&root, path))
            .collect::<Vec<_>>();
        (None, scan_paths(&root, &existing))
    } else {
        let Some(file_path) = edited_file(&hook_input) else {
            return ExitCode::SUCCESS;
        };
        scan_target(&root, &file_path)
    };
    let (_, registry, overrides, waivers, compatibility, _) =
        match crate::policy::load_profiled_registry(&root) {
            Ok(profile) => profile,
            Err(reason) => {
                diagnostic("load", "profile", &reason, false);
                return fail_open(adapter);
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
        persist(
            &root,
            hook_input.session_id.as_deref(),
            edited_file.as_deref(),
            result,
        );
    }
    if hook_input.hook_event_name.as_deref() == Some("PostToolUseFailure") {
        return ExitCode::SUCCESS;
    }
    handle_results(output, adapter, &results)
}

fn run_pi_read_guidance(
    root: &Path,
    hook_input: &input::HookInput,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    let Some(raw_path) = input::read_file(hook_input) else {
        diagnostic(
            "inject",
            "path-guidance",
            "read path is missing or invalid",
            false,
        );
        return fail_open(adapter);
    };
    let Some(path) = resolve_read_path(root, hook_input.cwd.as_deref(), &raw_path) else {
        diagnostic(
            "inject",
            "path-guidance",
            "read path is outside the repository or unavailable",
            false,
        );
        return fail_open(adapter);
    };
    let Some(session_id) = hook_input.session_id.clone() else {
        diagnostic("inject", "path-guidance", "session id is missing", false);
        return fail_open(adapter);
    };
    let request = crate::path_injection::PathInjectionRequest::new(vec![path], Some(session_id));
    let store = crate::path_injection::FileSessionDedupStore::for_root(root);
    let selection = crate::path_injection::select_rule_bodies_with_store(&request, &store);
    if !selection.diagnostics.is_empty() {
        diagnostic(
            "inject",
            "path-guidance",
            "some guidance could not be selected",
            false,
        );
    }
    if selection.bodies.is_empty() {
        return ExitCode::SUCCESS;
    }
    let packet = selection
        .bodies
        .into_iter()
        .map(|body| body.body)
        .collect::<Vec<_>>()
        .join("\n\n");
    let encoded = match adapter.encode_response(
        HookEvent::PostToolUse,
        HookResponse::PostToolFeedback { reason: packet },
    ) {
        Ok(encoded) => encoded,
        Err(error) => {
            diagnostic("encode", "path-guidance", &error, false);
            return fail_open(adapter);
        }
    };
    if let Err(error) = adapter::emit(output, &mut std::io::stderr(), &encoded) {
        diagnostic("write", "path-guidance", &error.to_string(), true);
        return fail_open(adapter);
    }
    ExitCode::SUCCESS
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

fn scan_target(root: &Path, file_path: &str) -> (Option<String>, Vec<EnforcementResult>) {
    let Some(resolved) = resolve_target(root, file_path) else {
        return (None, vec![unverified_target(file_path)]);
    };
    let results = scan_paths(root, std::slice::from_ref(&resolved));
    (Some(resolved), results)
}

fn scan_paths(root: &Path, paths: &[String]) -> Vec<EnforcementResult> {
    let mut results = Vec::new();
    for check in tiers::checks(tiers::for_hook(Hook::PostToolUse)) {
        match check {
            Check::Secrets if !paths.is_empty() => {
                let mut result = gitleaks::scan(paths);
                if result.locations.is_empty() {
                    result.locations = paths
                        .iter()
                        .map(|file| crate::checks::Location {
                            file: file.clone(),
                            line: None,
                        })
                        .collect();
                }
                results.push(result);
            }
            Check::Secrets => {}
            Check::Diff => {
                let touched = paths
                    .iter()
                    .filter_map(|path| {
                        Path::new(path)
                            .strip_prefix(root)
                            .ok()
                            .map(|path| path.to_string_lossy().into_owned())
                    })
                    .collect();
                results.extend(crate::checks::diff::evaluate_at(
                    root,
                    &touched,
                    None,
                    None,
                    crate::checks::diff::Stage::PostToolUse,
                ));
            }
            Check::Ruff => {
                let python: Vec<_> = paths
                    .iter()
                    .filter(|path| path.ends_with(".py"))
                    .cloned()
                    .collect();
                if !python.is_empty() {
                    results.extend(ruff::scan(&python));
                }
            }
            Check::NativeLanguages => {
                results.extend(languages::scan(paths));
                results.extend(structure::scan(paths));
                results.extend(crate::checks::modules::scan(paths));
                results.extend(crate::checks::naming::scan(paths));
                results.extend(crate::checks::boundary::scan(paths));
                results.extend(crate::checks::logging::scan(paths));
                results.extend(crate::checks::determinism::scan(paths));
                results.extend(crate::checks::ui::scan(paths));
                results.extend(crate::checks::justification::scan(paths));
                results.extend(crate::checks::construction::scan(paths));
                results.extend(crate::checks::endpoints::scan(paths));
            }
            _ => unreachable!("fast tier contains only fast checks"),
        }
    }
    results
}
fn handle_results(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    results: &[EnforcementResult],
) -> ExitCode {
    let failures: Vec<_> = results
        .iter()
        .filter(|result| result.status == Status::Failed && result.severity == Severity::Error)
        .collect();
    for result in results.iter().filter(|result| {
        result.status == Status::Unverified
            && (adapter.harness_name() != "pi" || result.severity == Severity::Error)
    }) {
        diagnostic(
            "scan",
            &result.rule_id,
            "check unverified; not blocking",
            false,
        );
    }
    for result in results.iter().filter(|result| {
        (adapter.harness_name() != "pi" || result.severity == Severity::Error)
            && (result.status == Status::Warning
                || (result.status == Status::Failed && result.severity != Severity::Error))
    }) {
        let reason = review_reason(result);
        diagnostic("review", &result.rule_id, &reason, false);
    }
    if failures.is_empty() {
        let items = crate::checks::pi_heuristic_notices(results);
        if adapter.harness_name() == "pi"
            && !items.is_empty()
            && !results.iter().any(|result| {
                result.status == Status::Unverified && result.severity == Severity::Error
            })
        {
            let response = HookResponse::HeuristicNotices(crate::adapter::PiHeuristicNotices {
                identity: None,
                items,
            });
            return match adapter.encode_response(HookEvent::PostToolUse, response) {
                Ok(encoded) => match adapter::emit(output, &mut std::io::stderr(), &encoded) {
                    Ok(()) => ExitCode::from(encoded.exit_code),
                    Err(_) => fail_open(adapter),
                },
                Err(_) => fail_open(adapter),
            };
        }
        if adapter.fail_open_on_error()
            && results
                .iter()
                .any(|result| result.status == Status::Unverified)
        {
            return ExitCode::from(1);
        }
        ExitCode::SUCCESS
    } else {
        emit_feedback(output, adapter, &failures)
    }
}

fn fail_open(adapter: &dyn HookAdapter) -> ExitCode {
    if adapter.fail_open_on_error() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn emit_feedback(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    results: &[&EnforcementResult],
) -> ExitCode {
    let reason = results
        .iter()
        .map(|result| feedback_reason(result))
        .collect::<Vec<_>>()
        .join("\n");
    let encoded = match adapter.encode_response(
        HookEvent::PostToolUse,
        HookResponse::PostToolFeedback { reason },
    ) {
        Ok(encoded) => encoded,
        Err(error) => {
            diagnostic("encode", "decision", &error, false);
            return ExitCode::SUCCESS;
        }
    };
    if let Err(error) = adapter::emit(output, &mut std::io::stderr(), &encoded) {
        diagnostic("write", "decision", &error.to_string(), true);
    }
    ExitCode::from(encoded.exit_code)
}

fn review_reason(result: &EnforcementResult) -> String {
    let message = control_free(&result.message);
    let remediation = result.remediation.as_deref().map(control_free);
    let remediation_suffix = remediation
        .as_deref()
        .map(|text| format!("{REVIEW_REMEDIATION_SEPARATOR}{text}"));
    let suffix_chars = remediation_suffix
        .as_deref()
        .map_or(0, |suffix| suffix.chars().count());
    let fixed_chars = REVIEW_FEEDBACK_PREFIX
        .chars()
        .count()
        .saturating_add(suffix_chars);
    let message_budget = MAX_REVIEW_FEEDBACK_CHARS.saturating_sub(fixed_chars);
    let mut reason = String::with_capacity(MAX_REVIEW_FEEDBACK_CHARS);
    reason.push_str(REVIEW_FEEDBACK_PREFIX);
    reason.extend(message.chars().take(message_budget));
    if let Some(suffix) = remediation_suffix {
        let remaining = MAX_REVIEW_FEEDBACK_CHARS.saturating_sub(reason.chars().count());
        reason.extend(suffix.chars().take(remaining));
    }
    reason
}

fn control_free(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn feedback_reason(result: &EnforcementResult) -> String {
    let mut reason = format!(
        "PostToolUse feedback: the tool already ran; {}",
        result.message
    );
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

fn persist(
    root: &Path,
    session_id: Option<&str>,
    edited_file: Option<&str>,
    result: &EnforcementResult,
) {
    if let Err(reason) = append_evidence(root, session_id, edited_file, result) {
        diagnostic("persist", "evidence", &reason, true);
    }
}

#[cfg(test)]
mod tests;
