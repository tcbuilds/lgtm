//! Stop hook: rerun required secret checks and enforce unresolved MUST failures.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::adapter::{ClaudeAdapter, HookAdapter, HookResponse};
use crate::checks::tiers::{self, Hook, Tier};
use crate::checks::{EnforcementResult, Location, ResultEvidence, Status};
use crate::checks::{commands, gitleaks, ruff, semgrep};
use crate::policy::Severity;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const MAX_LEDGER_BYTES: u64 = 5 * 1024 * 1024;
// Keep this in lockstep with PostToolUse rotation so Stop never parses an
// unbounded number of newline-delimited records from a bounded ledger.
const MAX_LEDGER_RECORDS: usize = 16 * 1024;
const MAX_TOUCHED_PATHS: usize = 512;
const MAX_TASK_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_SUMMARY_MESSAGE_CHARS: usize = 512;
const EVIDENCE_SCHEMA_JSON: &str = include_str!("../../schemas/evidence.schema.json");
const CURRENT_TASK_RETENTION_MESSAGE: &str =
    "Older current-task evidence records were dropped at the bounded retention limit.";
const CURRENT_TASK_PERSISTENCE_MESSAGE: &str =
    "Current-task evidence could not be persisted within the bounded ledger limit.";
const CURRENT_TASK_RETENTION_REASON: &str = "current-task evidence was truncated at the bounded retention limit; repair or regenerate evidence";
const CURRENT_TASK_RECORD_TRUNCATION_REASON: &str = "current-task evidence record details were truncated at a bounded limit; repair or regenerate evidence";
const CURRENT_TASK_PERSISTENCE_REASON: &str = "current-task evidence could not be persisted within the bounded ledger limit; repair or regenerate evidence";

#[cfg(test)]
thread_local! {
    static TOUCHED_PATH_RESOLUTION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Default, Deserialize)]
struct HookInput {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    transcript_path: Option<String>,
    #[serde(default)]
    check: bool,
    #[serde(default)]
    workspace: Option<String>,
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    stop_hook_active: bool,
}

#[derive(Debug, Deserialize)]
struct EditRecord {
    session_id: Option<String>,
    #[serde(default)]
    edited_file: Option<String>,
    result: EnforcementResult,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    persistence_failed: bool,
}

struct TouchedPaths {
    files: Vec<String>,
    had_edits: bool,
    ledger_issue: Option<String>,
}

enum CurrentTaskLedger {
    Missing,
    Readable(String),
    Unverified(String),
}

enum LedgerRecordError {
    Malformed,
    Schema,
}

#[derive(Debug, Deserialize, Serialize)]
struct RuleCounts {
    passed: usize,
    failed: usize,
    warning: usize,
    skipped: usize,
    not_applicable: usize,
    unverified: usize,
    overridden: usize,
    waived: usize,
}

#[derive(Debug, Serialize)]
struct TaskEvidence<'a> {
    task_id: &'a str,
    agent: &'static str,
    profile: &'a str,
    commit: Option<String>,
    rules: RuleCounts,
    results: &'a [EnforcementResult],
    commands: &'a [commands::CommandEvidence],
    overrides: &'a [crate::policy::overrides::OverrideRecord],
    waivers: &'a [crate::policy::waivers::Waiver],
    coverage: Vec<commands::CoverageEvidence>,
    policy_sources: &'a [String],
    policy_version: &'static str,
    policy_digest: String,
    binary_version: &'static str,
    platform: String,
    containment_version: &'static str,
    started_at_ms: u128,
    finished_at_ms: u128,
    touched_files_digest: String,
    config_digest: String,
    tier: &'a str,
}

struct EvidenceMeta<'a> {
    root: &'a Path,
    session_id: Option<&'a str>,
    profile: &'a str,
    paths: &'a [String],
    config_digest: &'a str,
    started_at_ms: u128,
    finished_at_ms: u128,
    tier: &'a str,
}

#[derive(Debug, Deserialize)]
struct StoredTaskEvidence {
    task_id: String,
    results: Vec<EnforcementResult>,
    commands: Vec<commands::CommandEvidence>,
    #[serde(default)]
    coverage: Vec<commands::CoverageEvidence>,
    policy_version: String,
    binary_version: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    containment_version: Option<String>,
    touched_files_digest: String,
    config_digest: String,
    #[serde(default)]
    tier: Option<String>,
}

struct InternalGateAdapter;

impl HookAdapter for InternalGateAdapter {
    fn parse_request(
        &self,
        _event: crate::adapter::HookEvent,
        _stdin_json: &str,
    ) -> Result<crate::adapter::HookRequest, String> {
        Err("internal gate adapter does not parse harness input".to_string())
    }

    fn encode_response(
        &self,
        event: crate::adapter::HookEvent,
        response: HookResponse,
    ) -> Result<crate::adapter::EncodedResponse, String> {
        if event != crate::adapter::HookEvent::Stop {
            return Err("internal gate adapter only supports Stop".to_string());
        }
        let (body, exit_code) = match response {
            HookResponse::Summary(_) => (String::new(), 0),
            HookResponse::BlockStop { reason } => (reason, 2),
            _ => return Err("internal gate adapter received an invalid response".to_string()),
        };
        Ok(crate::adapter::EncodedResponse {
            body,
            stream: crate::adapter::OutputStream::Stdout,
            exit_code,
        })
    }
}

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let adapter = ClaudeAdapter;
    run_with_adapter(input, output, &adapter)
}

/// Run the complete gate immediately before an agent executes `git commit`.
///
/// A matching successful full-tier record is reused for the same session and
/// exact file/config state, so a denied commit retry does not rerun unchanged
/// tests. `Ok(None)` means the commit may proceed; `Ok(Some(reason))` means the
/// full gate found a blocking failure.
pub(crate) fn run_pre_commit_gate(
    root: &Path,
    session_id: Option<&str>,
) -> Result<Option<String>, String> {
    run_pre_commit_gate_with_budget(root, session_id, commands::STOP_COMMAND_BUDGET)
}

fn run_pre_commit_gate_with_budget(
    root: &Path,
    session_id: Option<&str>,
    command_budget: Duration,
) -> Result<Option<String>, String> {
    let paths = check_paths(root)?;
    if matching_full_evidence(root, session_id, &paths).is_some() {
        return Ok(None);
    }
    let payload = serde_json::json!({
        "cwd": root,
        "session_id": session_id,
        "check": true,
        "tier": "full",
    });
    let mut input = std::io::Cursor::new(payload.to_string());
    let mut output = Vec::new();
    let code = run_inner_with_options(
        &mut input,
        &mut output,
        &InternalGateAdapter,
        crate::adapter::HookEvent::Stop,
        command_budget,
        true,
    )?;
    if code == ExitCode::SUCCESS {
        return Ok(None);
    }
    let reason = String::from_utf8(output)
        .map_err(|_| "pre-commit gate produced non-UTF-8 output".to_string())?;
    Ok(Some(reason.trim().to_string()))
}

/// Run Stop with an explicitly selected harness adapter.
pub fn run_with_adapter(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    run_for_event(input, output, adapter, crate::adapter::HookEvent::Stop)
}

/// Run Stop checks for a Codex subagent stop event.
pub fn run_subagent_stop_with_adapter(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    run_for_event(
        input,
        output,
        adapter,
        crate::adapter::HookEvent::SubagentStop,
    )
}

fn run_for_event(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
) -> ExitCode {
    match run_inner(input, output, adapter, event) {
        Ok(code) => code,
        Err(reason) => {
            let _ = writeln!(
                std::io::stderr(),
                "stop failed: entity=hook reason={reason} retryable=true"
            );
            ExitCode::SUCCESS
        }
    }
}

fn run_inner(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
) -> Result<ExitCode, String> {
    run_inner_with_budget(input, output, adapter, event, commands::STOP_COMMAND_BUDGET)
}

fn run_inner_with_budget(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
    command_budget: Duration,
) -> Result<ExitCode, String> {
    run_inner_with_options(input, output, adapter, event, command_budget, false)
}

fn run_inner_with_options(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
    command_budget: Duration,
    pre_commit: bool,
) -> Result<ExitCode, String> {
    debug_assert_eq!(tiers::for_hook(Hook::Stop), Tier::Targeted);
    let started_at_ms = unix_ms();
    let hook_input = read_input(input)?;
    let root = resolve_root(hook_input.cwd.as_deref())?;
    let config_snapshot = commands::load_snapshot(&root);
    let workspace_error = config_snapshot.settings.as_ref().ok().and_then(|settings| {
        settings
            .validate_workspace(hook_input.workspace.as_deref())
            .err()
    });
    let (paths, had_edits, ledger_issue) = if hook_input.check {
        (check_paths(&root)?, false, None)
    } else {
        let touched = touched_paths(&root, hook_input.session_id.as_deref())?;
        (touched.files, touched.had_edits, touched.ledger_issue)
    };
    let configured = configured_executables(config_snapshot.settings.as_ref().ok());
    let claims_only = !hook_input.check
        && !had_edits
        && crate::checks::claims::has_verification_claims(
            hook_input.transcript_path.as_deref().map(Path::new),
            &configured,
        );
    if !hook_input.check && !had_edits && !claims_only && workspace_error.is_none() {
        return Ok(ExitCode::SUCCESS);
    }
    let (profile, registry, overrides, waivers, compatibility, policy_sources) =
        crate::policy::load_profiled_registry(&root)?;
    let run_file_checks = hook_input.check || had_edits;
    let mut results = if run_file_checks {
        rerun_checks(&paths)
    } else {
        Vec::new()
    };
    if let Some(reason) = ledger_issue.as_deref() {
        results.push(current_task_ledger_unverified(reason));
    }
    let touched: BTreeSet<String> = paths
        .iter()
        .filter_map(|path| relative_path(&root, path))
        .collect();
    if run_file_checks {
        let intent = read_intent(&root, hook_input.session_id.as_deref());
        let baseline = read_diff_baseline(&root, hook_input.session_id.as_deref());
        results.extend(crate::checks::diff::evaluate(
            &root,
            &touched,
            baseline.as_ref(),
            intent.as_deref(),
        ));
        results.extend(rerun_python_checks(&paths));
        results.extend(crate::checks::languages::scan(&paths));
        results.extend(crate::checks::structure::scan(&paths));
        results.extend(crate::checks::modules::scan(&paths));
        results.extend(crate::checks::naming::scan(&paths));
        results.extend(crate::checks::boundary::scan(&paths));
        results.extend(crate::checks::logging::scan(&paths));
        results.extend(crate::checks::determinism::scan(&paths));
        results.extend(crate::checks::ui::scan(&paths));
        results.extend(crate::checks::justification::scan(&paths));
        results.extend(crate::checks::construction::scan(&paths));
        results.extend(crate::checks::endpoints::scan(&paths));
        results.extend(crate::checks::auth::scan(&paths));
    }
    let tier = effective_tier(hook_input.tier.as_deref());
    let mut budget = commands::ExecutionBudget::new(command_budget);
    let (mut command_run, coverage) = run_repository_commands(
        &root,
        config_snapshot.settings.as_ref(),
        hook_input.workspace.as_deref(),
        Some(tier),
        &paths,
        &mut budget,
    );
    if budget.is_exhausted() {
        command_run.results.push(commands::budget_unverified());
    }
    if budget.containment_failed() {
        command_run.results.push(commands::containment_unverified());
    }
    if trusted_config_changed(&root, &config_snapshot) {
        command_run
            .results
            .push(commands::config_mutation_unverified());
    }
    bind_command_provenance(&config_snapshot.digest, &paths, &mut command_run.evidence);
    let mut post_policy_command_gate_results =
        take_post_policy_command_gate_results(&mut command_run.results, pre_commit);
    if pre_commit {
        post_policy_command_gate_results.extend(
            coverage
                .iter()
                .filter(|item| item.status != "passed" && item.status != "not_applicable")
                .map(|item| commands::coverage_failure(&item.workspace_id, &item.status)),
        );
    }
    results.extend(command_run.results);
    results.extend(commands::coverage_results(&coverage));
    if !hook_input.check {
        let mut claim_evidence = command_run.evidence.clone();
        claim_evidence.extend(
            matching_full_evidence(&root, hook_input.session_id.as_deref(), &paths)
                .unwrap_or_default(),
        );
        results.push(crate::checks::claims::evaluate(
            hook_input.transcript_path.as_deref().map(Path::new),
            &claim_evidence,
            &configured,
        ));
    }
    if compatibility == crate::policy::config_version::Compatibility::LegacyMissing {
        results.push(legacy_version_result());
    }
    crate::policy::profile::apply_resolved_results(&registry, &mut results);
    crate::policy::overrides::apply_results(&overrides, &mut results);
    crate::policy::waivers::apply(&waivers, &mut results);
    if trusted_config_changed(&root, &config_snapshot)
        && !results
            .iter()
            .chain(&post_policy_command_gate_results)
            .any(is_config_result)
    {
        let mut mutation = commands::config_mutation_unverified();
        if pre_commit {
            mutation.status = Status::Failed;
            mutation.severity = Severity::Error;
        }
        results.push(mutation);
    }
    results.append(&mut post_policy_command_gate_results);
    if let Some(reason) = workspace_error {
        results.push(commands::invalid_workspace(&reason));
    }
    append_task_evidence(
        EvidenceMeta {
            root: &root,
            session_id: hook_input.session_id.as_deref(),
            profile: &profile,
            paths: &paths,
            config_digest: &config_snapshot.digest,
            started_at_ms,
            finished_at_ms: unix_ms(),
            tier,
        },
        &results,
        &command_run.evidence,
        &coverage,
        &policy_sources,
        &overrides,
        &waivers,
    )?;

    // Evidence persistence is part of the authorization transaction. If the
    // trusted config path changed while the first record was being made
    // durable, append a non-reusable denial record before deciding the gate.
    if trusted_config_changed(&root, &config_snapshot) && !results.iter().any(is_config_result) {
        let mut mutation = commands::config_mutation_unverified();
        if pre_commit {
            mutation.status = Status::Failed;
            mutation.severity = Severity::Error;
        }
        results.push(mutation);
        append_task_evidence(
            EvidenceMeta {
                root: &root,
                session_id: hook_input.session_id.as_deref(),
                profile: &profile,
                paths: &paths,
                config_digest: &config_snapshot.digest,
                started_at_ms,
                finished_at_ms: unix_ms(),
                tier,
            },
            &results,
            &command_run.evidence,
            &coverage,
            &policy_sources,
            &overrides,
            &waivers,
        )?;
    }

    let failures: Vec<&EnforcementResult> = results
        .iter()
        .filter(|result| result.is_failure() && result.severity == Severity::Error)
        .collect();
    if failures.is_empty() || hook_input.stop_hook_active {
        write_summary(output, adapter, event, &results)?;
        return Ok(ExitCode::SUCCESS);
    }
    write_block_decision(output, adapter, event, &failures)
}

fn effective_tier(tier: Option<&str>) -> &str {
    tier.unwrap_or_else(|| match tiers::for_hook(Hook::Stop) {
        Tier::Fast => "fast",
        Tier::Targeted => "targeted",
        Tier::Full => "full",
    })
}

fn select_coverage_commands(
    coverage: &[commands::CoverageCommand],
    workspace: Option<&str>,
) -> Vec<commands::CoverageCommand> {
    coverage
        .iter()
        .filter(|command| workspace.is_none_or(|id| command.workspace_id == id))
        .cloned()
        .collect()
}

// Executable names the repository configures as required commands. Claim matching
// is limited to these so backticked prose cannot invent an unprovable command.
fn configured_executables(settings: Option<&commands::Settings>) -> Vec<String> {
    let Some(settings) = settings else {
        return Vec::new();
    };
    let structured = settings
        .structured
        .iter()
        .filter_map(|command| command.argv.first().cloned());
    let flat = settings
        .commands
        .iter()
        .filter_map(|line| shlex::split(line)?.first().cloned());
    structured.chain(flat).collect()
}

fn legacy_version_result() -> EnforcementResult {
    EnforcementResult {
        rule_id: "config-version-compatible".to_string(),
        status: Status::Unverified,
        severity: Severity::Error,
        message: "Config version is missing; legacy compatibility was accepted. Run `lgtm init`."
            .to_string(),
        locations: Vec::new(),
        remediation: Some("Run `lgtm init` to add the current config version pin.".to_string()),
        evidence: ResultEvidence {
            check: "config.version".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

fn run_repository_commands(
    root: &Path,
    settings: Result<&commands::Settings, &String>,
    workspace: Option<&str>,
    tier: Option<&str>,
    touched_paths: &[String],
    budget: &mut commands::ExecutionBudget,
) -> (commands::RunResults, Vec<commands::CoverageEvidence>) {
    match settings {
        Ok(configured) if !configured.structured.is_empty() => {
            let selected: Vec<_> = configured
                .structured
                .iter()
                .filter(|command| workspace.is_none_or(|id| command.workspace_id == id))
                .filter(|command| tier.is_none_or(|selected| command.tier == selected))
                .filter(|command| workspace_touched(root, &command.cwd, touched_paths))
                .cloned()
                .collect();
            let command_run = commands::run_structured_with_budget(root, &selected, budget);
            let coverage = if tier == Some("full") {
                let selected = select_coverage_commands(&configured.coverage, workspace);
                commands::run_coverage_with_budget(root, &selected, budget)
            } else {
                commands::run_coverage(root, &[])
            };
            (command_run, coverage)
        }
        Ok(configured) if !configured.commands.is_empty() => (
            commands::RunResults {
                results: vec![commands::config_unverified(
                    "legacy config requires `lgtm init --migrate-config`",
                )],
                evidence: Vec::new(),
            },
            commands::run_coverage(root, &[]),
        ),
        Ok(configured) => {
            let command_run = commands::run_structured_with_budget(root, &[], budget);
            let coverage = if tier == Some("full") {
                let selected = select_coverage_commands(&configured.coverage, workspace);
                commands::run_coverage_with_budget(root, &selected, budget)
            } else {
                commands::run_coverage(root, &[])
            };
            (command_run, coverage)
        }
        Err(reason) => (
            commands::RunResults {
                results: vec![commands::config_unverified(reason)],
                evidence: Vec::new(),
            },
            commands::run_coverage(root, &[]),
        ),
    }
}

fn workspace_touched(root: &Path, cwd: &Path, touched_paths: &[String]) -> bool {
    if touched_paths.is_empty() {
        return true;
    }
    let workspace = root.join(cwd);
    touched_paths
        .iter()
        .any(|path| Path::new(path).starts_with(&workspace))
}

fn bind_command_provenance(
    config_digest: &str,
    paths: &[String],
    evidence: &mut [commands::CommandEvidence],
) {
    let touched_files_digest = digest_paths(paths);
    for item in evidence {
        item.config_digest = Some(config_digest.to_string());
        item.touched_files_digest = Some(touched_files_digest.clone());
        item.policy_version = Some(crate::policy::POLICY_BUNDLE_VERSION.to_string());
        item.binary_version = Some(env!("CARGO_PKG_VERSION").to_string());
    }
}

fn matching_full_evidence(
    root: &Path,
    session_id: Option<&str>,
    paths: &[String],
) -> Option<Vec<commands::CommandEvidence>> {
    let session_id = session_id?;
    // Reuse is authorization, not just a digest lookup: revalidate that the
    // current path is a trusted regular file (or an absent default config) and
    // parse the exact bytes whose digest is compared with durable evidence.
    let snapshot = commands::load_snapshot(root);
    let settings = snapshot.settings.as_ref().ok()?;
    if !settings.commands.is_empty() && settings.structured.is_empty() {
        return None;
    }
    let selected_commands = settings
        .structured
        .iter()
        .filter(|command| command.tier == "full")
        .filter(|command| workspace_touched(root, &command.cwd, paths))
        .collect::<Vec<_>>();
    let expected_files = digest_paths(paths);
    let raw = crate::fsutil::read_optional_bounded(
        &root.join(".lgtm/evidence/evidence.jsonl"),
        MAX_TASK_EVIDENCE_BYTES,
    );
    let record = raw.lines().rev().find_map(|line| {
        let record: StoredTaskEvidence = serde_json::from_str(line).ok()?;
        (record.task_id == session_id
            && record.tier.as_deref() == Some("full")
            && record.policy_version == crate::policy::POLICY_BUNDLE_VERSION
            && record.binary_version == env!("CARGO_PKG_VERSION")
            && record.platform.as_deref() == Some(commands::platform_id().as_str())
            && record.containment_version.as_deref() == Some(commands::CONTAINMENT_VERSION))
        .then_some(record)
    })?;
    if record.config_digest != snapshot.digest || record.touched_files_digest != expected_files {
        return None;
    }

    full_record_passed(&record, &selected_commands, &settings.coverage).then_some(record.commands)
}

fn full_record_passed(
    record: &StoredTaskEvidence,
    selected_commands: &[&commands::StructuredCommand],
    expected_coverage: &[commands::CoverageCommand],
) -> bool {
    if record
        .results
        .iter()
        .any(is_non_reusable_command_gate_result)
        || record
            .results
            .iter()
            .any(|result| result.is_failure() && result.severity == Severity::Error)
    {
        return false;
    }

    let passed_required_results = record
        .results
        .iter()
        .filter(|result| {
            commands::is_required_command_result(result) && result.status == Status::Passed
        })
        .count();
    if passed_required_results != selected_commands.len()
        || record.commands.len() != selected_commands.len()
    {
        return false;
    }
    if !record
        .commands
        .iter()
        .zip(selected_commands)
        .all(|(evidence, expected)| {
            evidence.exit_code == Some(0)
                && evidence.started_at_ms.is_some()
                && evidence.finished_at_ms.is_some()
                && evidence.argv == expected.argv
                && evidence.cwd.as_deref() == Some(expected.cwd.to_string_lossy().as_ref())
                && evidence.workspace_id.as_deref() == Some(expected.workspace_id.as_str())
        })
    {
        return false;
    }

    if expected_coverage.is_empty() {
        return record.coverage.len() == 1 && record.coverage[0].status == "not_applicable";
    }
    record.coverage.len() == expected_coverage.len()
        && record
            .coverage
            .iter()
            .zip(expected_coverage)
            .all(|(evidence, expected)| coverage_obligation_passed(evidence, expected))
}

fn coverage_obligation_passed(
    evidence: &commands::CoverageEvidence,
    expected: &commands::CoverageCommand,
) -> bool {
    evidence.status == "passed"
        && evidence.measured_at_ms.is_some()
        && evidence.workspace_id == expected.workspace_id
        && evidence.tool.as_deref() == expected.argv.first().map(String::as_str)
        && evidence.scope.as_deref() == Some(expected.scope.as_str())
        && expected.line_threshold_percent.is_none_or(|threshold| {
            evidence
                .line_percent
                .is_some_and(|value| value >= f64::from(threshold))
        })
        && expected.branch_threshold_percent.is_none_or(|threshold| {
            evidence
                .branch_percent
                .is_some_and(|value| value >= f64::from(threshold))
        })
}

fn trusted_config_changed(root: &Path, original: &commands::ConfigSnapshot) -> bool {
    if original.settings.is_err() {
        return false;
    }
    let current = commands::load_snapshot(root);
    current.settings.is_err() || current.digest != original.digest
}

#[cfg(test)]
fn stored_gate_passed(record: &StoredTaskEvidence) -> bool {
    let has_blocking_failure = record
        .results
        .iter()
        .any(|result| result.is_failure() && result.severity == Severity::Error);
    let command_results_verified = record.results.iter().all(|result| {
        result.rule_id != "required-repository-commands"
            || !matches!(result.status, Status::Failed | Status::Unverified)
    });
    let commands_verified = record
        .commands
        .iter()
        .all(|command| command.exit_code == Some(0));
    let coverage_verified = record
        .coverage
        .iter()
        .all(|coverage| matches!(coverage.status.as_str(), "passed" | "not_applicable"));
    !has_blocking_failure && command_results_verified && commands_verified && coverage_verified
}

fn is_aggregate_budget_result(result: &EnforcementResult) -> bool {
    result.evidence.check == commands::budget_unverified().evidence.check
}

fn is_config_result(result: &EnforcementResult) -> bool {
    result.evidence.check == commands::config_unverified("").evidence.check
}

fn is_non_reusable_command_gate_result(result: &EnforcementResult) -> bool {
    is_aggregate_budget_result(result)
        || is_config_result(result)
        || (commands::is_required_command_result(result)
            && result.status != Status::Passed
            && result.status != Status::NotApplicable)
        || (result.evidence.check == "command.coverage"
            && result.status != Status::Passed
            && result.status != Status::NotApplicable)
}

fn take_post_policy_command_gate_results(
    results: &mut Vec<EnforcementResult>,
    pre_commit: bool,
) -> Vec<EnforcementResult> {
    let mut protected = Vec::new();
    results.retain(|result| {
        if is_non_reusable_command_gate_result(result) {
            let mut result = result.clone();
            if pre_commit {
                result.status = Status::Failed;
                result.severity = Severity::Error;
            }
            protected.push(result);
            false
        } else {
            true
        }
    });
    protected
}

fn read_diff_baseline(root: &Path, session_id: Option<&str>) -> Option<BTreeSet<String>> {
    let path = root.join(".lgtm/evidence/current-task.baseline.json");
    let raw = crate::fsutil::read_optional_bounded(&path, 256 * 1_024);
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let recorded = value.get("session_id").and_then(|value| value.as_str());
    if recorded != session_id {
        return None;
    }
    value
        .get("diff_files_before")?
        .as_array()?
        .iter()
        .map(|file| file.as_str().map(str::to_string))
        .collect()
}

fn relative_path(root: &Path, path: &str) -> Option<String> {
    Path::new(path)
        .strip_prefix(root)
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn read_intent(root: &Path, session_id: Option<&str>) -> Option<String> {
    let path = root.join(".lgtm/evidence/current-task.intent.json");
    let raw = crate::fsutil::read_optional_bounded(&path, 4 * 1_024);
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let recorded = value.get("session_id").and_then(|value| value.as_str());
    (recorded == session_id)
        .then(|| value.get("intent")?.as_str().map(str::to_string))
        .flatten()
}

fn read_input(input: &mut impl Read) -> Result<HookInput, String> {
    let mut raw = String::new();
    input
        .take(MAX_PAYLOAD_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read stdin ({error})"))?;
    if raw.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err("stdin exceeds maximum size".to_string());
    }
    if raw.trim().is_empty() {
        return Ok(HookInput::default());
    }
    serde_json::from_str(&raw).map_err(|error| format!("parse stdin ({error})"))
}

fn resolve_root(cwd: Option<&str>) -> Result<PathBuf, String> {
    crate::hooks::root::resolve(cwd)
}

fn read_current_task_ledger(path: &Path) -> CurrentTaskLedger {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return CurrentTaskLedger::Missing;
        }
        Err(_) => {
            return CurrentTaskLedger::Unverified(
                "current-task evidence could not be inspected".to_string(),
            );
        }
    };
    if !metadata.file_type().is_file() {
        return CurrentTaskLedger::Unverified(
            "current-task evidence is not a regular file".to_string(),
        );
    }

    let file = match crate::fsutil::open_regular_file(path) {
        Ok(Some(file)) => file,
        Ok(None) => {
            return CurrentTaskLedger::Unverified(
                "current-task evidence became unavailable".to_string(),
            );
        }
        Err(_) => {
            return CurrentTaskLedger::Unverified(
                "current-task evidence could not be read".to_string(),
            );
        }
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_LEDGER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        return CurrentTaskLedger::Unverified(
            "current-task evidence could not be read".to_string(),
        );
    }
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return CurrentTaskLedger::Unverified(
            "current-task evidence exceeds the maximum size".to_string(),
        );
    }
    match String::from_utf8(bytes) {
        Ok(raw) if raw.is_empty() => {
            CurrentTaskLedger::Unverified("current-task evidence is empty".to_string())
        }
        Ok(raw) => CurrentTaskLedger::Readable(raw),
        Err(_) => {
            CurrentTaskLedger::Unverified("current-task evidence is not valid UTF-8".to_string())
        }
    }
}

fn current_task_ledger_unverified(reason: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: "current-task-evidence".to_string(),
        status: Status::Unverified,
        severity: Severity::Error,
        message: format!("Current-task edit evidence is unavailable: {reason}."),
        locations: Vec::new(),
        remediation: Some(
            "Repair or regenerate current-task evidence, then retry Stop.".to_string(),
        ),
        evidence: ResultEvidence {
            check: "evidence.current-task".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

fn resolve_touched_candidate(
    root: &Path,
    raw: &str,
    candidates: &mut BTreeSet<String>,
    resolved: &mut BTreeMap<String, Option<String>>,
) -> Result<Option<String>, ()> {
    if let Some(path) = resolved.get(raw) {
        return Ok(path.clone());
    }
    if candidates.len() >= MAX_TOUCHED_PATHS {
        return Err(());
    }
    candidates.insert(raw.to_string());
    #[cfg(test)]
    TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
    let path = canonical_contained_file(root, raw);
    resolved.insert(raw.to_string(), path.clone());
    Ok(path)
}

fn marker_shape(record: &EditRecord) -> bool {
    record.edited_file.is_none()
        && record.result.rule_id == "current-task-evidence"
        && record.result.status == Status::Unverified
        && record.result.severity == Severity::Error
        && record.result.locations.is_empty()
        && record.result.remediation.is_none()
        && record.result.evidence.check == "evidence.current-task"
        && record.result.evidence.tool_version.is_none()
        && record.result.evidence.finding_descriptions.is_empty()
}

fn is_current_task_marker(record: &EditRecord) -> bool {
    record.truncated && marker_shape(record)
}

fn is_retention_marker(record: &EditRecord) -> bool {
    is_current_task_marker(record)
        && record.result.message == CURRENT_TASK_RETENTION_MESSAGE
        && !record.persistence_failed
}

fn is_persistence_failure_marker(record: &EditRecord) -> bool {
    is_current_task_marker(record)
        && record.session_id.is_none()
        && record.result.message == CURRENT_TASK_PERSISTENCE_MESSAGE
        && record.persistence_failed
}

fn validate_ledger_object_shape(
    value: &serde_json::Value,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    if object
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err(());
    }
    if required
        .iter()
        .any(|field| !object.keys().any(|key| key == *field))
    {
        return Err(());
    }
    Ok(())
}

fn validate_edit_record_shape(value: &serde_json::Value) -> Result<(), ()> {
    validate_ledger_object_shape(
        value,
        &[
            "session_id",
            "edited_file",
            "result",
            "truncated",
            "persistence_failed",
        ],
        &["session_id", "result"],
    )?;
    let session_id = value.get("session_id").ok_or(())?;
    if !session_id.is_null()
        && session_id
            .as_str()
            .is_none_or(|session_id| session_id.is_empty())
    {
        return Err(());
    }
    let result = value.get("result").ok_or(())?;
    validate_ledger_object_shape(
        result,
        &[
            "rule_id",
            "status",
            "severity",
            "message",
            "locations",
            "remediation",
            "evidence",
        ],
        &[
            "rule_id",
            "status",
            "severity",
            "message",
            "locations",
            "evidence",
        ],
    )?;
    let result_object = result.as_object().ok_or(())?;
    if result_object
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|rule_id| rule_id.is_empty())
    {
        return Err(());
    }
    let locations = result
        .get("locations")
        .and_then(serde_json::Value::as_array)
        .ok_or(())?;
    if locations.len() > MAX_TOUCHED_PATHS {
        return Err(());
    }
    for location in locations {
        validate_ledger_object_shape(location, &["file", "line"], &["file"])?;
        let location = location.as_object().ok_or(())?;
        if !location["file"].is_string()
            || location
                .get("line")
                .is_some_and(|line| !line.is_null() && line.as_u64().is_none_or(|line| line == 0))
        {
            return Err(());
        }
    }
    let evidence = result.get("evidence").ok_or(())?;
    validate_ledger_object_shape(
        evidence,
        &["check", "tool_version", "finding_descriptions"],
        &["check"],
    )?;
    let evidence = evidence.as_object().ok_or(())?;
    if evidence
        .get("check")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|check| check.is_empty())
    {
        return Err(());
    }
    Ok(())
}

fn parse_edit_record(line: &str) -> Result<EditRecord, LedgerRecordError> {
    let value = serde_json::from_str::<serde_json::Value>(line)
        .map_err(|_| LedgerRecordError::Malformed)?;
    validate_edit_record_shape(&value).map_err(|_| LedgerRecordError::Schema)?;
    let has_persistence_metadata = value.get("persistence_failed").is_some();
    let record =
        serde_json::from_value::<EditRecord>(value).map_err(|_| LedgerRecordError::Schema)?;
    if marker_shape(&record) && !record.truncated && !record.persistence_failed {
        return Err(LedgerRecordError::Schema);
    }
    if marker_shape(&record)
        && record.truncated
        && !record.persistence_failed
        && record.result.message == CURRENT_TASK_RETENTION_MESSAGE
        && has_persistence_metadata
    {
        return Err(LedgerRecordError::Schema);
    }
    if (record.persistence_failed || record.result.message == CURRENT_TASK_PERSISTENCE_MESSAGE)
        && !is_persistence_failure_marker(&record)
    {
        return Err(LedgerRecordError::Schema);
    }
    Ok(record)
}

fn truncation_reason(record: &EditRecord) -> &'static str {
    if is_persistence_failure_marker(record) {
        CURRENT_TASK_PERSISTENCE_REASON
    } else if is_retention_marker(record) {
        CURRENT_TASK_RETENTION_REASON
    } else {
        CURRENT_TASK_RECORD_TRUNCATION_REASON
    }
}

/// Return the stable precedence of a typed loss marker. The parent-owned
/// aggregation must not let a later, less-specific survivor hide an earlier
/// persistence or retention signal.
fn truncation_priority(record: &EditRecord) -> Option<u8> {
    if is_persistence_failure_marker(record) {
        Some(3)
    } else if is_retention_marker(record) {
        Some(2)
    } else if record.truncated || record.persistence_failed {
        Some(1)
    } else {
        None
    }
}

fn retain_truncation_issue(issue: &mut Option<(u8, &'static str)>, record: &EditRecord) {
    let Some(priority) = truncation_priority(record) else {
        return;
    };
    let replace = match *issue {
        Some((current, _)) => priority > current,
        None => true,
    };
    if replace {
        *issue = Some((priority, truncation_reason(record)));
    }
}

/// Keep malformed/schema/path-limit failures visible rather than letting a
/// later record overwrite them. They all remain action-required; typed loss
/// markers are aggregated separately with their explicit precedence.
fn retain_structural_issue(issue: &mut Option<String>, reason: &str) {
    if issue.is_none() {
        *issue = Some(reason.to_string());
    }
}

fn touched_paths(root: &Path, session_id: Option<&str>) -> Result<TouchedPaths, String> {
    let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
    let mut paths = BTreeSet::new();
    let mut raw_candidates = BTreeSet::new();
    let mut resolved_candidates = BTreeMap::new();
    let mut had_edits = false;
    let mut structural_issue = None;
    let mut truncation_issue = None;
    let raw = match read_current_task_ledger(&ledger) {
        CurrentTaskLedger::Missing => String::new(),
        CurrentTaskLedger::Readable(raw) => raw,
        CurrentTaskLedger::Unverified(reason) => {
            return Ok(TouchedPaths {
                files: Vec::new(),
                had_edits: true,
                ledger_issue: Some(reason),
            });
        }
    };
    'records: for (record_index, line) in raw.lines().enumerate() {
        if record_index >= MAX_LEDGER_RECORDS {
            had_edits = true;
            retain_structural_issue(
                &mut structural_issue,
                "current-task evidence exceeds the bounded record limit; repair or regenerate evidence",
            );
            break;
        }
        let record = match parse_edit_record(line) {
            Ok(record) => record,
            Err(LedgerRecordError::Malformed) => {
                had_edits = true;
                retain_structural_issue(
                    &mut structural_issue,
                    "current-task evidence contains malformed records",
                );
                continue;
            }
            Err(LedgerRecordError::Schema) => {
                had_edits = true;
                retain_structural_issue(
                    &mut structural_issue,
                    "current-task evidence contains invalid record schema",
                );
                continue;
            }
        };
        if record.truncated || record.persistence_failed {
            had_edits = true;
            retain_truncation_issue(&mut truncation_issue, &record);
        }
        if record.session_id.as_deref() != session_id {
            continue;
        }
        had_edits = true;
        if let Some(file) = record.edited_file.as_deref() {
            let resolved = match resolve_touched_candidate(
                root,
                file,
                &mut raw_candidates,
                &mut resolved_candidates,
            ) {
                Ok(path) => path,
                Err(()) => {
                    retain_structural_issue(
                        &mut structural_issue,
                        "current-task evidence contains too many edited paths",
                    );
                    break 'records;
                }
            };
            if let Some(path) = resolved {
                if paths.len() < MAX_TOUCHED_PATHS || paths.contains(&path) {
                    paths.insert(path);
                } else {
                    retain_structural_issue(
                        &mut structural_issue,
                        "current-task evidence contains too many edited paths",
                    );
                }
                continue;
            }
        }
        if record.result.rule_id != "no-committed-secrets" {
            continue;
        }
        for location in record.result.locations {
            let resolved = match resolve_touched_candidate(
                root,
                &location.file,
                &mut raw_candidates,
                &mut resolved_candidates,
            ) {
                Ok(path) => path,
                Err(()) => {
                    retain_structural_issue(
                        &mut structural_issue,
                        "current-task evidence contains too many edited paths",
                    );
                    break 'records;
                }
            };
            if let Some(path) = resolved {
                if paths.len() < MAX_TOUCHED_PATHS || paths.contains(&path) {
                    paths.insert(path);
                } else {
                    retain_structural_issue(
                        &mut structural_issue,
                        "current-task evidence contains too many edited paths",
                    );
                    break;
                }
            }
        }
    }
    Ok(TouchedPaths {
        files: paths.into_iter().collect(),
        had_edits,
        ledger_issue: structural_issue
            .or_else(|| truncation_issue.map(|(_, reason)| reason.to_string())),
    })
}

fn check_paths(root: &Path) -> Result<Vec<String>, String> {
    let mut paths = Vec::new();
    collect_check_paths(root, root, 0, &mut paths)?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect_check_paths(
    root: &Path,
    current: &Path,
    depth: usize,
    paths: &mut Vec<String>,
) -> Result<(), String> {
    if depth > 8 || paths.len() >= 512 {
        return Ok(());
    }
    let entries =
        std::fs::read_dir(current).map_err(|error| format!("scan check paths ({error})"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read check path ({error})"))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect check path ({error})"))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            let relative = path.strip_prefix(root).unwrap_or(&path);
            if relative != Path::new("tests/fixtures/semgrep-python")
                && !matches!(
                    name.as_str(),
                    ".git"
                        | ".lgtm"
                        | ".claude"
                        | "target"
                        | "node_modules"
                        | "dist"
                        | "build"
                        | "vendor"
                        | ".venv"
                        | "venv"
                )
            {
                collect_check_paths(root, &path, depth + 1, paths)?;
            }
        } else if metadata.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|extension| {
                    matches!(
                        extension,
                        "py" | "rs"
                            | "ts"
                            | "tsx"
                            | "js"
                            | "jsx"
                            | "go"
                            | "sh"
                            | "tf"
                            | "yaml"
                            | "yml"
                            | "json"
                    )
                })
            && path.strip_prefix(root).is_ok()
        {
            paths.push(path.to_string_lossy().into_owned());
        }
    }
    Ok(())
}

fn canonical_contained_file(root: &Path, file: &str) -> Option<String> {
    let path = Path::new(file);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let metadata = std::fs::symlink_metadata(&candidate).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let canonical = std::fs::canonicalize(candidate).ok()?;
    canonical
        .starts_with(root)
        .then(|| canonical.to_string_lossy().into_owned())
}

fn rerun_checks(paths: &[String]) -> Vec<EnforcementResult> {
    if paths.is_empty() {
        return vec![EnforcementResult {
            rule_id: "no-committed-secrets".to_string(),
            status: Status::Unverified,
            severity: Severity::Error,
            message:
                "Secret scan unverified: no scannable edited files were recorded for this session."
                    .to_string(),
            locations: Vec::new(),
            remediation: Some(
                "Edit or write the intended repository file again, then retry Stop.".to_string(),
            ),
            evidence: ResultEvidence {
                check: "gitleaks.detect".to_string(),
                tool_version: None,
                finding_descriptions: Vec::new(),
            },
        }];
    }
    let mut result = gitleaks::scan(paths);
    if result.locations.is_empty() {
        result.locations = paths
            .iter()
            .map(|file| Location {
                file: file.clone(),
                line: None,
            })
            .collect();
    }
    vec![result]
}

fn rerun_python_checks(paths: &[String]) -> Vec<EnforcementResult> {
    let python_files: Vec<String> = paths
        .iter()
        .filter(|path| path.ends_with(".py"))
        .cloned()
        .collect();
    if python_files.is_empty() {
        return Vec::new();
    }
    let mut results = ruff::scan(&python_files);
    results.extend(semgrep::scan(&python_files));
    results
}

fn append_task_evidence(
    metadata: EvidenceMeta<'_>,
    results: &[EnforcementResult],
    commands: &[commands::CommandEvidence],
    coverage: &[commands::CoverageEvidence],
    policy_sources: &[String],
    overrides: &[crate::policy::overrides::OverrideRecord],
    waivers: &[crate::policy::waivers::Waiver],
) -> Result<(), String> {
    let root = metadata.root;
    let directory = root.join(".lgtm/evidence");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create evidence directory ({error})"))?;
    let task_id = metadata.session_id.unwrap_or("unknown-session");
    let record = TaskEvidence {
        task_id,
        agent: "claude-code",
        profile: metadata.profile,
        commit: None,
        rules: count_results(results),
        results,
        commands,
        overrides,
        waivers,
        coverage: coverage.to_vec(),
        policy_sources,
        policy_version: crate::policy::POLICY_BUNDLE_VERSION,
        policy_digest: crate::policy::bundle_digest(),
        binary_version: env!("CARGO_PKG_VERSION"),
        platform: commands::platform_id(),
        containment_version: commands::CONTAINMENT_VERSION,
        started_at_ms: metadata.started_at_ms,
        finished_at_ms: metadata.finished_at_ms,
        touched_files_digest: digest_paths(metadata.paths),
        config_digest: metadata.config_digest.to_string(),
        tier: metadata.tier,
    };
    let mut line =
        serde_json::to_string(&record).map_err(|error| format!("serialize evidence ({error})"))?;
    validate_evidence(&line)?;
    line.push('\n');
    append_bounded_regular(&directory.join("evidence.jsonl"), line.as_bytes())
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn digest_paths(paths: &[String]) -> String {
    let mut material = String::new();
    for path in paths {
        material.push_str(path);
        material.push('\0');
        material.push_str(&crate::fsutil::read_optional_bounded(
            Path::new(path),
            256 * 1024,
        ));
        material.push('\0');
    }
    digest_bytes(&material)
}

fn digest_bytes(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn validate_evidence(record: &str) -> Result<(), String> {
    let schema = serde_json::from_str(EVIDENCE_SCHEMA_JSON)
        .map_err(|error| format!("parse embedded evidence schema ({error})"))?;
    let artifact = serde_json::from_str(record)
        .map_err(|error| format!("parse serialized evidence ({error})"))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| format!("compile embedded evidence schema ({error})"))?;
    let errors: Vec<_> = validator
        .iter_errors(&artifact)
        .map(|error| error.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("evidence schema violations: {}", errors.join("; ")))
    }
}

fn append_bounded_regular(path: &Path, line: &[u8]) -> Result<(), String> {
    if line.len() as u64 > MAX_TASK_EVIDENCE_BYTES {
        return Err("single evidence record exceeds maximum size".to_string());
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err("evidence path is not a regular file".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| file.write_all(line))
                .map_err(|error| format!("append evidence ({error})"));
        }
        Err(error) => return Err(format!("inspect evidence ({error})")),
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("open evidence ({error})"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect open evidence ({error})"))?;
    if !metadata.is_file() {
        return Err("evidence path is not a regular file".to_string());
    }
    if metadata.len().saturating_add(line.len() as u64) > MAX_TASK_EVIDENCE_BYTES {
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line))
            .map_err(|error| format!("rotate evidence ({error})"))?;
        return Ok(());
    }

    let mut existing = Vec::with_capacity(metadata.len() as usize);
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut existing))
        .map_err(|error| format!("read evidence tail ({error})"))?;
    let (valid_prefix_len, needs_delimiter) = recoverable_evidence_prefix(&existing);
    let projected_size = (valid_prefix_len as u64)
        .saturating_add(u64::from(needs_delimiter))
        .saturating_add(line.len() as u64);
    if projected_size > MAX_TASK_EVIDENCE_BYTES {
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)))
            .and_then(|_| file.write_all(line))
            .map_err(|error| format!("rotate evidence ({error})"))?;
        return Ok(());
    }

    file.set_len(valid_prefix_len as u64)
        .and_then(|()| file.seek(SeekFrom::Start(valid_prefix_len as u64)))
        .and_then(|_| {
            if needs_delimiter {
                file.write_all(b"\n")?;
            }
            file.write_all(line)
        })
        .map_err(|error| format!("append evidence ({error})"))
}

fn recoverable_evidence_prefix(existing: &[u8]) -> (usize, bool) {
    if existing.is_empty() || existing.ends_with(b"\n") {
        return (existing.len(), false);
    }
    let tail_start = existing
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    if serde_json::from_slice::<serde_json::Value>(&existing[tail_start..]).is_ok() {
        (existing.len(), true)
    } else {
        (tail_start, false)
    }
}

fn count_results(results: &[EnforcementResult]) -> RuleCounts {
    let mut counts = RuleCounts {
        passed: 0,
        failed: 0,
        warning: 0,
        skipped: 0,
        not_applicable: 0,
        unverified: 0,
        overridden: 0,
        waived: 0,
    };
    for result in results {
        match result.status {
            Status::Passed => counts.passed += 1,
            Status::Failed => counts.failed += 1,
            Status::Warning => counts.warning += 1,
            Status::Skipped => counts.skipped += 1,
            Status::NotApplicable => counts.not_applicable += 1,
            Status::Unverified => counts.unverified += 1,
            Status::Overridden => counts.overridden += 1,
            Status::Waived => counts.waived += 1,
        }
    }
    counts
}

fn write_summary(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
    results: &[EnforcementResult],
) -> Result<(), String> {
    let counts = count_results(results);
    let clean = counts.failed == 0 && counts.warning == 0 && counts.unverified == 0;
    let mut lines = if clean {
        vec!["lgtm: passed".to_string()]
    } else {
        vec![format!(
            "lgtm: action required (failed={} warning={} unverified={})",
            counts.failed, counts.warning, counts.unverified
        )]
    };
    for result in results
        .iter()
        .filter(|result| result.status == Status::Failed)
    {
        let label = if result.severity == Severity::Error {
            "FAILED"
        } else {
            "REVIEW"
        };
        lines.push(format!(
            "{label} {}: {}",
            result.rule_id,
            bounded_summary_message(&result.message)
        ));
    }
    for result in results
        .iter()
        .filter(|result| result.status == Status::Unverified)
    {
        lines.push(format!(
            "UNVERIFIED {}: {}",
            result.rule_id,
            bounded_summary_message(&result.message)
        ));
    }
    for result in results
        .iter()
        .filter(|result| result.status == Status::Warning)
    {
        lines.push(format!(
            "REVIEW {}: {}",
            result.rule_id,
            bounded_summary_message(&result.message)
        ));
    }
    let encoded = adapter.encode_response(event, HookResponse::Summary(lines.join("\n")))?;
    crate::adapter::emit(output, &mut std::io::stderr(), &encoded)
        .map_err(|error| format!("write summary ({error})"))
}

fn bounded_summary_message(message: &str) -> String {
    let sanitized: String = message
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .collect();
    if sanitized.chars().count() <= MAX_SUMMARY_MESSAGE_CHARS {
        return sanitized;
    }
    let mut bounded: String = sanitized
        .chars()
        .take(MAX_SUMMARY_MESSAGE_CHARS.saturating_sub(1))
        .collect();
    bounded.push('…');
    bounded
}

fn write_block_decision(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    event: crate::adapter::HookEvent,
    failures: &[&EnforcementResult],
) -> Result<ExitCode, String> {
    use crate::adapter::HookResponse;
    let mut reason = "lgtm Stop blocked: unresolved MUST violations:".to_string();
    for result in failures {
        reason.push_str(&format!("\n- {}: {}", result.rule_id, result.message));
        if let Some(remediation) = &result.remediation {
            reason.push_str(&format!("\n  Repair: {remediation}"));
        }
    }
    let encoded = adapter.encode_response(event, HookResponse::BlockStop { reason })?;
    crate::adapter::emit(output, &mut std::io::stderr(), &encoded)
        .map_err(|error| format!("write block decision ({error})"))?;
    Ok(ExitCode::from(encoded.exit_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct TestTempDir {
        path: PathBuf,
    }

    static TEST_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let unique = TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("lgtm-stop-{label}-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temporary root creatable");
            Self { path }
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn run_stop_fixture(root: &Path, session_id: &str) -> (ExitCode, String) {
        let payload = serde_json::json!({
            "cwd": root,
            "session_id": session_id,
        });
        let mut input = std::io::Cursor::new(payload.to_string());
        let mut output = Vec::new();
        let code = run_inner_with_budget(
            &mut input,
            &mut output,
            &ClaudeAdapter,
            crate::adapter::HookEvent::Stop,
            Duration::ZERO,
        )
        .expect("Stop fixture runs");
        (
            code,
            String::from_utf8(output).expect("Stop fixture output is UTF-8"),
        )
    }

    fn assert_stop_reports_unverified(root: &Path, session_id: &str) {
        let (code, output) = run_stop_fixture(root, session_id);
        assert_eq!(
            code,
            ExitCode::SUCCESS,
            "Unverified is surfaced, not blocked"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(
            output.contains("UNVERIFIED current-task-evidence"),
            "{output}"
        );
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    fn write_ledger(root: &Path, contents: &[u8]) {
        let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        std::fs::write(ledger, contents).expect("ledger fixture writable");
    }

    fn valid_ledger_line_with_message(
        session_id: &str,
        edited_file: &str,
        status: &str,
        message: &str,
    ) -> String {
        format!(
            "{}\n",
            serde_json::json!({
                "session_id": session_id,
                "edited_file": edited_file,
                "result": {
                    "rule_id": "no-committed-secrets",
                    "status": status,
                    "severity": "error",
                    "message": message,
                    "locations": [],
                    "remediation": null,
                    "evidence": {
                        "check": "gitleaks.detect",
                        "tool_version": null,
                        "finding_descriptions": []
                    }
                }
            })
        )
    }

    fn valid_ledger_line(session_id: &str, edited_file: &str, status: &str) -> String {
        valid_ledger_line_with_message(session_id, edited_file, status, "finding")
    }

    fn exact_size_valid_ledger(target_bytes: usize) -> Vec<u8> {
        let empty = valid_ledger_line_with_message("exact-session", "src/exact.py", "passed", "");
        let message = "x".repeat(target_bytes - empty.len());
        let line =
            valid_ledger_line_with_message("exact-session", "src/exact.py", "passed", &message);
        assert_eq!(line.len(), target_bytes, "exact ledger fixture size");
        line.into_bytes()
    }

    fn write_path_cap_ledger(root: &Path, session_id: &str, count: usize) {
        let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        let mut records = String::new();
        for index in 0..count {
            let relative = format!("touched/{index}.py");
            let path = root.join(&relative);
            std::fs::create_dir_all(path.parent().expect("touched parent"))
                .expect("touched directory");
            std::fs::write(&path, "value = 1\n").expect("touched source");
            records.push_str(&valid_ledger_line(session_id, &relative, "failed"));
        }
        std::fs::write(ledger, records).expect("path-cap ledger");
    }

    fn write_location_path_cap_ledger(root: &Path, session_id: &str, count: usize) {
        let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        let mut records = String::new();
        for index in 0..count {
            let relative = format!("located/{index}.py");
            let path = root.join(&relative);
            std::fs::create_dir_all(path.parent().expect("located parent"))
                .expect("located directory");
            std::fs::write(&path, "value = 1\n").expect("located source");
            records.push_str(&format!(
                "{}\n",
                serde_json::json!({
                    "session_id": session_id,
                    "edited_file": null,
                    "result": {
                        "rule_id": "no-committed-secrets",
                        "status": "failed",
                        "severity": "error",
                        "message": "finding",
                        "locations": [{"file": relative, "line": 1}],
                        "remediation": null,
                        "evidence": {
                            "check": "gitleaks.detect",
                            "tool_version": null,
                            "finding_descriptions": []
                        }
                    }
                })
            ));
        }
        std::fs::write(ledger, records).expect("location path-cap ledger");
    }

    fn write_mixed_path_cap_ledger(root: &Path, session_id: &str) {
        let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        let mut records = String::new();
        for index in 0..256 {
            let relative = format!("mixed-edited/{index}.py");
            let path = root.join(&relative);
            std::fs::create_dir_all(path.parent().expect("mixed-edited parent"))
                .expect("mixed-edited directory");
            std::fs::write(&path, "value = 1\n").expect("mixed edited source");
            records.push_str(&valid_ledger_line(session_id, &relative, "failed"));
        }
        for index in 0..257 {
            let relative = format!("mixed-located/{index}.py");
            let path = root.join(&relative);
            std::fs::create_dir_all(path.parent().expect("mixed-located parent"))
                .expect("mixed-located directory");
            std::fs::write(&path, "value = 1\n").expect("mixed located source");
            records.push_str(&format!(
                "{}\n",
                serde_json::json!({
                    "session_id": session_id,
                    "edited_file": null,
                    "result": {
                        "rule_id": "no-committed-secrets",
                        "status": "failed",
                        "severity": "error",
                        "message": "finding",
                        "locations": [{"file": relative, "line": 1}],
                        "remediation": null,
                        "evidence": {
                            "check": "gitleaks.detect",
                            "tool_version": null,
                            "finding_descriptions": []
                        }
                    }
                })
            ));
        }
        std::fs::write(ledger, records).expect("mixed path-cap ledger");
    }

    fn stored_record(
        severity: Severity,
        exit_code: Option<i32>,
        coverage_status: &str,
    ) -> StoredTaskEvidence {
        StoredTaskEvidence {
            task_id: "task".to_string(),
            results: vec![EnforcementResult {
                rule_id: "review".to_string(),
                status: Status::Failed,
                severity,
                message: "review finding".to_string(),
                locations: Vec::new(),
                remediation: None,
                evidence: ResultEvidence {
                    check: "native.review".to_string(),
                    tool_version: None,
                    finding_descriptions: Vec::new(),
                },
            }],
            commands: vec![commands::CommandEvidence {
                command: "check".to_string(),
                exit_code,
                duration_ms: 1,
                argv: Vec::new(),
                cwd: None,
                workspace_id: None,
                config_digest: None,
                touched_files_digest: None,
                policy_version: None,
                binary_version: None,
                started_at_ms: None,
                finished_at_ms: None,
            }],
            coverage: vec![commands::CoverageEvidence {
                workspace_id: "workspace".to_string(),
                status: coverage_status.to_string(),
                tool: None,
                scope: None,
                line_percent: None,
                branch_percent: None,
                measured_at_ms: None,
            }],
            policy_version: crate::policy::POLICY_BUNDLE_VERSION.to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            platform: Some(commands::platform_id()),
            containment_version: Some(commands::CONTAINMENT_VERSION.to_string()),
            touched_files_digest: "files".to_string(),
            config_digest: "config".to_string(),
            tier: Some("full".to_string()),
        }
    }

    #[test]
    fn reusable_gate_allows_warning_failures_but_rejects_incomplete_tool_evidence() {
        assert!(stored_gate_passed(&stored_record(
            Severity::Warning,
            Some(0),
            "passed"
        )));
        assert!(!stored_gate_passed(&stored_record(
            Severity::Error,
            Some(0),
            "passed"
        )));
        for exit_code in [None, Some(1)] {
            assert!(!stored_gate_passed(&stored_record(
                Severity::Warning,
                exit_code,
                "passed"
            )));
        }
        for coverage_status in ["failed", "unverified"] {
            assert!(!stored_gate_passed(&stored_record(
                Severity::Warning,
                Some(0),
                coverage_status
            )));
        }
        for status in [Status::Failed, Status::Unverified] {
            let mut incomplete = stored_record(Severity::Warning, Some(0), "passed");
            incomplete.commands.clear();
            incomplete.results[0].rule_id = "required-repository-commands".to_string();
            incomplete.results[0].status = status;
            assert!(!stored_gate_passed(&incomplete));
        }
    }

    #[test]
    fn evidence_tail_recovery_only_delimits_valid_json() {
        assert_eq!(recoverable_evidence_prefix(b"{\"valid\":true}"), (14, true));
        assert_eq!(
            recoverable_evidence_prefix(b"{\"valid\":true}\n{\"broken\":"),
            (15, false)
        );
    }

    #[test]
    fn summary_messages_are_sanitized_and_bounded() {
        let message = format!("{}\rsecret", "é".repeat(MAX_SUMMARY_MESSAGE_CHARS));
        let bounded = bounded_summary_message(&message);
        assert_eq!(bounded.chars().count(), MAX_SUMMARY_MESSAGE_CHARS);
        assert!(bounded.ends_with('…'));
        assert!(!bounded.contains('\r'));
    }

    #[test]
    fn full_check_excludes_the_intentional_semgrep_violation_corpus() {
        let root =
            std::env::temp_dir().join(format!("lgtm-stop-check-paths-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(root.join("tests/fixtures/semgrep-python"))
            .expect("fixture directory");
        std::fs::write(root.join("src/app.py"), "value = 1\n").expect("source file");
        std::fs::write(
            root.join("tests/fixtures/semgrep-python/violations.py"),
            "eval(input())\n",
        )
        .expect("fixture file");

        let paths = check_paths(&root).expect("check paths");
        assert!(paths.iter().any(|path| path.ends_with("src/app.py")));
        assert!(!paths.iter().any(|path| path.contains("semgrep-python")));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn current_task_ledger_invalid_inputs_are_unverified_not_no_edits() {
        let cases = [
            (
                "malformed",
                b"{not-json}\n".to_vec(),
                "current-task evidence contains malformed records",
            ),
            (
                "invalid-utf8",
                vec![0xff, 0xfe],
                "current-task evidence is not valid UTF-8",
            ),
            ("empty", Vec::new(), "current-task evidence is empty"),
            (
                "whitespace",
                b" \n".to_vec(),
                "current-task evidence contains malformed records",
            ),
            (
                "schema-invalid",
                serde_json::json!({
                    "session_id": "schema-invalid",
                    "edited_file": "src/app.py",
                    "result": {
                        "rule_id": "no-committed-secrets",
                        "status": "failed",
                        "severity": "error",
                        "message": "missing locations",
                        "evidence": {"check": "gitleaks.detect"}
                    }
                })
                .to_string()
                .into_bytes(),
                "current-task evidence contains invalid record schema",
            ),
            (
                "unknown-field",
                format!(
                    "{}\n",
                    serde_json::json!({
                        "session_id": "other-session",
                        "edited_file": "src/app.py",
                        "unexpected": true,
                        "result": {
                            "rule_id": "no-committed-secrets",
                            "status": "passed",
                            "severity": "error",
                            "message": "clean",
                            "locations": [],
                            "evidence": {"check": "gitleaks.detect"}
                        }
                    })
                )
                .into_bytes(),
                "current-task evidence contains invalid record schema",
            ),
            (
                "empty-check",
                format!(
                    "{}\n",
                    serde_json::json!({
                        "session_id": "other-session",
                        "edited_file": "src/app.py",
                        "result": {
                            "rule_id": "no-committed-secrets",
                            "status": "passed",
                            "severity": "error",
                            "message": "clean",
                            "locations": [],
                            "evidence": {"check": ""}
                        }
                    })
                )
                .into_bytes(),
                "current-task evidence contains invalid record schema",
            ),
            (
                "empty-rule-id",
                format!(
                    "{}\n",
                    serde_json::json!({
                        "session_id": "other-session",
                        "edited_file": "src/app.py",
                        "result": {
                            "rule_id": "",
                            "status": "passed",
                            "severity": "error",
                            "message": "clean",
                            "locations": [],
                            "evidence": {"check": "gitleaks.detect"}
                        }
                    })
                )
                .into_bytes(),
                "current-task evidence contains invalid record schema",
            ),
            (
                "line-zero",
                format!(
                    "{}\n",
                    serde_json::json!({
                        "session_id": "other-session",
                        "edited_file": "src/app.py",
                        "result": {
                            "rule_id": "no-committed-secrets",
                            "status": "failed",
                            "severity": "error",
                            "message": "finding",
                            "locations": [{"file": "src/app.py", "line": 0}],
                            "evidence": {"check": "gitleaks.detect"}
                        }
                    })
                )
                .into_bytes(),
                "current-task evidence contains invalid record schema",
            ),
        ];
        for (label, contents, reason) in cases {
            let fixture = TestTempDir::new(label);
            write_ledger(&fixture.path, &contents);
            assert_stop_reports_unverified(&fixture.path, label);
            let (_, output) = run_stop_fixture(&fixture.path, label);
            assert!(output.contains(reason), "{output}");
        }
    }

    #[test]
    fn current_task_ledger_location_line_null_is_valid_but_other_non_numeric_values_are_not() {
        let make_record = |location: serde_json::Value| {
            serde_json::json!({
                "session_id": "line-session",
                "edited_file": null,
                "result": {
                    "rule_id": "no-committed-secrets",
                    "status": "failed",
                    "severity": "error",
                    "message": "finding",
                    "locations": [location],
                    "evidence": {"check": "gitleaks.detect"}
                }
            })
        };

        for (label, location) in [
            ("line-absent", serde_json::json!({"file": "src/app.py"})),
            (
                "line-null",
                serde_json::json!({"file": "src/app.py", "line": null}),
            ),
        ] {
            let fixture = TestTempDir::new(label);
            write_ledger(
                &fixture.path,
                format!("{}\n", make_record(location)).as_bytes(),
            );
            let touched = touched_paths(&fixture.path, Some("line-session"))
                .expect("optional location line parses");
            assert!(touched.had_edits);
            assert!(
                touched.ledger_issue.is_none(),
                "{label} must remain Stop-usable: {:?}",
                touched.ledger_issue
            );
        }

        for (label, line) in [
            ("line-zero", serde_json::json!(0)),
            ("line-negative", serde_json::json!(-1)),
            ("line-fractional", serde_json::json!(1.5)),
            ("line-string", serde_json::json!("1")),
            ("line-boolean", serde_json::json!(true)),
            ("line-object", serde_json::json!({})),
            ("line-array", serde_json::json!([])),
        ] {
            let fixture = TestTempDir::new(label);
            let location = serde_json::json!({"file": "src/app.py", "line": line});
            write_ledger(
                &fixture.path,
                format!("{}\n", make_record(location)).as_bytes(),
            );
            let touched = touched_paths(&fixture.path, Some("line-session"))
                .expect("invalid line remains a surfaced ledger issue");
            assert_eq!(
                touched.ledger_issue.as_deref(),
                Some("current-task evidence contains invalid record schema"),
                "{label} must remain schema-invalid"
            );
            assert!(touched.had_edits);
        }
    }

    #[test]
    fn invalid_ledger_remediation_requires_repair_not_deletion() {
        let result = current_task_ledger_unverified("malformed records");
        let remediation = result.remediation.expect("invalid ledger remediation");
        assert!(remediation.contains("Repair or regenerate"));
        assert!(!remediation.contains("remove"));
        assert!(!remediation.contains("delete"));
    }

    #[test]
    fn current_task_ledger_record_limit_is_unverified_not_no_edits() {
        let fixture = TestTempDir::new("record-limit");
        let contents = valid_ledger_line("other-session", "src/ignored.py", "passed")
            .repeat(MAX_LEDGER_RECORDS + 1);
        write_ledger(&fixture.path, contents.as_bytes());
        let (code, output) = run_stop_fixture(&fixture.path, "record-limit-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence exceeds the bounded record limit"),
            "{output}"
        );
        assert!(
            output.contains("UNVERIFIED current-task-evidence"),
            "{output}"
        );
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn exact_stop_record_cap_is_accepted_but_one_over_is_unverified() {
        let fixture = TestTempDir::new("record-cap-boundary");
        let record = valid_ledger_line("other-session", "src/ignored.py", "passed");
        let exact = record.repeat(MAX_LEDGER_RECORDS);
        write_ledger(&fixture.path, exact.as_bytes());
        let (code, output) = run_stop_fixture(&fixture.path, "record-cap-boundary-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.is_empty(),
            "exact record cap must remain accepted: {output}"
        );

        let one_over = format!("{exact}{record}");
        write_ledger(&fixture.path, one_over.as_bytes());
        let (code, output) = run_stop_fixture(&fixture.path, "record-cap-boundary-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence exceeds the bounded record limit"),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn exact_size_valid_current_task_ledger_is_readable() {
        let fixture = TestTempDir::new("exact-limit");
        let contents = exact_size_valid_ledger(MAX_LEDGER_BYTES as usize);
        write_ledger(&fixture.path, &contents);

        match read_current_task_ledger(
            &fixture
                .path
                .join(".lgtm/evidence/current-task.results.jsonl"),
        ) {
            CurrentTaskLedger::Readable(raw) => assert_eq!(raw.len(), MAX_LEDGER_BYTES as usize),
            CurrentTaskLedger::Missing => panic!("exact-size ledger must be readable"),
            CurrentTaskLedger::Unverified(reason) => {
                panic!("exact-size ledger must not be unverified: {reason}")
            }
        }
    }

    #[test]
    fn oversized_valid_current_task_ledger_is_rejected_for_size() {
        let fixture = TestTempDir::new("oversized-valid");
        let contents = exact_size_valid_ledger(MAX_LEDGER_BYTES as usize + 1);
        write_ledger(&fixture.path, &contents);

        match read_current_task_ledger(
            &fixture
                .path
                .join(".lgtm/evidence/current-task.results.jsonl"),
        ) {
            CurrentTaskLedger::Unverified(reason) => {
                assert!(reason.contains("exceeds the maximum size"), "{reason}");
            }
            CurrentTaskLedger::Missing => panic!("oversized ledger must be inspected"),
            CurrentTaskLedger::Readable(_) => panic!("one-byte-over ledger must be rejected"),
        }
        assert_stop_reports_unverified(&fixture.path, "exact-session");
    }

    #[test]
    fn absent_current_task_ledger_remains_silent_no_edits() {
        let fixture = TestTempDir::new("absent");
        let (code, output) = run_stop_fixture(&fixture.path, "absent-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(output.is_empty(), "absent ledger remains silent: {output}");
    }

    #[test]
    fn present_empty_current_task_ledger_is_unverified_not_no_edits() {
        let fixture = TestTempDir::new("empty-ledger");
        write_ledger(&fixture.path, b"");
        let (code, output) = run_stop_fixture(&fixture.path, "empty-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence is empty"),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn current_task_ledger_nonregular_input_is_unverified_not_no_edits() {
        let fixture = TestTempDir::new("nonregular");
        let ledger = fixture
            .path
            .join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(&ledger).expect("non-regular ledger fixture");
        assert_stop_reports_unverified(&fixture.path, "nonregular-session");
    }

    #[cfg(unix)]
    #[test]
    fn current_task_ledger_symlink_is_unverified_without_following() {
        let fixture = TestTempDir::new("symlink");
        let source = fixture.path.join("src/target.py");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "value = 1\n").expect("symlink target source");
        let target = fixture.path.join("target.jsonl");
        std::fs::write(
            &target,
            valid_ledger_line("symlink-session", "src/target.py", "passed"),
        )
        .expect("valid symlink target ledger");
        let ledger = fixture
            .path
            .join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        std::os::unix::fs::symlink(&target, &ledger).expect("ledger symlink");
        assert_stop_reports_unverified(&fixture.path, "symlink-session");
    }

    #[cfg(unix)]
    #[test]
    fn current_task_ledger_fifo_is_unverified_without_blocking() {
        let fixture = TestTempDir::new("fifo");
        let ledger = fixture
            .path
            .join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        let cpath = std::ffi::CString::new(ledger.as_os_str().as_encoded_bytes())
            .expect("FIFO path has no interior nul");
        // SAFETY: `mkfifo` receives a valid path and mode; the return value is
        // checked so no malformed fixture can silently pass.
        let result = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        assert_eq!(result, 0, "FIFO fixture must be creatable");
        let started = std::time::Instant::now();
        assert_stop_reports_unverified(&fixture.path, "fifo-session");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO inspection must remain non-blocking"
        );
    }

    #[test]
    fn current_task_ledger_loss_marker_from_other_session_is_unverified() {
        let fixture = TestTempDir::new("marker-global");
        let marker = serde_json::json!({
            "session_id": "other-session",
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_RETENTION_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        });
        write_ledger(&fixture.path, format!("{marker}\n").as_bytes());
        assert_stop_reports_unverified(&fixture.path, "current-session");
        let touched = touched_paths(&fixture.path, Some("current-session"))
            .expect("other-session marker parses");
        assert!(touched.files.is_empty());
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(
                "current-task evidence was truncated at the bounded retention limit; repair or regenerate evidence"
            )
        );
        let (_, output) = run_stop_fixture(&fixture.path, "current-session");
        assert!(
            output.contains(
                "current-task evidence was truncated at the bounded retention limit; repair or regenerate evidence"
            ),
            "{output}"
        );
    }

    #[test]
    fn current_task_ledger_marker_preserves_surviving_path_identity() {
        let fixture = TestTempDir::new("marker-path");
        let source = fixture.path.join("src/app.py");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "value = 1\n").expect("source fixture");
        let marker = serde_json::json!({
            "session_id": "marker-session",
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_RETENTION_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        });
        write_ledger(
            &fixture.path,
            format!(
                "{}\n{}",
                marker,
                valid_ledger_line("marker-session", "src/app.py", "failed")
            )
            .as_bytes(),
        );

        let touched = touched_paths(&fixture.path, Some("marker-session")).expect("marker parses");
        assert!(touched.had_edits);
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(
                "current-task evidence was truncated at the bounded retention limit; repair or regenerate evidence"
            )
        );
        assert_eq!(touched.files, vec![source.to_string_lossy().into_owned()]);
        let (_, output) = run_stop_fixture(&fixture.path, "marker-session");
        assert!(
            output.contains(
                "current-task evidence was truncated at the bounded retention limit; repair or regenerate evidence"
            ),
            "{output}"
        );
    }

    #[test]
    fn current_task_ledger_detail_truncation_is_not_retention_marker() {
        let fixture = TestTempDir::new("detail-truncation");
        let source = fixture.path.join("src/app.py");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "value = 1\n").expect("source fixture");
        let record = serde_json::json!({
            "session_id": "detail-session",
            "edited_file": "src/app.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "failed",
                "severity": "error",
                "message": "details were compacted",
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "gitleaks.detect",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let touched = touched_paths(&fixture.path, Some("detail-session"))
            .expect("detail-truncated record parses");
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_RECORD_TRUNCATION_REASON)
        );
        assert_eq!(touched.files, vec![source.to_string_lossy().into_owned()]);
        let (_, output) = run_stop_fixture(&fixture.path, "detail-session");
        assert!(
            output.contains(CURRENT_TASK_RECORD_TRUNCATION_REASON),
            "{output}"
        );
        assert!(!output.contains(CURRENT_TASK_RETENTION_REASON), "{output}");
    }

    #[test]
    fn current_task_ledger_structural_marker_with_wrong_message_is_detail_truncation() {
        let fixture = TestTempDir::new("structural-marker");
        let record = serde_json::json!({
            "session_id": "structural-session",
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": "evidence was truncated",
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let touched = touched_paths(&fixture.path, Some("structural-session"))
            .expect("structural marker parses");
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_RECORD_TRUNCATION_REASON)
        );
        let (_, output) = run_stop_fixture(&fixture.path, "structural-session");
        assert!(
            output.contains(CURRENT_TASK_RECORD_TRUNCATION_REASON),
            "{output}"
        );
        assert!(!output.contains(CURRENT_TASK_RETENTION_REASON), "{output}");
    }

    #[test]
    fn current_task_ledger_detail_truncation_from_other_session_is_global() {
        let fixture = TestTempDir::new("detail-truncation-global");
        let record = serde_json::json!({
            "session_id": "other-session",
            "edited_file": "src/other.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "failed",
                "severity": "error",
                "message": "details were compacted",
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "gitleaks.detect",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let touched = touched_paths(&fixture.path, Some("current-session"))
            .expect("other-session detail truncation parses");
        assert!(touched.files.is_empty());
        assert!(touched.had_edits);
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_RECORD_TRUNCATION_REASON)
        );
        let (_, output) = run_stop_fixture(&fixture.path, "current-session");
        assert!(
            output.contains(CURRENT_TASK_RECORD_TRUNCATION_REASON),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn current_task_persistence_failure_marker_is_global() {
        let fixture = TestTempDir::new("persistence-global");
        let record = serde_json::json!({
            "session_id": null,
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_PERSISTENCE_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true,
            "persistence_failed": true
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let touched = touched_paths(&fixture.path, Some("current-session"))
            .expect("persistence marker parses");
        assert!(touched.files.is_empty());
        assert!(touched.had_edits);
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_PERSISTENCE_REASON)
        );
        let (_, output) = run_stop_fixture(&fixture.path, "current-session");
        assert!(output.contains(CURRENT_TASK_PERSISTENCE_REASON), "{output}");
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn current_task_loss_marker_precedence_survives_later_truncated_survivors() {
        let persistence = serde_json::json!({
            "session_id": null,
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_PERSISTENCE_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true,
            "persistence_failed": true
        });
        let retention = |session_id: &str| {
            serde_json::json!({
                "session_id": session_id,
                "edited_file": null,
                "result": {
                    "rule_id": "current-task-evidence",
                    "status": "unverified",
                    "severity": "error",
                    "message": CURRENT_TASK_RETENTION_MESSAGE,
                    "locations": [],
                    "remediation": null,
                    "evidence": {
                        "check": "evidence.current-task",
                        "tool_version": null,
                        "finding_descriptions": []
                    }
                },
                "truncated": true
            })
        };
        let detail = |session_id: &str| {
            serde_json::json!({
                "session_id": session_id,
                "edited_file": null,
                "result": {
                    "rule_id": "no-committed-secrets",
                    "status": "failed",
                    "severity": "error",
                    "message": "details were compacted",
                    "locations": [],
                    "remediation": null,
                    "evidence": {
                        "check": "gitleaks.detect",
                        "tool_version": null,
                        "finding_descriptions": []
                    }
                },
                "truncated": true
            })
        };

        let persistence_fixture = TestTempDir::new("precedence-persistence");
        write_ledger(
            &persistence_fixture.path,
            format!(
                "{}\n{}\n{}\n",
                persistence,
                retention("later-session"),
                detail("later-session")
            )
            .as_bytes(),
        );
        let touched = touched_paths(&persistence_fixture.path, Some("later-session"))
            .expect("persistence precedence fixture parses");
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_PERSISTENCE_REASON)
        );
        let (_, output) = run_stop_fixture(&persistence_fixture.path, "later-session");
        assert!(output.contains(CURRENT_TASK_PERSISTENCE_REASON), "{output}");
        assert!(!output.contains(CURRENT_TASK_RETENTION_REASON), "{output}");
        assert!(
            !output.contains(CURRENT_TASK_RECORD_TRUNCATION_REASON),
            "{output}"
        );

        let retention_fixture = TestTempDir::new("precedence-retention");
        write_ledger(
            &retention_fixture.path,
            format!(
                "{}\n{}\n",
                retention("retention-session"),
                detail("retention-session")
            )
            .as_bytes(),
        );
        let touched = touched_paths(&retention_fixture.path, Some("retention-session"))
            .expect("retention precedence fixture parses");
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some(CURRENT_TASK_RETENTION_REASON)
        );
        let (_, output) = run_stop_fixture(&retention_fixture.path, "retention-session");
        assert!(output.contains(CURRENT_TASK_RETENTION_REASON), "{output}");
        assert!(
            !output.contains(CURRENT_TASK_RECORD_TRUNCATION_REASON),
            "{output}"
        );
        assert!(
            !output.contains(CURRENT_TASK_PERSISTENCE_REASON),
            "{output}"
        );
    }

    #[test]
    fn persistence_marker_metadata_permutations_are_schema_invalid_in_stop() {
        let valid = serde_json::json!({
            "session_id": null,
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_PERSISTENCE_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true,
            "persistence_failed": true
        });
        type ValueMutation = fn(&mut serde_json::Value);
        let cases: [(&str, ValueMutation); 8] = [
            ("missing-truncated", |value| {
                value
                    .as_object_mut()
                    .expect("marker object")
                    .remove("truncated");
            }),
            ("false-truncated", |value| {
                value["truncated"] = serde_json::json!(false)
            }),
            ("missing-persistence-failed", |value| {
                value
                    .as_object_mut()
                    .expect("marker object")
                    .remove("persistence_failed");
            }),
            ("false-persistence-failed", |value| {
                value["persistence_failed"] = serde_json::json!(false)
            }),
            ("non-null-session", |value| {
                value["session_id"] = serde_json::json!("session")
            }),
            ("empty-session", |value| {
                value["session_id"] = serde_json::json!("")
            }),
            ("wrong-message", |value| {
                value["result"]["message"] = serde_json::json!("not the persistence marker")
            }),
            ("ordinary-record-with-persistence-failed", |value| {
                value["session_id"] = serde_json::json!("ordinary-session");
                value["edited_file"] = serde_json::json!("src/ordinary.py");
                value["result"]["rule_id"] = serde_json::json!("no-committed-secrets");
                value["result"]["status"] = serde_json::json!("failed");
                value["result"]["message"] = serde_json::json!("finding");
                value
                    .as_object_mut()
                    .expect("ordinary record object")
                    .remove("truncated");
            }),
        ];

        for (label, mutate) in cases {
            let mut record = valid.clone();
            mutate(&mut record);
            let fixture = TestTempDir::new(label);
            write_ledger(&fixture.path, format!("{record}\n").as_bytes());
            let (code, output) = run_stop_fixture(&fixture.path, label);
            assert_eq!(
                code,
                ExitCode::SUCCESS,
                "invalid marker remains a surfaced issue"
            );
            assert!(
                output.contains("current-task evidence contains invalid record schema"),
                "{label}: {output}"
            );
            assert!(
                output.contains("lgtm: action required"),
                "{label}: {output}"
            );
            assert!(!output.contains("lgtm: passed"), "{label}: {output}");
        }
    }

    #[test]
    fn retention_marker_with_false_persistence_metadata_is_schema_invalid_in_stop() {
        let fixture = TestTempDir::new("retention-false-persistence");
        let record = serde_json::json!({
            "session_id": "retention-session",
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": CURRENT_TASK_RETENTION_MESSAGE,
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true,
            "persistence_failed": false
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let (code, output) = run_stop_fixture(&fixture.path, "retention-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence contains invalid record schema"),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn current_task_ledger_keeps_valid_session_path_identity() {
        let fixture = TestTempDir::new("valid");
        let source = fixture.path.join("src/app.py");
        let ledger = fixture
            .path
            .join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::create_dir_all(ledger.parent().expect("ledger parent"))
            .expect("evidence directory");
        std::fs::write(&source, "value = 1\n").expect("source fixture");
        let result = EnforcementResult {
            rule_id: "no-committed-secrets".to_string(),
            status: Status::Failed,
            severity: Severity::Error,
            message: "finding".to_string(),
            locations: Vec::new(),
            remediation: None,
            evidence: ResultEvidence {
                check: "gitleaks.detect".to_string(),
                tool_version: None,
                finding_descriptions: Vec::new(),
            },
        };
        std::fs::write(
            &ledger,
            format!(
                "{}\n",
                serde_json::json!({
                    "session_id": "session",
                    "edited_file": "src/app.py",
                    "result": result,
                })
            ),
        )
        .expect("ledger fixture");

        let touched = touched_paths(&fixture.path, Some("session")).expect("valid ledger parses");
        assert!(touched.had_edits);
        assert!(touched.ledger_issue.is_none());
        assert_eq!(touched.files, vec![source.to_string_lossy().into_owned()]);
    }

    #[test]
    fn stop_production_checks_surviving_touched_path() {
        let fixture = TestTempDir::new("production-path");
        let source = fixture.path.join("src/App.tsx");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "const value: any = input;\n").expect("source fixture");
        write_ledger(
            &fixture.path,
            valid_ledger_line("production-path-session", "src/App.tsx", "passed").as_bytes(),
        );

        let (code, output) = run_stop_fixture(&fixture.path, "production-path-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(output.contains("typescript-no-any"), "{output}");
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");

        let evidence = std::fs::read_to_string(fixture.path.join(".lgtm/evidence/evidence.jsonl"))
            .expect("Stop persists task evidence");
        let record: serde_json::Value = serde_json::from_str(evidence.trim()).expect("evidence");
        let source = source.to_string_lossy().into_owned();
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["rule_id"] == "typescript-no-any"
                    && result["locations"].as_array().is_some_and(|locations| {
                        locations
                            .iter()
                            .any(|location| location["file"].as_str() == Some(source.as_str()))
                    })
            })
        }));
    }

    #[test]
    fn current_task_ledger_touched_paths_are_bounded() {
        let fixture = TestTempDir::new("path-cap");
        write_path_cap_ledger(&fixture.path, "path-cap-session", 512);
        let exact =
            touched_paths(&fixture.path, Some("path-cap-session")).expect("exact path-cap parses");
        assert_eq!(exact.files.len(), 512);
        assert!(exact.ledger_issue.is_none());
        assert!(exact.had_edits);

        write_path_cap_ledger(&fixture.path, "path-cap-session", 513);
        let exceeded = touched_paths(&fixture.path, Some("path-cap-session"))
            .expect("exceeded path-cap parses");
        assert_eq!(exceeded.files.len(), 512);
        assert!(exceeded.ledger_issue.is_some());
        assert!(exceeded.had_edits);
    }

    #[test]
    fn current_task_ledger_duplicate_raw_paths_use_the_resolution_cache() {
        let fixture = TestTempDir::new("duplicate-path-cache");
        write_path_cap_ledger(&fixture.path, "duplicate-path-cache-session", 512);
        let ledger = fixture
            .path
            .join(".lgtm/evidence/current-task.results.jsonl");
        let mut contents = std::fs::read_to_string(&ledger).expect("path-cap ledger readable");
        contents.push_str(&valid_ledger_line(
            "duplicate-path-cache-session",
            "touched/0.py",
            "failed",
        ));
        std::fs::write(&ledger, contents).expect("duplicate path ledger writable");
        TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.set(0));

        let touched = touched_paths(&fixture.path, Some("duplicate-path-cache-session"))
            .expect("duplicate path ledger parses");
        assert_eq!(touched.files.len(), 512);
        assert!(touched.ledger_issue.is_none());
        assert_eq!(
            TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.get()),
            512,
            "the duplicate 513th raw candidate must use the cached resolution"
        );
    }

    #[test]
    fn current_task_ledger_location_candidates_stop_before_the_next_resolution() {
        let fixture = TestTempDir::new("location-path-cap");
        write_location_path_cap_ledger(&fixture.path, "location-path-cap-session", 513);
        TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.set(0));

        let touched = touched_paths(&fixture.path, Some("location-path-cap-session"))
            .expect("location path-cap parses");
        assert_eq!(touched.files.len(), 512);
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some("current-task evidence contains too many edited paths")
        );
        assert!(touched.had_edits);
        assert_eq!(
            TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.get()),
            512,
            "the 513th raw candidate must not reach canonical resolution"
        );
    }

    #[test]
    fn current_task_ledger_rejects_over_limit_stored_locations() {
        let fixture = TestTempDir::new("over-limit-locations");
        let locations: Vec<_> = (0..=MAX_TOUCHED_PATHS)
            .map(|index| {
                serde_json::json!({
                    "file": format!("src/existing-{index}.py"),
                    "line": 1
                })
            })
            .collect();
        let record = serde_json::json!({
            "session_id": "over-limit-session",
            "edited_file": "src/existing.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "failed",
                "severity": "error",
                "message": "finding",
                "locations": locations,
                "evidence": {"check": "gitleaks.detect"}
            }
        });
        write_ledger(&fixture.path, format!("{record}\n").as_bytes());

        let (code, output) = run_stop_fixture(&fixture.path, "over-limit-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence contains invalid record schema"),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[test]
    fn current_task_ledger_accepts_exact_stored_location_bound() {
        let locations: Vec<_> = (0..MAX_TOUCHED_PATHS)
            .map(|index| {
                serde_json::json!({
                    "file": format!("src/existing-{index}.py"),
                    "line": 1
                })
            })
            .collect();
        let record = serde_json::json!({
            "session_id": "exact-location-session",
            "edited_file": "src/existing.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "failed",
                "severity": "error",
                "message": "finding",
                "locations": locations,
                "evidence": {"check": "gitleaks.detect"}
            }
        });

        let parsed = match parse_edit_record(&record.to_string()) {
            Ok(record) => record,
            Err(_) => panic!("exact stored location bound remains schema-valid"),
        };
        assert_eq!(parsed.result.locations.len(), MAX_TOUCHED_PATHS);
        assert_eq!(parsed.result.locations[0].file, "src/existing-0.py");
        assert_eq!(
            parsed.result.locations[MAX_TOUCHED_PATHS - 1].file,
            format!("src/existing-{}.py", MAX_TOUCHED_PATHS - 1)
        );
    }

    #[test]
    fn current_task_ledger_path_candidates_share_one_aggregate_budget() {
        let fixture = TestTempDir::new("mixed-path-cap");
        write_mixed_path_cap_ledger(&fixture.path, "mixed-path-cap-session");
        TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.set(0));

        let touched = touched_paths(&fixture.path, Some("mixed-path-cap-session"))
            .expect("mixed path-cap parses");
        assert_eq!(touched.files.len(), 512);
        assert_eq!(
            touched.ledger_issue.as_deref(),
            Some("current-task evidence contains too many edited paths")
        );
        assert_eq!(
            TOUCHED_PATH_RESOLUTION_ATTEMPTS.with(|attempts| attempts.get()),
            512,
            "edited-file and location candidates share the aggregate bound"
        );
    }

    #[test]
    fn aggregate_path_budget_overflow_reaches_stop_action_required() {
        let fixture = TestTempDir::new("mixed-path-production");
        let mut contents = String::new();
        for index in 0..=MAX_TOUCHED_PATHS {
            contents.push_str(&valid_ledger_line(
                "mixed-path-production-session",
                &format!("missing/{index}.py"),
                "failed",
            ));
        }
        write_ledger(&fixture.path, contents.as_bytes());

        let (code, output) = run_stop_fixture(&fixture.path, "mixed-path-production-session");
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(
            output.contains("current-task evidence contains too many edited paths"),
            "{output}"
        );
        assert!(output.contains("lgtm: action required"), "{output}");
        assert!(!output.contains("lgtm: passed"), "{output}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreadable_proc_ledger_is_unverified_without_reading_contents() {
        let state = read_current_task_ledger(Path::new("/proc/self/mem"));
        assert!(
            matches!(state, CurrentTaskLedger::Unverified(_)),
            "/proc/self/mem must fail as an unreadable ledger"
        );
    }

    #[test]
    fn aggregate_budget_unverified_result_cannot_report_passed() {
        let mut output = Vec::new();
        write_summary(
            &mut output,
            &ClaudeAdapter,
            crate::adapter::HookEvent::Stop,
            &[commands::budget_unverified()],
        )
        .expect("summary writes");
        let summary = String::from_utf8(output).expect("summary is UTF-8");
        assert!(summary.contains("lgtm: action required"));
        assert!(summary.contains("UNVERIFIED"));
        assert!(!summary.contains("lgtm: passed"));
    }

    #[test]
    fn incomplete_command_gate_evidence_is_not_reused_but_unrelated_unverified_is() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-full-evidence-reuse-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let evidence_path = root.join(".lgtm/evidence/evidence.jsonl");
        std::fs::create_dir_all(evidence_path.parent().expect("evidence parent"))
            .expect("evidence directory");
        let config_digest = digest_bytes("");
        let touched_files_digest = digest_paths(&[]);
        let record = |results: Vec<serde_json::Value>| {
            serde_json::json!({
                "task_id": "aggregate-budget",
                "rules": {
                    "passed": 0,
                    "failed": 0,
                    "warning": 0,
                    "skipped": 0,
                    "not_applicable": 0,
                    "unverified": results.iter().filter(|result| result["status"] == "unverified").count(),
                    "overridden": 0,
                    "waived": 0
                },
                "results": results,
                "commands": [],
                "coverage": [{
                    "workspace_id": "repository",
                    "status": "not_applicable",
                    "tool": null,
                    "scope": null,
                    "line_percent": null,
                    "branch_percent": null,
                    "measured_at_ms": null
                }],
                "policy_version": crate::policy::POLICY_BUNDLE_VERSION,
                "binary_version": env!("CARGO_PKG_VERSION"),
                "platform": commands::platform_id(),
                "containment_version": commands::CONTAINMENT_VERSION,
                "touched_files_digest": touched_files_digest,
                "config_digest": config_digest,
                "tier": "full"
            })
        };
        let mut incomplete_command = commands::config_unverified("ordinary command");
        incomplete_command.evidence.check = "command.required".to_string();
        let mut unrelated_unverified = commands::config_unverified("unrelated check");
        unrelated_unverified.evidence.check = "native.unrelated".to_string();
        let cases = [
            (
                vec![serde_json::to_value(commands::budget_unverified()).expect("cutoff result")],
                false,
            ),
            (
                vec![
                    serde_json::to_value(commands::config_unverified("invalid config"))
                        .expect("config result"),
                ],
                false,
            ),
            (
                vec![serde_json::to_value(incomplete_command).expect("command result")],
                false,
            ),
            (
                vec![serde_json::to_value(unrelated_unverified).expect("unrelated result")],
                true,
            ),
            (Vec::new(), true),
        ];

        for (results, reusable) in cases {
            std::fs::write(&evidence_path, format!("{}\n", record(results)))
                .expect("evidence record");
            assert_eq!(
                matching_full_evidence(&root, Some("aggregate-budget"), &[]).is_some(),
                reusable,
                "cutoff-specific evidence reuse decision"
            );
        }

        for (field, value) in [
            ("platform", "different-platform"),
            ("containment_version", "different-containment-version"),
            ("containment_version", "linux-isolated-subreaper-v1"),
        ] {
            let mut mismatched = record(Vec::new());
            mismatched[field] = serde_json::json!(value);
            std::fs::write(&evidence_path, format!("{mismatched}\n"))
                .expect("mismatched evidence record");
            assert!(
                matching_full_evidence(&root, Some("aggregate-budget"), &[]).is_none(),
                "{field} mismatch must prevent authorization reuse"
            );
        }

        std::fs::remove_dir_all(root).expect("temporary evidence directory removal");
    }

    #[cfg(unix)]
    #[test]
    fn pre_commit_gate_denies_aggregate_budget_exhaustion() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-pre-commit-budget-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm/bin")).expect("fixture directories");
        let command = root.join(".lgtm/bin/slow");
        std::fs::write(&command, "#!/bin/sh\nexec /bin/sleep 1\n").expect("fixture command");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
            .expect("fixture permissions");
        std::fs::write(
            root.join(".lgtm/config.json"),
            serde_json::json!({
                "version": "2",
                "profile": "prototype",
                "workspaces": [{
                    "id": "root",
                    "language": "shell",
                    "root": ".",
                    "commands": [{
                        "argv": [command.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "tier": "full",
                        "purpose": "test",
                        "source": "fixture",
                        "confidence": "high"
                    }],
                    "coverage": []
                }],
                "disabled_rules": [],
                "severity_overrides": {}
            })
            .to_string(),
        )
        .expect("fixture config");
        std::fs::write(
            root.join(".lgtm/waivers.json"),
            serde_json::json!({
                "waivers": [{
                    "rule_id": "required-repository-commands",
                    "reason": "fixture waiver must not authorize a truncated gate",
                    "owner": "test-owner",
                    "expires": "2999-01-01"
                }]
            })
            .to_string(),
        )
        .expect("fixture waiver");

        let reason = run_pre_commit_gate_with_budget(
            &root,
            Some("pre-commit-budget"),
            Duration::from_millis(50),
        )
        .expect("pre-commit gate runs")
        .expect("aggregate cutoff denies commit");

        assert!(reason.contains("aggregate execution budget expired"));
        let evidence =
            std::fs::read_to_string(root.join(".lgtm/evidence/evidence.jsonl")).expect("evidence");
        let record: serde_json::Value = serde_json::from_str(evidence.trim()).expect("record");
        assert_eq!(record["profile"], "prototype");
        assert_eq!(record["waivers"].as_array().map(Vec::len), Some(1));
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["status"] == "failed"
                    && result["evidence"]["check"] == commands::budget_unverified().evidence.check
            })
        }));

        std::fs::remove_dir_all(root).expect("temporary fixture removal");
    }

    #[cfg(unix)]
    #[test]
    fn coverage_only_cutoff_denies_pre_commit_with_stable_aggregate_evidence() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-coverage-only-budget-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm/bin")).expect("fixture directories");
        let coverage = root.join(".lgtm/bin/coverage");
        std::fs::write(&coverage, "#!/bin/sh\nexec /bin/sleep 1\n").expect("coverage command");
        std::fs::set_permissions(&coverage, std::fs::Permissions::from_mode(0o700))
            .expect("fixture permissions");
        std::fs::write(
            root.join(".lgtm/config.json"),
            serde_json::json!({
                "version": "2",
                "profile": "default",
                "workspaces": [{
                    "id": "root",
                    "language": "shell",
                    "root": ".",
                    "commands": [],
                    "coverage": [{
                        "argv": [coverage.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                }],
                "disabled_rules": [],
                "severity_overrides": {}
            })
            .to_string(),
        )
        .expect("fixture config");

        let reason = run_pre_commit_gate_with_budget(
            &root,
            Some("coverage-only-budget"),
            Duration::from_millis(50),
        )
        .expect("pre-commit gate runs")
        .expect("coverage cutoff denies commit");
        assert!(reason.contains("aggregate execution budget expired"));

        let evidence =
            std::fs::read_to_string(root.join(".lgtm/evidence/evidence.jsonl")).expect("evidence");
        let record: serde_json::Value = serde_json::from_str(evidence.trim()).expect("record");
        assert_eq!(record["coverage"][0]["status"], "unverified");
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["status"] == "failed"
                    && result["evidence"]["check"] == "command.aggregate_budget"
            })
        }));

        std::fs::remove_dir_all(root).expect("temporary fixture removal");
    }

    #[test]
    fn invalid_v2_command_count_is_rejected_by_profile_validation() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-invalid-v2-precommit-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm")).expect("fixture directory");
        let commands = (0..=crate::config_v2::MAX_STRUCTURED_COMMANDS)
            .map(|_| {
                serde_json::json!({
                    "argv": ["true"],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                })
            })
            .collect::<Vec<_>>();
        std::fs::write(
            root.join(".lgtm/config.json"),
            serde_json::json!({
                "version": "2",
                "profile": "default",
                "workspaces": [{
                    "id": "root",
                    "language": "shell",
                    "root": ".",
                    "commands": commands,
                    "coverage": []
                }],
                "disabled_rules": [],
                "severity_overrides": {}
            })
            .to_string(),
        )
        .expect("invalid V2 config");

        let payload = serde_json::json!({
            "cwd": root,
            "session_id": "invalid-v2",
            "check": true,
            "tier": "full"
        });
        let mut input = std::io::Cursor::new(payload.to_string());
        let mut output = Vec::new();
        let check_error = run_inner_with_budget(
            &mut input,
            &mut output,
            &ClaudeAdapter,
            crate::adapter::HookEvent::Stop,
            Duration::from_secs(1),
        )
        .expect_err("profile validation rejects the invalid V2 config");
        assert!(check_error.contains("config V2 is invalid"));

        let pre_commit_error =
            run_pre_commit_gate_with_budget(&root, Some("invalid-v2"), Duration::from_secs(1))
                .expect_err("pre-commit fails closed on invalid profile config");
        assert!(pre_commit_error.contains("config V2 is invalid"));
        assert!(!root.join(".lgtm/evidence/evidence.jsonl").exists());

        std::fs::remove_dir_all(root).expect("temporary fixture removal");
    }

    #[cfg(unix)]
    #[test]
    fn config_replacement_denies_pre_commit_and_binds_original_bytes() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-config-replacement-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm/bin")).expect("fixture directories");
        let command = root.join(".lgtm/bin/replace-config");
        std::fs::write(
            &command,
            format!(
                "#!/bin/sh\nprintf '{{}}\\n' > {}\n",
                root.join(".lgtm/config.json").display()
            ),
        )
        .expect("replacement command");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
            .expect("fixture permissions");
        let original = serde_json::json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "root",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [command.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string();
        std::fs::write(root.join(".lgtm/config.json"), &original).expect("fixture config");
        let original_digest = digest_bytes(&original);

        let reason = run_pre_commit_gate_with_budget(
            &root,
            Some("config-replacement"),
            Duration::from_secs(1),
        )
        .expect("pre-commit gate runs")
        .expect("config replacement denies commit");
        assert!(reason.contains("changed after repository commands were configured"));

        let evidence =
            std::fs::read_to_string(root.join(".lgtm/evidence/evidence.jsonl")).expect("evidence");
        let record: serde_json::Value = serde_json::from_str(evidence.trim()).expect("record");
        assert_eq!(record["config_digest"], original_digest);
        assert_eq!(record["commands"][0]["config_digest"], original_digest);
        assert_eq!(record["commands"][0]["exit_code"], 0);
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["status"] == "failed" && result["evidence"]["check"] == "command.config"
            })
        }));
        assert!(matching_full_evidence(&root, Some("config-replacement"), &[]).is_none());

        std::fs::remove_dir_all(root).expect("temporary fixture removal");
    }

    #[cfg(unix)]
    #[test]
    fn joined_last_command_is_nonpassing_and_not_reusable() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-joined-command-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm/bin")).expect("fixture directories");
        let command = root.join(".lgtm/bin/joined-command");
        // Detached-descendant containment is exercised at the production
        // supervisor boundary; this fixture joins its child before failing.
        std::fs::write(
            &command,
            "#!/bin/sh\n( sleep 0.05 ) & child=$!; wait \"$child\"; exit 7\n",
        )
        .expect("joined failing command");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700))
            .expect("fixture permissions");
        let original = serde_json::json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "root",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": [command.to_string_lossy()],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "test",
                    "source": "fixture",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string();
        std::fs::write(root.join(".lgtm/config.json"), &original).expect("fixture config");

        let decision = run_pre_commit_gate_with_budget(
            &root,
            Some("delayed-config-replacement"),
            Duration::from_secs(1),
        )
        .expect("pre-commit gate runs")
        .expect("joined failing command denies pre-commit");
        assert!(decision.contains("exit status 7"));
        assert_eq!(
            std::fs::read_to_string(root.join(".lgtm/config.json")).expect("config remains"),
            original
        );
        assert!(matching_full_evidence(&root, Some("delayed-config-replacement"), &[]).is_none());

        std::fs::remove_dir_all(root).expect("temporary fixture removal");
    }

    #[cfg(unix)]
    #[test]
    fn full_stop_budget_records_cutoff_evidence_and_action_required_summary() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "lgtm-stop-budget-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(root.join(".lgtm")).expect("config directory");
        std::fs::create_dir_all(root.join("bin")).expect("binary directory");
        let active_started = root.join("active-started");
        let later_started = root.join("later-started");
        let coverage_started = root.join("coverage-started");
        let active = root.join("bin/active");
        let later = root.join("bin/later");
        let coverage = root.join("bin/coverage");
        for (path, body) in [
            (
                &active,
                format!("touch {}; exec /bin/sleep 1", active_started.display()),
            ),
            (&later, format!("touch {}; exit 0", later_started.display())),
            (
                &coverage,
                format!(
                    "touch {}; echo 'line coverage: 95% branch coverage: 95%'",
                    coverage_started.display()
                ),
            ),
        ] {
            std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("script");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("script permissions");
        }
        std::fs::write(
            root.join(".lgtm/config.json"),
            serde_json::json!({
                "version": "2",
                "profile": "default",
                "workspaces": [{
                    "id": "root",
                    "language": "shell",
                    "root": ".",
                    "commands": [
                        {
                            "argv": [active.to_string_lossy()],
                            "cwd": ".",
                            "timeout_seconds": 30,
                            "tier": "full",
                            "purpose": "test",
                            "source": "fixture",
                            "confidence": "high"
                        },
                        {
                            "argv": [later.to_string_lossy()],
                            "cwd": ".",
                            "timeout_seconds": 30,
                            "tier": "full",
                            "purpose": "test",
                            "source": "fixture",
                            "confidence": "high"
                        }
                    ],
                    "coverage": [{
                        "argv": [coverage.to_string_lossy()],
                        "cwd": ".",
                        "timeout_seconds": 30,
                        "scope": "unit",
                        "line_threshold_percent": 80,
                        "branch_threshold_percent": 80
                    }]
                }],
                "disabled_rules": [],
                "severity_overrides": {}
            })
            .to_string(),
        )
        .expect("config");

        let payload = serde_json::json!({
            "cwd": root,
            "session_id": "aggregate-budget",
            "check": true,
            "tier": "full"
        });
        let mut input = std::io::Cursor::new(payload.to_string());
        let mut output = Vec::new();
        let code = run_inner_with_budget(
            &mut input,
            &mut output,
            &ClaudeAdapter,
            crate::adapter::HookEvent::Stop,
            Duration::from_millis(100),
        )
        .expect("Stop runs");

        assert_eq!(code, ExitCode::SUCCESS);
        let summary = String::from_utf8(output).expect("summary UTF-8");
        assert!(summary.contains("lgtm: action required"));
        assert!(summary.contains("unverified"));
        assert!(active_started.exists());
        assert!(!later_started.exists());
        assert!(!coverage_started.exists());
        let evidence =
            std::fs::read_to_string(root.join(".lgtm/evidence/evidence.jsonl")).expect("evidence");
        let record: serde_json::Value = serde_json::from_str(evidence.trim()).expect("record");
        assert_eq!(record["tier"], "full");
        assert_eq!(record["commands"][0]["exit_code"], serde_json::Value::Null);
        assert_eq!(record["commands"][1]["exit_code"], serde_json::Value::Null);
        assert_eq!(
            record["commands"][1]["started_at_ms"],
            serde_json::Value::Null
        );
        assert_eq!(record["coverage"][0]["status"], "unverified");
        assert_eq!(
            record["coverage"][0]["line_percent"],
            serde_json::Value::Null
        );
        assert!(record["results"].as_array().is_some_and(|results| {
            results.iter().any(|result| {
                result["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("aggregate execution budget expired"))
            })
        }));
        let results: Vec<EnforcementResult> =
            serde_json::from_value(record["results"].clone()).expect("typed results");
        assert!(results.iter().any(is_aggregate_budget_result));
        assert!(results.iter().any(|result| {
            is_aggregate_budget_result(result) && result.status == Status::Unverified
        }));

        std::fs::remove_dir_all(root).ok();
    }
}
