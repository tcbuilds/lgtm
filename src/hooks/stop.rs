//! Stop hook: rerun required secret checks and enforce unresolved MUST failures.

use std::collections::BTreeSet;
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
const MAX_TASK_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_SUMMARY_MESSAGE_CHARS: usize = 512;
const EVIDENCE_SCHEMA_JSON: &str = include_str!("../../schemas/evidence.schema.json");

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
}

struct TouchedPaths {
    files: Vec<String>,
    had_edits: bool,
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
    started_at_ms: u128,
    finished_at_ms: u128,
    tier: &'a str,
}

#[derive(Debug, Deserialize)]
struct StoredTaskEvidence {
    task_id: String,
    results: Vec<EnforcementResult>,
    commands: Vec<commands::CommandEvidence>,
    coverage: Vec<commands::CoverageEvidence>,
    policy_version: String,
    binary_version: String,
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
    let code = run_inner(
        &mut input,
        &mut output,
        &InternalGateAdapter,
        crate::adapter::HookEvent::Stop,
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
    debug_assert_eq!(tiers::for_hook(Hook::Stop), Tier::Targeted);
    let started_at_ms = unix_ms();
    let hook_input = read_input(input)?;
    let root = resolve_root(hook_input.cwd.as_deref())?;
    let workspace_error = commands::load(&root).ok().and_then(|settings| {
        settings
            .validate_workspace(hook_input.workspace.as_deref())
            .err()
    });
    let (paths, had_edits) = if hook_input.check {
        (check_paths(&root)?, false)
    } else {
        let touched = touched_paths(&root, hook_input.session_id.as_deref())?;
        (touched.files, touched.had_edits)
    };
    let settings = commands::load(&root);
    let configured = configured_executables(settings.as_ref().ok());
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
        settings.as_ref(),
        hook_input.workspace.as_deref(),
        Some(tier),
        &paths,
        &mut budget,
    );
    if budget.is_exhausted() {
        command_run.results.push(commands::budget_unverified());
    }
    bind_command_provenance(&root, &paths, &mut command_run.evidence);
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
    if let Some(reason) = workspace_error {
        results.push(commands::invalid_workspace(&reason));
    }
    append_task_evidence(
        EvidenceMeta {
            root: &root,
            session_id: hook_input.session_id.as_deref(),
            profile: &profile,
            paths: &paths,
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
    root: &Path,
    paths: &[String],
    evidence: &mut [commands::CommandEvidence],
) {
    let config_digest = digest_bytes(&crate::fsutil::read_optional_bounded(
        &root.join(".lgtm/config.json"),
        256 * 1024,
    ));
    let touched_files_digest = digest_paths(root, paths);
    for item in evidence {
        item.config_digest = Some(config_digest.clone());
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
    let expected_config = digest_bytes(&crate::fsutil::read_optional_bounded(
        &root.join(".lgtm/config.json"),
        256 * 1024,
    ));
    let expected_files = digest_paths(root, paths);
    let raw = crate::fsutil::read_optional_bounded(
        &root.join(".lgtm/evidence/evidence.jsonl"),
        MAX_TASK_EVIDENCE_BYTES,
    );
    raw.lines().rev().find_map(|line| {
        let record: StoredTaskEvidence = serde_json::from_str(line).ok()?;
        (record.task_id == session_id
            && stored_gate_passed(&record)
            && record.tier.as_deref() == Some("full")
            && record.policy_version == crate::policy::POLICY_BUNDLE_VERSION
            && record.binary_version == env!("CARGO_PKG_VERSION")
            && record.config_digest == expected_config
            && record.touched_files_digest == expected_files)
            .then_some(record.commands)
    })
}

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

fn touched_paths(root: &Path, session_id: Option<&str>) -> Result<TouchedPaths, String> {
    let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
    let raw = crate::fsutil::read_optional_bounded(&ledger, MAX_LEDGER_BYTES);
    let mut paths = BTreeSet::new();
    let mut had_edits = false;
    for line in raw.lines() {
        let record: EditRecord =
            serde_json::from_str(line).map_err(|error| format!("parse result ledger ({error})"))?;
        if record.session_id.as_deref() != session_id {
            continue;
        }
        had_edits = true;
        if let Some(path) = record
            .edited_file
            .as_deref()
            .and_then(|file| canonical_contained_file(root, file))
        {
            paths.insert(path);
            continue;
        }
        if record.result.rule_id != "no-committed-secrets" {
            continue;
        }
        for location in record.result.locations {
            if let Some(path) = canonical_contained_file(root, &location.file) {
                paths.insert(path);
            }
        }
    }
    Ok(TouchedPaths {
        files: paths.into_iter().collect(),
        had_edits,
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
        started_at_ms: metadata.started_at_ms,
        finished_at_ms: metadata.finished_at_ms,
        touched_files_digest: digest_paths(root, metadata.paths),
        config_digest: digest_bytes(&crate::fsutil::read_optional_bounded(
            &root.join(".lgtm/config.json"),
            256 * 1024,
        )),
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

fn digest_paths(root: &Path, paths: &[String]) -> String {
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
    let _ = root;
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

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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
    fn aggregate_cutoff_full_evidence_is_not_reused_for_pre_commit() {
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
        let touched_files_digest = digest_paths(&root, &[]);
        let record = |unverified| {
            serde_json::json!({
                "task_id": "aggregate-budget",
                "rules": {
                    "passed": 0,
                    "failed": 0,
                    "warning": 0,
                    "skipped": 0,
                    "not_applicable": 0,
                    "unverified": unverified,
                    "overridden": 0,
                    "waived": 0
                },
                "commands": [],
                "policy_version": crate::policy::POLICY_BUNDLE_VERSION,
                "binary_version": env!("CARGO_PKG_VERSION"),
                "touched_files_digest": touched_files_digest,
                "config_digest": config_digest,
                "tier": "full"
            })
        };

        for (unverified, reusable) in [(1, false), (0, true)] {
            std::fs::write(&evidence_path, format!("{}\n", record(unverified)))
                .expect("evidence record");
            assert_eq!(
                matching_full_evidence(&root, Some("aggregate-budget"), &[]).is_some(),
                reusable,
                "unverified count {unverified} reuse decision"
            );
        }

        std::fs::remove_dir_all(root).expect("temporary evidence directory removal");
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
                format!("touch {}; sleep 1", active_started.display()),
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

        std::fs::remove_dir_all(root).ok();
    }
}
