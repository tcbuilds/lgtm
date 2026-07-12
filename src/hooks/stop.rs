//! Stop hook: rerun required secret checks and enforce unresolved MUST failures.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::checks::tiers::{self, Hook, Tier};
use crate::checks::{EnforcementResult, Location, ResultEvidence, Status};
use crate::checks::{commands, gitleaks, ruff, semgrep};
use crate::policy::Severity;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const MAX_LEDGER_BYTES: u64 = 5 * 1024 * 1024;
const MAX_TASK_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;
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
}

#[derive(Debug, Deserialize)]
struct EditRecord {
    session_id: Option<String>,
    result: EnforcementResult,
}

#[derive(Debug, Serialize)]
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
    policy_version: &'static str,
    policy_digest: String,
    binary_version: &'static str,
    started_at_ms: u128,
    finished_at_ms: u128,
    touched_files_digest: String,
    config_digest: String,
}

struct EvidenceMeta<'a> {
    root: &'a Path,
    session_id: Option<&'a str>,
    profile: &'a str,
    paths: &'a [String],
    started_at_ms: u128,
    finished_at_ms: u128,
}

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    match run_inner(input, output) {
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

fn run_inner(input: &mut impl Read, output: &mut impl Write) -> Result<ExitCode, String> {
    debug_assert_eq!(tiers::for_hook(Hook::Stop), Tier::Full);
    let started_at_ms = unix_ms();
    let hook_input = read_input(input)?;
    let root = resolve_root(hook_input.cwd.as_deref())?;
    let (profile, registry, overrides, waivers, compatibility) =
        crate::policy::load_profiled_registry(&root)?;
    let paths = if hook_input.check {
        check_paths(&root)?
    } else {
        touched_paths(&root, hook_input.session_id.as_deref())?
    };
    let mut results = rerun_checks(&paths);
    let touched: BTreeSet<String> = paths
        .iter()
        .filter_map(|path| relative_path(&root, path))
        .collect();
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
    let mut command_run = run_repository_commands(
        &root,
        hook_input.workspace.as_deref(),
        hook_input.tier.as_deref(),
    );
    bind_command_provenance(&root, &paths, &mut command_run.evidence);
    let coverage = commands::load(&root)
        .map(|settings| commands::run_coverage(&root, &settings.coverage))
        .unwrap_or_else(|_| commands::run_coverage(&root, &[]));
    results.extend(command_run.results);
    if !hook_input.check {
        results.push(crate::checks::claims::evaluate(
            hook_input.transcript_path.as_deref().map(Path::new),
            &command_run.evidence,
        ));
    }
    if compatibility == crate::policy::config_version::Compatibility::LegacyMissing {
        results.push(legacy_version_result());
    }
    crate::policy::profile::apply_resolved_results(&registry, &mut results);
    crate::policy::overrides::apply_results(&overrides, &mut results);
    crate::policy::waivers::apply(&waivers, &mut results);
    append_task_evidence(
        EvidenceMeta {
            root: &root,
            session_id: hook_input.session_id.as_deref(),
            profile: &profile,
            paths: &paths,
            started_at_ms,
            finished_at_ms: unix_ms(),
        },
        &results,
        &command_run.evidence,
        &coverage,
        &overrides,
        &waivers,
    )?;

    let failures: Vec<&EnforcementResult> = results
        .iter()
        .filter(|result| result.is_failure() && result.severity == Severity::Error)
        .collect();
    if failures.is_empty() {
        write_summary(output, &results)?;
        return Ok(ExitCode::SUCCESS);
    }
    write_block_decision(&failures)?;
    Ok(ExitCode::from(2))
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
    workspace: Option<&str>,
    tier: Option<&str>,
) -> commands::RunResults {
    match commands::load(root) {
        Ok(configured) if !configured.structured.is_empty() => {
            let selected: Vec<_> = configured
                .structured
                .iter()
                .filter(|command| workspace.is_none_or(|id| command.workspace_id == id))
                .filter(|command| tier.is_none_or(|selected| command.tier == selected))
                .cloned()
                .collect();
            commands::run_structured(root, &selected)
        }
        Ok(configured) => commands::run(root, &configured.commands, configured.timeout),
        Err(reason) => commands::RunResults {
            results: vec![commands::config_unverified(&reason)],
            evidence: Vec::new(),
        },
    }
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
    let candidate = cwd
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)
        .map_err(|error| format!("resolve cwd ({error})"))?;
    let root =
        std::fs::canonicalize(candidate).map_err(|error| format!("canonicalize cwd ({error})"))?;
    if !root.is_dir() {
        return Err("cwd is not a directory".to_string());
    }
    Ok(root)
}

fn touched_paths(root: &Path, session_id: Option<&str>) -> Result<Vec<String>, String> {
    let ledger = root.join(".lgtm/evidence/current-task.results.jsonl");
    let raw = crate::fsutil::read_optional_bounded(&ledger, MAX_LEDGER_BYTES);
    let mut paths = BTreeSet::new();
    for line in raw.lines() {
        let record: EditRecord =
            serde_json::from_str(line).map_err(|error| format!("parse result ledger ({error})"))?;
        if record.session_id.as_deref() != session_id {
            continue;
        }
        for location in record.result.locations {
            if let Some(path) = canonical_contained_file(root, &location.file) {
                paths.insert(path);
            }
        }
    }
    Ok(paths.into_iter().collect())
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
            if !matches!(
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
            ) {
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
    use std::io::Write as _;

    if line.len() as u64 > MAX_TASK_EVIDENCE_BYTES {
        return Err("single evidence record exceeds maximum size".to_string());
    }
    let existing_size = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return Err("evidence path is not a regular file".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(format!("inspect evidence ({error})")),
    };
    let should_rotate = existing_size.saturating_add(line.len() as u64) > MAX_TASK_EVIDENCE_BYTES;
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if existing_size == 0 && !path.exists() {
        options.create_new(true);
    } else if should_rotate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(line))
        .map_err(|error| format!("append evidence ({error})"))
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

fn write_summary(output: &mut impl Write, results: &[EnforcementResult]) -> Result<(), String> {
    let counts = count_results(results);
    writeln!(
        output,
        "lgtm Stop: passed={} warning={} unverified={} failed=0",
        counts.passed, counts.warning, counts.unverified
    )
    .map_err(|error| format!("write summary ({error})"))?;
    for result in results
        .iter()
        .filter(|result| result.status == Status::Unverified)
    {
        writeln!(output, "UNVERIFIED {}: {}", result.rule_id, result.message)
            .map_err(|error| format!("write summary ({error})"))?;
    }
    for result in results
        .iter()
        .filter(|result| result.status == Status::Warning)
    {
        writeln!(output, "REVIEW {}: {}", result.rule_id, result.message)
            .map_err(|error| format!("write summary ({error})"))?;
    }
    Ok(())
}

fn write_block_decision(failures: &[&EnforcementResult]) -> Result<(), String> {
    let mut reason = "lgtm Stop blocked: unresolved MUST violations:".to_string();
    for result in failures {
        reason.push_str(&format!("\n- {}: {}", result.rule_id, result.message));
        if let Some(remediation) = &result.remediation {
            reason.push_str(&format!("\n  Repair: {remediation}"));
        }
    }
    let decision = serde_json::json!({
        "decision": "block",
        "reason": reason,
    });
    let serialized = serde_json::to_string(&decision)
        .map_err(|error| format!("serialize block decision ({error})"))?;
    writeln!(std::io::stderr(), "{serialized}")
        .map_err(|error| format!("write block decision ({error})"))
}
