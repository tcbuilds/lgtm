//! Stop hook: rerun required secret checks and enforce unresolved MUST failures.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

use crate::checks::{EnforcementResult, Location, ResultEvidence, Status};
use crate::checks::{gitleaks, ruff};
use crate::policy::Severity;

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const MAX_LEDGER_BYTES: u64 = 5 * 1024 * 1024;
const MAX_TASK_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
struct HookInput {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
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
}

#[derive(Debug, Serialize)]
struct TaskEvidence<'a> {
    task_id: &'a str,
    agent: &'static str,
    profile: &'static str,
    commit: Option<String>,
    rules: RuleCounts,
    results: &'a [EnforcementResult],
    commands: Vec<serde_json::Value>,
    overrides: Vec<serde_json::Value>,
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
    let hook_input = read_input(input)?;
    let root = resolve_root(hook_input.cwd.as_deref())?;
    let paths = touched_paths(&root, hook_input.session_id.as_deref())?;
    let results = rerun_checks(&paths);
    append_task_evidence(&root, hook_input.session_id.as_deref(), &results)?;

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
    let mut results = vec![result];
    let python_files: Vec<String> = paths
        .iter()
        .filter(|path| path.ends_with(".py"))
        .cloned()
        .collect();
    if !python_files.is_empty() {
        results.extend(ruff::scan(&python_files));
    }
    results
}

fn append_task_evidence(
    root: &Path,
    session_id: Option<&str>,
    results: &[EnforcementResult],
) -> Result<(), String> {
    let directory = root.join(".lgtm/evidence");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create evidence directory ({error})"))?;
    let task_id = session_id.unwrap_or("unknown-session");
    let record = TaskEvidence {
        task_id,
        agent: "claude-code",
        profile: "default",
        commit: None,
        rules: count_results(results),
        results,
        commands: Vec::new(),
        overrides: Vec::new(),
    };
    let mut line =
        serde_json::to_string(&record).map_err(|error| format!("serialize evidence ({error})"))?;
    line.push('\n');
    append_bounded_regular(&directory.join("evidence.jsonl"), line.as_bytes())
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
        }
    }
    counts
}

fn write_summary(output: &mut impl Write, results: &[EnforcementResult]) -> Result<(), String> {
    let counts = count_results(results);
    writeln!(
        output,
        "lgtm Stop: passed={} unverified={} failed=0",
        counts.passed, counts.unverified
    )
    .map_err(|error| format!("write summary ({error})"))?;
    for result in results
        .iter()
        .filter(|result| result.status == Status::Unverified)
    {
        writeln!(output, "UNVERIFIED {}: {}", result.rule_id, result.message)
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
