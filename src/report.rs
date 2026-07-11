use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;

use serde::Deserialize;

use crate::checks::{EnforcementResult, Status};

const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Deserialize)]
struct Record {
    task_id: String,
    agent: String,
    profile: String,
    results: Vec<EnforcementResult>,
    #[serde(default)]
    commands: Vec<CommandRecord>,
    #[serde(default)]
    overrides: Vec<OverrideRecord>,
}

#[derive(Deserialize)]
struct CommandRecord {
    command: String,
    exit_code: Option<i32>,
    duration_ms: u64,
}

#[derive(Deserialize)]
struct OverrideRecord {
    rule_id: String,
    action: String,
    severity: Option<crate::policy::Severity>,
}

pub fn render(path: &Path, task: Option<&str>, output: &mut impl Write) -> Result<(), String> {
    let records = read(path)?;
    let record = records
        .into_iter()
        .rev()
        .find(|record| task.is_none_or(|task| record.task_id == task))
        .ok_or_else(|| {
            task.map_or_else(
                || "evidence contains no records".to_string(),
                |task| format!("task `{}` not found", sanitize(task)),
            )
        })?;
    let root = evidence_root(path).or_else(current_root);
    write_report(&record, root.as_deref(), output)
}

fn evidence_root(path: &Path) -> Option<std::path::PathBuf> {
    let evidence = path.parent()?;
    let lgtm = evidence.parent()?;
    if evidence.file_name()? != "evidence" || lgtm.file_name()? != ".lgtm" {
        return None;
    }
    lgtm.parent()?.canonicalize().ok()
}

fn current_root() -> Option<std::path::PathBuf> {
    std::env::current_dir()
        .ok()
        .and_then(|path| path.canonicalize().ok())
}

fn read(path: &Path) -> Result<Vec<Record>, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("inspect evidence ({error})"))?;
    if !metadata.is_file() {
        return Err("evidence path is not a regular file".to_string());
    }
    if metadata.len() > MAX_EVIDENCE_BYTES {
        return Err("evidence exceeds maximum size".to_string());
    }
    let mut raw = String::new();
    crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open evidence ({error})"))?
        .ok_or_else(|| "evidence file is missing".to_string())?
        .take(MAX_EVIDENCE_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read evidence ({error})"))?;
    raw.lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("malformed evidence line {} ({error})", index + 1))
        })
        .collect()
}

fn write_report(
    record: &Record,
    root: Option<&Path>,
    output: &mut impl Write,
) -> Result<(), String> {
    writeln!(output, "Task: {}", sanitize(&record.task_id)).map_err(write_error)?;
    writeln!(output, "Agent: {}", sanitize(&record.agent)).map_err(write_error)?;
    writeln!(output, "Profile: {}", sanitize(&record.profile)).map_err(write_error)?;
    write_files(record, root, output)?;
    write_results(record, output)?;
    write_commands(record, output)?;
    write_overrides(record, output)?;
    write_risks(record, output)
}

fn write_files(
    record: &Record,
    root: Option<&Path>,
    output: &mut impl Write,
) -> Result<(), String> {
    let files: BTreeSet<_> = record
        .results
        .iter()
        .flat_map(|result| &result.locations)
        .map(|location| display_path(&location.file, root))
        .collect();
    writeln!(output, "Files changed ({}):", files.len()).map_err(write_error)?;
    for file in files {
        writeln!(output, "- {file}").map_err(write_error)?;
    }
    Ok(())
}

fn display_path(file: &str, root: Option<&Path>) -> String {
    let path = Path::new(file);
    if path.is_absolute()
        && let Some(root) = root
        && let Ok(relative) = path.strip_prefix(root)
    {
        return sanitize(&relative.to_string_lossy());
    }
    sanitize(file)
}

fn write_results(record: &Record, output: &mut impl Write) -> Result<(), String> {
    let mut results: Vec<_> = record.results.iter().collect();
    results.sort_by_key(|result| (&result.rule_id, status_name(result.status)));
    writeln!(output, "Checks:").map_err(write_error)?;
    for result in results {
        writeln!(
            output,
            "- {}: {}",
            sanitize(&result.rule_id),
            status_name(result.status)
        )
        .map_err(write_error)?;
    }
    let omitted: Vec<_> = record
        .results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                Status::Skipped | Status::NotApplicable | Status::Unverified
            )
        })
        .collect();
    writeln!(output, "Checks not run ({}):", omitted.len()).map_err(write_error)?;
    for result in omitted {
        writeln!(
            output,
            "- {}: {}",
            sanitize(&result.rule_id),
            not_run_reason(result.status)
        )
        .map_err(write_error)?;
    }
    Ok(())
}

fn write_commands(record: &Record, output: &mut impl Write) -> Result<(), String> {
    writeln!(output, "Commands ({}):", record.commands.len()).map_err(write_error)?;
    for command in &record.commands {
        writeln!(
            output,
            "- {}: exit={:?} duration_ms={}",
            safe_command_name(&command.command),
            command.exit_code,
            command.duration_ms
        )
        .map_err(write_error)?;
    }
    Ok(())
}

fn safe_command_name(command: &str) -> String {
    let executable = shlex::split(command)
        .and_then(|arguments| arguments.into_iter().next())
        .unwrap_or_else(|| "unparseable-command".to_string());
    Path::new(&executable)
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "command".to_string())
}

fn write_overrides(record: &Record, output: &mut impl Write) -> Result<(), String> {
    writeln!(output, "Overrides ({}):", record.overrides.len()).map_err(write_error)?;
    for item in &record.overrides {
        writeln!(
            output,
            "- {}: {}{}",
            sanitize(&item.rule_id),
            sanitize(&item.action),
            item.severity
                .map_or(String::new(), |value| format!(" -> {value}"))
        )
        .map_err(write_error)?;
    }
    Ok(())
}

fn write_risks(record: &Record, output: &mut impl Write) -> Result<(), String> {
    let risks: Vec<_> = record
        .results
        .iter()
        .filter(|result| {
            matches!(
                result.status,
                Status::Failed | Status::Warning | Status::Unverified
            )
        })
        .collect();
    writeln!(output, "Residual risks ({}):", risks.len()).map_err(write_error)?;
    for risk in risks {
        writeln!(
            output,
            "- {}: {}",
            sanitize(&risk.rule_id),
            status_name(risk.status)
        )
        .map_err(write_error)?;
    }
    Ok(())
}

fn status_name(status: Status) -> &'static str {
    match status {
        Status::Passed => "passed",
        Status::Failed => "failed",
        Status::Warning => "warning",
        Status::Skipped => "skipped",
        Status::NotApplicable => "not-applicable",
        Status::Unverified => "unverified",
        Status::Overridden => "overridden",
    }
}
fn not_run_reason(status: Status) -> &'static str {
    match status {
        Status::Skipped => "deliberately skipped",
        Status::NotApplicable => "not applicable",
        Status::Unverified => "tool or evidence unavailable",
        _ => "not run",
    }
}
fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}
fn write_error(error: std::io::Error) -> String {
    format!("write report ({error})")
}
