use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::Path;

use serde::Deserialize;

use crate::checks::{EnforcementResult, Status};
use crate::pi_state::{self, PiEnforcementState, PiStateReport};

const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Deserialize)]
struct RecordedEnforcement {
    state: PiEnforcementState,
    scope: Option<String>,
    reason: String,
}

#[derive(Deserialize)]
struct Record {
    task_id: String,
    agent: String,
    #[serde(default)]
    harness: Option<String>,
    #[serde(default)]
    enforcement: Option<RecordedEnforcement>,
    profile: String,
    results: Vec<EnforcementResult>,
    #[serde(default)]
    coverage: Vec<CoverageRecord>,
    #[serde(default)]
    commands: Vec<CommandRecord>,
    #[serde(default)]
    overrides: Vec<OverrideRecord>,
    #[serde(default)]
    waivers: Vec<WaiverRecord>,
    #[serde(default)]
    policy_version: Option<String>,
    #[serde(default)]
    policy_digest: Option<String>,
    #[serde(default)]
    binary_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CoverageStatus {
    Passed,
    Failed,
    Unverified,
    NotApplicable,
}

impl CoverageStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Unverified => "unverified",
            Self::NotApplicable => "not_applicable",
        }
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageRecord {
    workspace_id: String,
    status: CoverageStatus,
    #[serde(deserialize_with = "required_nullable")]
    tool: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    scope: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    line_percent: Option<f64>,
    #[serde(deserialize_with = "required_nullable")]
    branch_percent: Option<f64>,
    #[serde(deserialize_with = "required_nullable")]
    measured_at_ms: Option<u128>,
    #[serde(default, rename = "cwd")]
    _cwd: Option<String>,
    #[serde(default, rename = "cwd_identity")]
    _cwd_identity: Option<String>,
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

#[derive(Deserialize)]
struct WaiverRecord {
    rule_id: String,
    reason: String,
    owner: String,
    expires: String,
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
    let root = evidence_root(path);
    write_report(&record, root.as_deref(), output)
}

fn evidence_root(path: &Path) -> Option<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    let evidence = absolute.parent()?;
    let lgtm = evidence.parent()?;
    if evidence.file_name()? != "evidence" || lgtm.file_name()? != ".lgtm" {
        return None;
    }
    for directory in [evidence, lgtm] {
        let metadata = std::fs::symlink_metadata(directory).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return None;
        }
    }
    let canonical_file = std::fs::canonicalize(&absolute).ok()?;
    let canonical_evidence = canonical_file.parent()?;
    let canonical_lgtm = canonical_evidence.parent()?;
    if canonical_evidence.file_name()? != "evidence" || canonical_lgtm.file_name()? != ".lgtm" {
        return None;
    }
    // Keep the input path's spelling for display; state inspection canonicalizes the root.
    Some(lgtm.parent()?.to_path_buf())
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
            let record: Record = serde_json::from_str(line)
                .map_err(|error| malformed_evidence(index + 1, &error))?;
            validate_coverage(&record)
                .map_err(|error| format!("malformed evidence line {} ({error})", index + 1))?;
            Ok(record)
        })
        .collect()
}

fn malformed_evidence(line: usize, error: &serde_json::Error) -> String {
    let reason = match error.classify() {
        serde_json::error::Category::Syntax => "invalid JSON syntax",
        serde_json::error::Category::Eof => "unexpected end of JSON",
        serde_json::error::Category::Data => "evidence schema mismatch",
        serde_json::error::Category::Io => "JSON input failure",
    };
    format!(
        "malformed evidence line {line} ({reason} at column {})",
        error.column()
    )
}

fn validate_coverage(record: &Record) -> Result<(), String> {
    for coverage in &record.coverage {
        if coverage.workspace_id.is_empty() {
            return Err("coverage workspace_id must not be empty".to_string());
        }
        for (name, value) in [
            ("line_percent", coverage.line_percent),
            ("branch_percent", coverage.branch_percent),
        ] {
            if let Some(value) = value
                && (!value.is_finite() || !(0.0..=100.0).contains(&value))
            {
                return Err(format!(
                    "coverage {name} must be finite and between 0 and 100"
                ));
            }
        }
    }
    Ok(())
}

fn write_report(
    record: &Record,
    root: Option<&Path>,
    output: &mut impl Write,
) -> Result<(), String> {
    writeln!(output, "Task: {}", sanitize(&record.task_id)).map_err(write_error)?;
    writeln!(output, "Agent: {}", sanitize(&record.agent)).map_err(write_error)?;
    if let Some(harness) = &record.harness {
        writeln!(output, "Harness: {}", sanitize(harness)).map_err(write_error)?;
    }
    writeln!(output, "Profile: {}", sanitize(&record.profile)).map_err(write_error)?;
    if let Some(version) = &record.policy_version {
        writeln!(output, "Policy bundle: {}", sanitize(version)).map_err(write_error)?;
    }
    if let Some(digest) = &record.policy_digest {
        writeln!(output, "Policy digest: {}", sanitize(digest)).map_err(write_error)?;
    }
    if let Some(version) = &record.binary_version {
        writeln!(output, "Binary version: {}", sanitize(version)).map_err(write_error)?;
    }
    if let Some(root) = root {
        write_enforcement_report(record, root, output)?;
    } else if record.harness.as_deref() == Some("pi") || record.enforcement.is_some() {
        writeln!(
            output,
            "Pi installation current: unavailable (evidence path is outside .lgtm/evidence)"
        )
        .map_err(write_error)?;
        writeln!(
            output,
            "Pi enforcement effective: recorded-only; current state unavailable"
        )
        .map_err(write_error)?;
    }
    write_files(record, root, output)?;
    write_results(record, output)?;
    write_coverage(record, output)?;
    write_commands(record, output)?;
    write_overrides(record, output)?;
    write_waivers(record, output)?;
    write_risks(record, output)
}

fn write_enforcement_report(
    record: &Record,
    root: &Path,
    output: &mut impl Write,
) -> Result<(), String> {
    let harness = record.harness.as_deref().unwrap_or(&record.agent);
    let current = if harness == "pi" {
        pi_state::assess_for_session(root, &record.task_id)
    } else {
        pi_state::assess(root)
    };
    if let Some(recorded) = &record.enforcement {
        writeln!(
            output,
            "Pi enforcement recorded: {} scope={} reason={}",
            recorded.state.as_str(),
            report_scope(recorded.scope.as_deref()),
            sanitize(&recorded.reason)
        )
        .map_err(write_error)?;
    } else {
        writeln!(
            output,
            "Pi enforcement recorded: stale/unverified scope=none reason=legacy record has no Pi state"
        )
        .map_err(write_error)?;
    }
    writeln!(
        output,
        "Pi installation current: {} scope={} reason={}",
        current.state.as_str(),
        report_scope(current.scope.as_deref()),
        sanitize(&current.reason)
    )
    .map_err(write_error)?;
    let (state, scope, reason) = effective_state(record, harness, &current);
    writeln!(
        output,
        "Pi enforcement effective: {} scope={} reason={}",
        state,
        scope,
        sanitize(&reason)
    )
    .map_err(write_error)
}

fn effective_state(
    record: &Record,
    harness: &str,
    current: &PiStateReport,
) -> (&'static str, String, String) {
    if harness != "pi" {
        return (
            "stale/unverified",
            "none".to_string(),
            "recorded harness did not establish Pi enforcement".to_string(),
        );
    }
    let Some(recorded) = record.enforcement.as_ref() else {
        return (
            "stale/unverified",
            "none".to_string(),
            "Pi enforcement was not recorded for this session".to_string(),
        );
    };
    if state_rank(current.state) <= state_rank(recorded.state) {
        return (
            current.state.as_str(),
            report_scope(current.scope.as_deref()),
            current.reason.clone(),
        );
    }
    (
        recorded.state.as_str(),
        report_scope(recorded.scope.as_deref()),
        recorded.reason.clone(),
    )
}

fn report_scope(scope: Option<&str>) -> String {
    match scope {
        Some("project") => "project".to_string(),
        Some("global") => "global".to_string(),
        _ => "none".to_string(),
    }
}

fn state_rank(state: PiEnforcementState) -> u8 {
    match state {
        PiEnforcementState::NotInstalled => 0,
        PiEnforcementState::InstalledUnloadable => 1,
        PiEnforcementState::ProjectUntrusted => 2,
        PiEnforcementState::ToolContractUnverified => 3,
        PiEnforcementState::StaleUnverified => 4,
        PiEnforcementState::Active => 5,
    }
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

struct CoverageProjectionNumber<T> {
    value: Option<T>,
    rendered: String,
}

struct CoverageProjection {
    workspace: String,
    status: String,
    tool: String,
    scope: String,
    line_percent: CoverageProjectionNumber<f64>,
    branch_percent: CoverageProjectionNumber<f64>,
    measured_at_ms: CoverageProjectionNumber<u128>,
}

fn project_coverage(item: &CoverageRecord) -> CoverageProjection {
    CoverageProjection {
        workspace: coverage_workspace(&item.workspace_id),
        status: item.status.as_str().to_string(),
        tool: coverage_tool(item.tool.as_deref()),
        scope: optional_coverage_text(item.scope.as_deref()),
        line_percent: CoverageProjectionNumber {
            value: item.line_percent,
            rendered: optional_number(item.line_percent),
        },
        branch_percent: CoverageProjectionNumber {
            value: item.branch_percent,
            rendered: optional_number(item.branch_percent),
        },
        measured_at_ms: CoverageProjectionNumber {
            value: item.measured_at_ms,
            rendered: optional_integer(item.measured_at_ms),
        },
    }
}

fn write_coverage(record: &Record, output: &mut impl Write) -> Result<(), String> {
    if record.coverage.is_empty() {
        return Ok(());
    }
    let mut coverage: Vec<_> = record.coverage.iter().map(project_coverage).collect();
    coverage.sort_by(|left, right| {
        left.workspace
            .cmp(&right.workspace)
            .then_with(|| left.status.cmp(&right.status))
            .then_with(|| left.tool.cmp(&right.tool))
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| {
                compare_coverage_number(left.line_percent.value, right.line_percent.value)
            })
            .then_with(|| {
                compare_coverage_number(left.branch_percent.value, right.branch_percent.value)
            })
            .then_with(|| left.measured_at_ms.value.cmp(&right.measured_at_ms.value))
    });
    writeln!(output, "Coverage ({}):", coverage.len()).map_err(write_error)?;
    for item in coverage {
        writeln!(
            output,
            "- workspace={} status={} tool={} scope={} line_percent={} branch_percent={} measured_at_ms={}",
            item.workspace,
            item.status,
            item.tool,
            item.scope,
            item.line_percent.rendered,
            item.branch_percent.rendered,
            item.measured_at_ms.rendered,
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

fn write_waivers(record: &Record, output: &mut impl Write) -> Result<(), String> {
    writeln!(output, "Waivers ({}):", record.waivers.len()).map_err(write_error)?;
    for item in &record.waivers {
        writeln!(
            output,
            "- {}: owner={} expires={} reason={}",
            sanitize(&item.rule_id),
            sanitize(&item.owner),
            sanitize(&item.expires),
            sanitize(&item.reason)
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
        Status::Waived => "waived",
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
struct SanitizedCoverageText {
    text: String,
    has_substantive_character: bool,
}

fn coverage_workspace(value: &str) -> String {
    let sanitized = sanitize_coverage_with_origin(value);
    if sanitized.text.is_empty() || !sanitized.has_substantive_character {
        "redacted-workspace".to_string()
    } else {
        sanitized.text
    }
}

fn coverage_tool(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".to_string(),
        |value| {
            let component = value.rsplit(['/', '\\']).next().unwrap_or(value);
            let sanitized = sanitize_coverage(component);
            let bytes = sanitized.as_bytes();
            let without_drive =
                if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                    &sanitized[2..]
                } else {
                    &sanitized
                };
            if without_drive.is_empty() {
                "tool".to_string()
            } else {
                without_drive.to_string()
            }
        },
    )
}

fn optional_coverage_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), sanitize_coverage)
}

fn sanitize_coverage(value: &str) -> String {
    sanitize_coverage_with_origin(value).text
}

fn sanitize_coverage_with_origin(value: &str) -> SanitizedCoverageText {
    let mut text = String::new();
    let mut output_len = 0;
    let mut has_substantive_character = false;
    for character in value.chars() {
        let emitted = if character.is_control()
            || matches!(character, '\u{2028}' | '\u{2029}')
            || is_coverage_default_ignorable(character)
        {
            None
        } else if character.is_whitespace() || character == '=' {
            Some('_')
        } else {
            Some(character)
        };
        let Some(emitted) = emitted else {
            continue;
        };
        if output_len >= 512 {
            break;
        }
        if !character.is_whitespace() {
            has_substantive_character = true;
        }
        text.push(emitted);
        output_len += 1;
    }
    SanitizedCoverageText {
        text,
        has_substantive_character,
    }
}

fn is_coverage_default_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

fn compare_coverage_number(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => left.total_cmp(&right),
    }
}

fn optional_number(value: Option<f64>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn optional_integer(value: Option<u128>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn write_error(error: std::io::Error) -> String {
    format!("write report ({error})")
}
