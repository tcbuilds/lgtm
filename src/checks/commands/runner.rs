use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::checks::Status;

use super::config::{CoverageCommand, StructuredCommand};
use super::result::{CommandEvidence, CoverageEvidence, RunResults, not_applicable, result};

/// Fixed total wall-clock budget for one Stop-facing repository-command gate.
pub const STOP_COMMAND_BUDGET_SECONDS: u64 = 3_600;
pub const STOP_COMMAND_BUDGET: Duration = Duration::from_secs(STOP_COMMAND_BUDGET_SECONDS);

#[derive(Debug)]
pub struct ExecutionBudget {
    deadline: Option<Instant>,
    exhausted: bool,
}

impl ExecutionBudget {
    pub fn new(limit: Duration) -> Self {
        Self {
            deadline: Some(Instant::now() + limit),
            exhausted: false,
        }
    }

    fn unlimited() -> Self {
        Self {
            deadline: None,
            exhausted: false,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    fn timeout_for(&mut self, configured: Duration) -> Option<Duration> {
        let Some(deadline) = self.deadline else {
            return Some(configured);
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.exhausted = true;
            None
        } else {
            Some(configured.min(remaining))
        }
    }

    fn expired(&mut self) -> bool {
        let Some(deadline) = self.deadline else {
            return false;
        };
        if Instant::now() >= deadline {
            self.exhausted = true;
            true
        } else {
            false
        }
    }
}

pub fn run(root: &Path, commands: &[String], timeout: std::time::Duration) -> RunResults {
    let mut output = RunResults {
        results: Vec::new(),
        evidence: Vec::new(),
    };
    if commands.is_empty() {
        output.results.push(not_applicable());
        return output;
    }
    for command in commands {
        run_one(root, command, timeout, &mut output);
    }
    output
}

pub fn run_structured(root: &Path, commands: &[StructuredCommand]) -> RunResults {
    let mut budget = ExecutionBudget::unlimited();
    run_structured_with_budget(root, commands, &mut budget)
}

pub fn run_structured_with_budget(
    root: &Path,
    commands: &[StructuredCommand],
    budget: &mut ExecutionBudget,
) -> RunResults {
    let mut output = RunResults {
        results: Vec::new(),
        evidence: Vec::new(),
    };
    if commands.is_empty() {
        output.results.push(not_applicable());
        return output;
    }
    for command in commands {
        let display = command.argv.join(" ");
        let Some(timeout) = budget.timeout_for(command.timeout) else {
            output
                .evidence
                .push(unrun_structured_evidence(command, &display));
            output.results.push(unverified_for_budget(&display));
            continue;
        };
        let started_at_ms = unix_ms();
        let started = Instant::now();
        let mut process = Command::new(&command.argv[0]);
        process
            .args(&command.argv[1..])
            .current_dir(root.join(&command.cwd))
            .stdin(Stdio::null());
        apply_environment(&mut process);
        let details = crate::checks::gitleaks::runner::run_details_with_timeout(process, timeout);
        let budget_expired = budget.expired();
        let details = if budget_expired { None } else { details };
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let code = details.as_ref().and_then(|details| details.code);
        output.evidence.push(CommandEvidence {
            command: display.clone(),
            exit_code: code,
            duration_ms,
            argv: command.argv.clone(),
            cwd: Some(command.cwd.to_string_lossy().into_owned()),
            workspace_id: Some(command.workspace_id.clone()),
            config_digest: None,
            touched_files_digest: None,
            policy_version: None,
            binary_version: None,
            started_at_ms: Some(started_at_ms),
            finished_at_ms: Some(unix_ms()),
        });
        output.results.push(if budget_expired {
            unverified_for_budget(&display)
        } else {
            classify(&display, details)
        });
    }
    output
}

pub fn run_coverage(root: &Path, commands: &[CoverageCommand]) -> Vec<CoverageEvidence> {
    let mut budget = ExecutionBudget::unlimited();
    run_coverage_with_budget(root, commands, &mut budget)
}

pub fn run_coverage_with_budget(
    root: &Path,
    commands: &[CoverageCommand],
    budget: &mut ExecutionBudget,
) -> Vec<CoverageEvidence> {
    if commands.is_empty() {
        return vec![CoverageEvidence {
            workspace_id: "repository".to_string(),
            status: "not_applicable".to_string(),
            tool: None,
            scope: None,
            line_percent: None,
            branch_percent: None,
            measured_at_ms: None,
        }];
    }
    let mut evidence = Vec::with_capacity(commands.len());
    for command in commands {
        let Some(timeout) = budget.timeout_for(command.timeout) else {
            evidence.push(unrun_coverage_evidence(command));
            continue;
        };
        let mut process = Command::new(&command.argv[0]);
        process
            .args(&command.argv[1..])
            .current_dir(root.join(&command.cwd))
            .stdin(Stdio::null());
        apply_environment(&mut process);
        let measured_at_ms = unix_ms();
        let captured = crate::checks::gitleaks::runner::run_details_with_timeout(process, timeout);
        if budget.expired() {
            evidence.push(coverage_unverified_evidence(command, Some(measured_at_ms)));
            continue;
        }
        let (status, line_percent, branch_percent) = classify_coverage(command, captured);
        evidence.push(CoverageEvidence {
            workspace_id: command.workspace_id.clone(),
            status: status.to_string(),
            tool: command.argv.first().cloned(),
            scope: Some(command.scope.clone()),
            line_percent,
            branch_percent,
            measured_at_ms: Some(measured_at_ms),
        });
    }
    evidence
}

fn unverified_for_budget(command: &str) -> crate::checks::EnforcementResult {
    result(
        command,
        Status::Unverified,
        "was not completed before the aggregate execution budget expired",
    )
}

fn unrun_structured_evidence(command: &StructuredCommand, display: &str) -> CommandEvidence {
    CommandEvidence {
        command: display.to_string(),
        exit_code: None,
        duration_ms: 0,
        argv: command.argv.clone(),
        cwd: Some(command.cwd.to_string_lossy().into_owned()),
        workspace_id: Some(command.workspace_id.clone()),
        config_digest: None,
        touched_files_digest: None,
        policy_version: None,
        binary_version: None,
        started_at_ms: None,
        finished_at_ms: None,
    }
}

fn unrun_coverage_evidence(command: &CoverageCommand) -> CoverageEvidence {
    coverage_unverified_evidence(command, None)
}

fn coverage_unverified_evidence(
    command: &CoverageCommand,
    measured_at_ms: Option<u128>,
) -> CoverageEvidence {
    CoverageEvidence {
        workspace_id: command.workspace_id.clone(),
        status: "unverified".to_string(),
        tool: command.argv.first().cloned(),
        scope: Some(command.scope.clone()),
        line_percent: None,
        branch_percent: None,
        measured_at_ms,
    }
}

fn classify_coverage(
    command: &CoverageCommand,
    captured: Option<crate::checks::gitleaks::runner::Captured>,
) -> (&'static str, Option<f64>, Option<f64>) {
    match captured {
        Some(details) if details.code == Some(0) => {
            let text = String::from_utf8_lossy(&details.stdout);
            let line = parse_metric(&text, "line");
            let branch = parse_metric(&text, "branch");
            let status = classify_coverage_status(command, line, branch);
            (status, line, branch)
        }
        _ => ("unverified", None, None),
    }
}

fn classify_coverage_status(
    command: &CoverageCommand,
    line: Option<f64>,
    branch: Option<f64>,
) -> &'static str {
    let passed = command
        .line_threshold_percent
        .is_none_or(|threshold| line.is_some_and(|value| value >= f64::from(threshold)))
        && command
            .branch_threshold_percent
            .is_none_or(|threshold| branch.is_some_and(|value| value >= f64::from(threshold)));
    let line_below_threshold = command
        .line_threshold_percent
        .is_some_and(|threshold| line.is_some_and(|value| value < f64::from(threshold)));
    let branch_below_threshold = command
        .branch_threshold_percent
        .is_some_and(|threshold| branch.is_some_and(|value| value < f64::from(threshold)));
    let missing_configured_metric = (command.line_threshold_percent.is_some() && line.is_none())
        || (command.branch_threshold_percent.is_some() && branch.is_none());
    if line_below_threshold || branch_below_threshold {
        "failed"
    } else if (line.is_none() && branch.is_none()) || missing_configured_metric {
        "unverified"
    } else if passed {
        "passed"
    } else {
        "failed"
    }
}

pub(super) fn parse_metric(output: &str, label: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        let start = find_metric_label(&lower, label)?;
        let suffix = &lower[start + label.len()..];
        let next_metric = ["line", "branch"]
            .into_iter()
            .filter(|metric| *metric != label)
            .filter_map(|metric| find_metric_label(suffix, metric))
            .min();
        let suffix = next_metric.map_or(suffix, |end| &suffix[..end]);
        parse_percent(suffix)
    })
}

fn find_metric_label(text: &str, label: &str) -> Option<usize> {
    text.match_indices(label).find_map(|(start, _)| {
        let before = text[..start].chars().next_back();
        let end = start + label.len();
        let after = text[end..].chars().next();
        (before.is_none_or(is_metric_boundary) && after.is_none_or(is_metric_boundary))
            .then_some(start)
    })
}

fn is_metric_boundary(character: char) -> bool {
    !character.is_alphanumeric() && character != '_'
}

fn parse_percent(metric: &str) -> Option<f64> {
    let percent = metric.find('%')?;
    let prefix = metric[..percent].trim_end();
    let number_start = prefix
        .char_indices()
        .rev()
        .find(|(_, character)| !character.is_ascii_digit() && !matches!(character, '.' | '+' | '-'))
        .map_or(0, |(index, character)| index + character.len_utf8());
    let token = &prefix[number_start..];
    if token.is_empty()
        || prefix[..number_start]
            .chars()
            .next_back()
            .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    let value = token.parse::<f64>().ok()?;
    (value.is_finite() && (0.0..=100.0).contains(&value)).then_some(value)
}

fn run_one(root: &Path, command: &str, timeout: std::time::Duration, output: &mut RunResults) {
    let argv = match parse(command) {
        Ok(argv) => argv,
        Err(reason) => {
            output.results.push(result(
                command,
                Status::Unverified,
                &format!("could not run ({reason})"),
            ));
            output.evidence.push(CommandEvidence {
                command: command.to_string(),
                exit_code: None,
                duration_ms: 0,
                argv: Vec::new(),
                cwd: None,
                workspace_id: None,
                config_digest: None,
                touched_files_digest: None,
                policy_version: None,
                binary_version: None,
                started_at_ms: None,
                finished_at_ms: None,
            });
            return;
        }
    };
    let started = Instant::now();
    let mut process = Command::new(&argv[0]);
    process
        .args(&argv[1..])
        .current_dir(root)
        .stdin(Stdio::null());
    apply_environment(&mut process);
    let details = crate::checks::gitleaks::runner::run_details_with_timeout(process, timeout);
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let code = details.as_ref().and_then(|details| details.code);
    output.evidence.push(CommandEvidence {
        command: command.to_string(),
        exit_code: code,
        duration_ms,
        argv: Vec::new(),
        cwd: None,
        workspace_id: None,
        config_digest: None,
        touched_files_digest: None,
        policy_version: None,
        binary_version: None,
        started_at_ms: None,
        finished_at_ms: None,
    });
    output.results.push(classify(command, details));
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn classify(
    command: &str,
    details: Option<crate::checks::gitleaks::runner::Captured>,
) -> crate::checks::EnforcementResult {
    let _stderr_bytes = details.as_ref().map_or(0, |details| details.stderr.len());
    match details {
        Some(details) if details.code == Some(0) => result(command, Status::Passed, "passed"),
        Some(details) => result(
            command,
            Status::Failed,
            &format!(
                "failed with exit status {}",
                details
                    .code
                    .map_or_else(|| "signal".to_string(), |code| code.to_string())
            ),
        ),
        None => result(
            command,
            Status::Unverified,
            "could not run (missing, timed out, or wait failed)",
        ),
    }
}

fn parse(command: &str) -> Result<Vec<String>, String> {
    if command.contains('#') || command.chars().any(char::is_control) {
        return Err("comments and control characters are not allowed".to_string());
    }
    let argv = shlex::split(command).ok_or_else(|| "invalid quoting".to_string())?;
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    if argv[0].contains('=') {
        return Err("environment assignments are not allowed".to_string());
    }
    if argv
        .iter()
        .any(|token| token.chars().any(|character| ";|&><".contains(character)))
    {
        return Err("shell operators are not allowed".to_string());
    }
    Ok(argv)
}

fn apply_environment(process: &mut Command) {
    let path = std::env::var_os("PATH");
    let home = std::env::var_os("HOME");
    let ci = std::env::var_os("CI");
    process.env_clear();
    if let Some(path) = path {
        process.env("PATH", path);
    }
    if let Some(home) = home {
        process.env("HOME", home);
    }
    if let Some(ci) = ci {
        process.env("CI", ci);
    }
}
