use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checks::Status;

use super::config::{CoverageCommand, StructuredCommand};
use super::result::{CommandEvidence, CoverageEvidence, RunResults, not_applicable, result};

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
        let started_at_ms = unix_ms();
        let started = Instant::now();
        let mut process = Command::new(&command.argv[0]);
        process
            .args(&command.argv[1..])
            .current_dir(root.join(&command.cwd))
            .stdin(Stdio::null());
        let details =
            crate::checks::gitleaks::runner::run_details_with_timeout(process, command.timeout);
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
        output.results.push(classify(&display, details));
    }
    output
}

pub fn run_coverage(root: &Path, commands: &[CoverageCommand]) -> Vec<CoverageEvidence> {
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
    commands
        .iter()
        .map(|command| {
            let mut process = Command::new(&command.argv[0]);
            process
                .args(&command.argv[1..])
                .current_dir(root.join(&command.cwd))
                .stdin(Stdio::null());
            let measured_at_ms = unix_ms();
            let captured =
                crate::checks::gitleaks::runner::run_details_with_timeout(process, command.timeout);
            let (status, line_percent, branch_percent) = match captured {
                Some(details) if details.code == Some(0) => {
                    let text = String::from_utf8_lossy(&details.stdout);
                    let line = parse_metric(&text, "line");
                    let branch = parse_metric(&text, "branch");
                    let passed = line.is_some_and(|value| {
                        command
                            .line_threshold_percent
                            .is_none_or(|threshold| value >= f64::from(threshold))
                    }) && branch.is_none_or(|value| {
                        command
                            .branch_threshold_percent
                            .is_none_or(|threshold| value >= f64::from(threshold))
                    });
                    if line.is_none() && branch.is_none() {
                        ("unverified", line, branch)
                    } else if passed {
                        ("passed", line, branch)
                    } else {
                        ("failed", line, branch)
                    }
                }
                _ => ("unverified", None, None),
            };
            CoverageEvidence {
                workspace_id: command.workspace_id.clone(),
                status: status.to_string(),
                tool: command.argv.first().cloned(),
                scope: Some(command.scope.clone()),
                line_percent,
                branch_percent,
                measured_at_ms: Some(measured_at_ms),
            }
        })
        .collect()
}

fn parse_metric(output: &str, label: &str) -> Option<f64> {
    output.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if !lower.contains(label) || !lower.contains('%') {
            return None;
        }
        let percent = lower
            .split('%')
            .next()?
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        percent.chars().rev().collect::<String>().parse().ok()
    })
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
