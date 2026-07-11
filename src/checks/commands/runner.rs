use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::checks::Status;

use super::result::{CommandEvidence, RunResults, not_applicable, result};

pub fn run(root: &Path, commands: &[String]) -> RunResults {
    let mut output = RunResults {
        results: Vec::new(),
        evidence: Vec::new(),
    };
    if commands.is_empty() {
        output.results.push(not_applicable());
        return output;
    }
    for command in commands {
        run_one(root, command, &mut output);
    }
    output
}

fn run_one(root: &Path, command: &str, output: &mut RunResults) {
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
    let details = crate::checks::gitleaks::runner::run_details(process);
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let code = details.as_ref().and_then(|details| details.code);
    output.evidence.push(CommandEvidence {
        command: command.to_string(),
        exit_code: code,
        duration_ms,
    });
    output.results.push(classify(command, details));
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
