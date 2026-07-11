use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const RULES: [(&str, &str); 2] = [
    ("no-swallowed-errors", "S110,S112"),
    ("no-broad-exception-handling", "BLE001,E722"),
];

#[derive(Deserialize)]
struct Finding {
    code: String,
    filename: String,
    message: String,
    location: Position,
}

#[derive(Deserialize)]
struct Position {
    row: u64,
}

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    scan_with_binary("ruff", files)
}

pub fn installed_version() -> Option<String> {
    version_with_binary("ruff")
}

fn version_with_binary(binary: &str) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("--version");
    let (status, stdout) = run_bounded(command).ok()?;
    status
        .success()
        .then(|| String::from_utf8_lossy(&stdout).trim().to_string())
}

fn scan_with_binary(binary: &str, files: &[String]) -> Vec<EnforcementResult> {
    if files.is_empty() {
        return RULES
            .map(|(rule, _)| unverified(rule, "no Python files were provided", None))
            .to_vec();
    }
    let mut command = Command::new(binary);
    command.args([
        "check",
        "--output-format",
        "json",
        "--select",
        "S110,S112,BLE001,E722",
    ]);
    command
        .args(files)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, stdout) = match run_bounded(command) {
        Ok(output) => output,
        Err(reason) => return unverified_all(&reason, None),
    };
    if !matches!(status.code(), Some(0 | 1)) {
        return unverified_all(&format!("ruff exited with status {status}"), None);
    }
    let findings: Vec<Finding> = match serde_json::from_slice(&stdout) {
        Ok(findings) => findings,
        Err(error) => {
            return unverified_all(&format!("could not parse ruff output ({error})"), None);
        }
    };
    normalize(findings, version_with_binary(binary))
}

fn run_bounded(mut command: Command) -> Result<(std::process::ExitStatus, Vec<u8>), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start ruff ({error})"))?;
    let stdout_reader = drain(child.stdout.take());
    let stderr_reader = drain(child.stderr.take());
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                kill_process_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    kill_process_group(child.id());
    let stdout = join_bounded(stdout_reader);
    let _ = join_bounded(stderr_reader);
    let status = status.ok_or_else(|| "ruff timed out or could not be waited on".to_string())?;
    if stdout.len() as u64 > MAX_OUTPUT_BYTES {
        return Err("ruff output exceeded maximum size".to_string());
    }
    Ok((status, stdout))
}

fn join_bounded(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    let Some(handle) = handle else {
        return Vec::new();
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.send(handle.join().unwrap_or_default());
    });
    receiver.recv_timeout(DRAIN_TIMEOUT).unwrap_or_default()
}

#[cfg(unix)]
fn set_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setpgid is async-signal-safe and the closure touches no shared state.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn set_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    // SAFETY: kill has no memory preconditions; negative pid selects the child group.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {}

fn drain<R: Read + Send + 'static>(stream: Option<R>) -> Option<thread::JoinHandle<Vec<u8>>> {
    stream.map(|stream| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut bytes);
            bytes
        })
    })
}

fn normalize(findings: Vec<Finding>, version: Option<String>) -> Vec<EnforcementResult> {
    RULES
        .iter()
        .map(|(rule, codes)| {
            let selected: Vec<_> = findings
                .iter()
                .filter(|finding| codes.split(',').any(|code| code == finding.code))
                .collect();
            let status = if selected.is_empty() {
                Status::Passed
            } else {
                Status::Failed
            };
            EnforcementResult {
                rule_id: (*rule).to_string(),
                status,
                severity: Severity::Error,
                message: if selected.is_empty() {
                    format!("{rule}: Ruff found no violations.")
                } else {
                    format!("{rule}: Ruff found {} violation(s).", selected.len())
                },
                locations: selected
                    .iter()
                    .map(|finding| Location {
                        file: sanitize(&finding.filename),
                        line: Some(finding.location.row),
                    })
                    .collect(),
                remediation: (status == Status::Failed).then(|| remediation(rule).to_string()),
                evidence: ResultEvidence {
                    check: "ruff.check".to_string(),
                    tool_version: version.clone(),
                    finding_descriptions: selected
                        .iter()
                        .map(|finding| sanitize(&finding.message))
                        .collect(),
                },
            }
        })
        .collect()
}

fn remediation(rule: &str) -> &'static str {
    if rule == "no-swallowed-errors" {
        "Handle the error explicitly or document and log why it is intentionally ignored."
    } else {
        "Catch the narrow exception types this operation can raise; do not use a bare or broad exception handler."
    }
}

fn unverified_all(reason: &str, version: Option<String>) -> Vec<EnforcementResult> {
    RULES
        .map(|(rule, _)| unverified(rule, reason, version.clone()))
        .to_vec()
}

fn unverified(rule: &str, reason: &str, version: Option<String>) -> EnforcementResult {
    EnforcementResult {
        rule_id: rule.to_string(),
        status: Status::Unverified,
        severity: Severity::Error,
        message: format!(
            "{rule}: Ruff verification unavailable ({}).",
            sanitize(reason)
        ),
        locations: Vec::new(),
        remediation: Some("Install Ruff and rerun the edit or Stop check.".to_string()),
        evidence: ResultEvidence {
            check: "ruff.check".to_string(),
            tool_version: version,
            finding_descriptions: Vec::new(),
        },
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(300)
        .collect()
}

#[cfg(all(test, unix))]
#[path = "ruff/tests.rs"]
mod tests;
