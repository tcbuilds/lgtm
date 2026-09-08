#[cfg(test)]
use std::io::{ErrorKind, Read};
#[cfg(all(unix, test))]
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command, Stdio};
#[cfg(test)]
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

const TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
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

pub fn scan_with_deadline(files: &[String], deadline: Instant) -> Vec<EnforcementResult> {
    scan_with_binary_until("ruff", files, deadline)
}

pub fn installed_version() -> Option<String> {
    version_with_binary("ruff")
}

fn version_with_binary(binary: &str) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("--version");
    let (status, stdout) = run_bounded(command).ok()?;
    status
        .is_some_and(|code| code == 0)
        .then(|| String::from_utf8_lossy(&stdout).trim().to_string())
}

fn version_with_binary_until(binary: &str, deadline: Instant) -> Option<String> {
    let mut command = Command::new(binary);
    command.arg("--version");
    let (status, stdout) = run_bounded_until(command, deadline).ok()?;
    status
        .is_some_and(|code| code == 0)
        .then(|| String::from_utf8_lossy(&stdout).trim().to_string())
}

fn deadline_after(duration: Duration) -> Instant {
    Instant::now()
        .checked_add(duration)
        .unwrap_or_else(Instant::now)
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
    if !matches!(status, Some(0 | 1)) {
        return unverified_all(&format!("ruff exited with status {status:?}"), None);
    }
    let findings: Vec<Finding> = match serde_json::from_slice(&stdout) {
        Ok(findings) => findings,
        Err(error) => {
            return unverified_all(&format!("could not parse ruff output ({error})"), None);
        }
    };
    normalize(findings, version_with_binary(binary))
}

fn scan_with_binary_until(
    binary: &str,
    files: &[String],
    deadline: Instant,
) -> Vec<EnforcementResult> {
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
    let (status, stdout) = match run_bounded_until(command, deadline) {
        Ok(output) => output,
        Err(reason) => return unverified_all(&reason, None),
    };
    if !matches!(status, Some(0 | 1)) {
        return unverified_all(&format!("ruff exited with status {status:?}"), None);
    }
    let findings: Vec<Finding> = match serde_json::from_slice(&stdout) {
        Ok(findings) => findings,
        Err(error) => {
            return unverified_all(&format!("could not parse ruff output ({error})"), None);
        }
    };
    normalize(findings, version_with_binary_until(binary, deadline))
}

fn run_bounded(command: Command) -> Result<(Option<i32>, Vec<u8>), String> {
    run_bounded_until(command, deadline_after(TIMEOUT))
}

fn run_bounded_until(
    command: Command,
    deadline: Instant,
) -> Result<(Option<i32>, Vec<u8>), String> {
    if Instant::now() >= deadline {
        return Err("ruff deadline expired".to_string());
    }
    #[cfg(all(target_os = "linux", not(test)))]
    {
        run_bounded_via_supervisor(command, deadline)
    }
    #[cfg(all(test, unix))]
    return run_bounded_direct(command, deadline);
    #[cfg(all(test, not(unix)))]
    {
        let _ = (command, deadline);
        Err("Ruff test execution is unavailable on this platform".to_string())
    }
    #[cfg(all(not(target_os = "linux"), not(test)))]
    {
        let _ = (command, deadline);
        Err("Ruff descendant containment is unavailable on this platform".to_string())
    }
}

#[cfg(all(test, unix))]
struct TestCapture<R> {
    stream: Option<R>,
    bytes: Vec<u8>,
    truncated: bool,
    failed: bool,
}

#[cfg(all(test, unix))]
impl<R: Read + AsRawFd> TestCapture<R> {
    fn new(stream: Option<R>) -> Option<Self> {
        let stream = stream?;
        set_nonblocking(stream.as_raw_fd()).ok()?;
        Some(Self {
            stream: Some(stream),
            bytes: Vec::new(),
            truncated: false,
            failed: false,
        })
    }

    fn read_available(&mut self) -> bool {
        let Some(stream) = self.stream.as_mut() else {
            return true;
        };
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    self.stream = None;
                    return true;
                }
                Ok(read) => {
                    let remaining = MAX_OUTPUT_BYTES as usize - self.bytes.len();
                    let accepted = read.min(remaining);
                    self.bytes.extend_from_slice(&buffer[..accepted]);
                    self.truncated |= accepted < read;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return true,
                Err(_) => {
                    self.failed = true;
                    self.stream = None;
                    return false;
                }
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
}

#[cfg(all(test, unix))]
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl operates on the owned pipe descriptor and does not outlive it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fcntl updates only flags on the owned pipe descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    (result == 0)
        .then_some(())
        .ok_or_else(std::io::Error::last_os_error)
}

#[cfg(all(test, unix))]
fn finish_test_capture<R: Read + AsRawFd>(
    capture: &mut TestCapture<R>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    while !capture.is_closed() {
        if !capture.read_available() {
            return None;
        }
        if capture.is_closed() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(Duration::from_millis(10).min(remaining));
    }
    (!capture.failed && !capture.truncated).then(|| std::mem::take(&mut capture.bytes))
}

#[cfg(all(test, unix))]
fn wait_and_drain_test(
    child: &mut std::process::Child,
    stdout: &mut TestCapture<std::process::ChildStdout>,
    stderr: &mut TestCapture<std::process::ChildStderr>,
    deadline: Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        let _ = stdout.read_available();
        let _ = stderr.read_available();
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Err(_) => return None,
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(Duration::from_millis(20).min(remaining));
    }
}

#[cfg(all(test, unix))]
fn reap_test_child(child: &mut std::process::Child, deadline: Instant) -> bool {
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(Duration::from_millis(10).min(remaining));
    }
}

#[cfg(all(test, unix))]
fn stop_test_child(child: &mut std::process::Child, pid: u32, deadline: Instant) {
    kill_process_group(pid);
    let _ = child.kill();
    let _ = reap_test_child(child, deadline);
}

#[cfg(all(test, unix))]
fn run_bounded_direct(
    mut command: Command,
    deadline: Instant,
) -> Result<(Option<i32>, Vec<u8>), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start ruff ({error})"))?;
    let pid = child.id();
    let Some(mut stdout) = TestCapture::new(child.stdout.take()) else {
        stop_test_child(&mut child, pid, deadline);
        return Err("ruff stdout capture could not be initialized".to_string());
    };
    let Some(mut stderr) = TestCapture::new(child.stderr.take()) else {
        stop_test_child(&mut child, pid, deadline);
        return Err("ruff stderr capture could not be initialized".to_string());
    };
    let status = wait_and_drain_test(&mut child, &mut stdout, &mut stderr, deadline);
    if status.is_none() {
        stop_test_child(&mut child, pid, deadline);
    } else {
        kill_process_group(pid);
    }
    let stdout = finish_test_capture(&mut stdout, deadline);
    let stderr = finish_test_capture(&mut stderr, deadline);
    let status = status.ok_or_else(|| "ruff timed out or could not be waited on".to_string())?;
    let Some(stdout) = stdout else {
        return Err("ruff stdout did not close before the deadline".to_string());
    };
    if stderr.is_none() {
        return Err("ruff stderr did not close before the deadline".to_string());
    }
    Ok((Some(status.code().unwrap_or(-1)), stdout))
}

#[cfg(all(test, not(unix)))]
fn run_bounded_direct(
    command: Command,
    deadline: Instant,
) -> Result<(Option<i32>, Vec<u8>), String> {
    let _ = (command, deadline);
    Err("Ruff test execution is unavailable on this platform".to_string())
}

#[cfg(all(target_os = "linux", not(test)))]
fn run_bounded_via_supervisor(
    command: Command,
    deadline: Instant,
) -> Result<(Option<i32>, Vec<u8>), String> {
    let root = std::env::current_dir()
        .map_err(|error| format!("could not locate Ruff working directory ({error})"))?;
    let environment = crate::checks::commands::bounded_environment_snapshot()
        .map_err(|_| "Ruff environment exceeds bounded supervisor transport".to_string())?;
    let captured = crate::checks::commands::run_command_with_deadline(
        command,
        environment,
        &root,
        std::path::Path::new("."),
        std::path::Path::new("."),
        deadline,
        MAX_OUTPUT_BYTES,
    )
    .map_err(|error| format!("Ruff supervisor failed ({error:?})"))?;
    Ok((captured.code, captured.stdout))
}

#[cfg(all(unix, test))]
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

#[cfg(all(not(unix), test))]
fn set_process_group(_command: &mut Command) {}

#[cfg(all(unix, test))]
fn kill_process_group(pid: u32) {
    // SAFETY: kill has no memory preconditions; negative pid selects the child group.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(all(not(unix), test))]
fn kill_process_group(_pid: u32) {}

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

#[cfg(all(test, target_os = "linux"))]
mod fallback_tests {
    use super::*;

    struct EscapedChildCleanup {
        marker: std::path::PathBuf,
    }

    impl Drop for EscapedChildCleanup {
        fn drop(&mut self) {
            let Some(pid) = std::fs::read_to_string(&self.marker)
                .ok()
                .and_then(|value| value.trim().parse::<u32>().ok())
            else {
                return;
            };
            // SAFETY: the fixture wrote this PID and the test owns its process.
            unsafe {
                let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline
                && std::path::Path::new(&format!("/proc/{pid}")).exists()
            {
                thread::sleep(Duration::from_millis(10));
            }
            let _ = std::fs::remove_file(&self.marker);
        }
    }

    #[test]
    fn escaped_pipe_holder_does_not_leave_a_drain_thread_blocked() {
        let marker = std::env::temp_dir().join(format!(
            "lgtm-ruff-test-fallback-{}.pid",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&marker);
        let _cleanup = EscapedChildCleanup {
            marker: marker.clone(),
        };
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(
                r#"/usr/bin/setsid /bin/sh -c 'echo $$ > "$1"; exec /bin/sleep 120' fallback "$1" & while [ ! -s "$1" ]; do /bin/sleep 0.001; done; exit 0"#,
            )
            .arg("fallback")
            .arg(&marker);
        let started = Instant::now();
        let result = run_bounded_direct(command, started + Duration::from_millis(250));

        assert!(result.is_err(), "an open escaped pipe must be unverified");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "test fallback must return within its deadline"
        );
    }
}

#[cfg(all(test, unix))]
#[path = "ruff/tests.rs"]
mod tests;
