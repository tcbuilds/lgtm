use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const REQUEST_ENV: &str = "LGTM_INTERNAL_COMMAND_SUPERVISOR_REQUEST";
const MAX_CAPTURE_BYTES: u64 = 256 * 1024;
#[cfg(not(test))]
const MAX_RESPONSE_BYTES: usize = (MAX_CAPTURE_BYTES as usize * 4) + 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const QUIESCENCE: Duration = Duration::from_millis(20);
const CLEANUP_RESERVE: Duration = Duration::from_millis(50);
#[cfg(not(test))]
const PARENT_RESERVE: Duration = Duration::from_millis(50);

pub fn platform_id() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(target_os = "linux")]
pub const CONTAINMENT_VERSION: &str = "linux-isolated-subreaper-v2";
#[cfg(not(target_os = "linux"))]
pub const CONTAINMENT_VERSION: &str = "unavailable-v1";

#[cfg_attr(test, allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum ContainedRunError {
    CouldNotRun,
    ContainmentUnavailable,
    ContainmentViolation,
    ContainmentUnproven,
}

pub(crate) struct Captured {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SupervisorRequest {
    argv: Vec<String>,
    cwd: String,
    timeout_ms: u64,
    path: Option<String>,
    home: Option<String>,
    ci: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SupervisorResponse {
    outcome: SupervisorOutcome,
    code: Option<i32>,
    stdout_hex: String,
    stderr_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SupervisorOutcome {
    Completed,
    CouldNotRun,
    ContainmentUnavailable,
    ContainmentViolation,
    ContainmentUnproven,
}

pub(crate) fn run_with_deadline(
    argv: &[String],
    cwd: &Path,
    deadline: Instant,
) -> Result<Captured, ContainedRunError> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        run_via_supervisor(argv, cwd, deadline)
    }
    // Unit tests share one process and cannot exec the normal CLI entry point.
    // The production boundary is covered by integration tests through the real
    // binary; unit tests retain bounded process-group behavior only.
    #[cfg(all(target_os = "linux", test))]
    {
        let command = configured_command(argv, cwd);
        let captured =
            crate::checks::gitleaks::runner::run_details_with_deadline(command, deadline)
                .ok_or(ContainedRunError::CouldNotRun)?;
        if captured.process_group_survived {
            return Err(ContainedRunError::ContainmentViolation);
        }
        Ok(Captured {
            code: captured.code,
            stdout: captured.stdout,
            stderr: captured.stderr,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (argv, cwd, deadline);
        Err(ContainedRunError::ContainmentUnavailable)
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn run_via_supervisor(
    argv: &[String],
    cwd: &Path,
    deadline: Instant,
) -> Result<Captured, ContainedRunError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let supervisor_budget = remaining
        .checked_sub(PARENT_RESERVE)
        .ok_or(ContainedRunError::CouldNotRun)?;
    let timeout_ms = supervisor_budget.as_millis().min(u128::from(u64::MAX)) as u64;
    if timeout_ms == 0 {
        return Err(ContainedRunError::CouldNotRun);
    }
    let request = SupervisorRequest {
        argv: argv.to_vec(),
        cwd: cwd.to_string_lossy().into_owned(),
        timeout_ms,
        path: std::env::var("PATH").ok(),
        home: std::env::var("HOME").ok(),
        ci: std::env::var("CI").ok(),
    };
    let serialized = serde_json::to_string(&request).map_err(|_| ContainedRunError::CouldNotRun)?;
    let executable = std::env::current_exe().map_err(|_| ContainedRunError::CouldNotRun)?;
    let mut command = Command::new(executable);
    command
        .arg("__command-supervisor")
        .env_clear()
        .env(REQUEST_ENV, serialized);
    let captured = crate::checks::gitleaks::runner::run_details_with_deadline_and_limit(
        command,
        deadline,
        MAX_RESPONSE_BYTES as u64,
    )
    .ok_or(ContainedRunError::ContainmentUnproven)?;
    let _supervisor_stderr_bytes = captured.stderr.len();
    if captured.process_group_survived
        || captured.code != Some(0)
        || captured.stdout.len() > MAX_RESPONSE_BYTES
    {
        return Err(ContainedRunError::ContainmentUnproven);
    }
    let response: SupervisorResponse = serde_json::from_slice(&captured.stdout)
        .map_err(|_| ContainedRunError::ContainmentUnproven)?;
    let stdout = decode_hex(&response.stdout_hex).ok_or(ContainedRunError::ContainmentUnproven)?;
    let stderr = decode_hex(&response.stderr_hex).ok_or(ContainedRunError::ContainmentUnproven)?;
    if stdout.len() > MAX_CAPTURE_BYTES as usize || stderr.len() > MAX_CAPTURE_BYTES as usize {
        return Err(ContainedRunError::ContainmentUnproven);
    }
    match response.outcome {
        SupervisorOutcome::Completed => Ok(Captured {
            code: response.code,
            stdout,
            stderr,
        }),
        SupervisorOutcome::CouldNotRun => Err(ContainedRunError::CouldNotRun),
        SupervisorOutcome::ContainmentUnavailable => Err(ContainedRunError::ContainmentUnavailable),
        SupervisorOutcome::ContainmentViolation => Err(ContainedRunError::ContainmentViolation),
        SupervisorOutcome::ContainmentUnproven => Err(ContainedRunError::ContainmentUnproven),
    }
}

/// Hidden CLI entry point. It is intentionally an exec boundary: only this
/// short-lived process becomes a Linux child subreaper.
#[doc(hidden)]
pub fn run_from_environment() -> ExitCode {
    let response = std::env::var(REQUEST_ENV)
        .ok()
        .and_then(|raw| serde_json::from_str::<SupervisorRequest>(&raw).ok())
        .map_or_else(unproven_response, run_supervisor);
    match serde_json::to_writer(std::io::stdout().lock(), &response) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(target_os = "linux")]
fn run_supervisor(request: SupervisorRequest) -> SupervisorResponse {
    if request.argv.is_empty() || request.timeout_ms == 0 || direct_children().is_err() {
        return unproven_response();
    }
    let mut original_subreaper = 0;
    // SAFETY: prctl writes one integer to the supplied valid pointer.
    let inspected = unsafe {
        libc::prctl(
            libc::PR_GET_CHILD_SUBREAPER,
            &mut original_subreaper as *mut libc::c_int,
            0,
            0,
            0,
        )
    } == 0;
    // SAFETY: this changes child reparenting only in the dedicated supervisor.
    let enabled = inspected
        && original_subreaper == 0
        && unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;
    if !enabled {
        return response(
            SupervisorOutcome::ContainmentUnavailable,
            None,
            Vec::new(),
            Vec::new(),
        );
    }

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(request.timeout_ms))
        .unwrap_or_else(Instant::now);
    let Some(execution_deadline) = deadline.checked_sub(CLEANUP_RESERVE) else {
        return unproven_response();
    };
    let mut command = command_from_request(&request);
    prepare_command(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return response(SupervisorOutcome::CouldNotRun, None, Vec::new(), Vec::new()),
    };
    let pid = child.id();
    let stdout = drain_bounded(child.stdout.take());
    let stderr = drain_bounded(child.stderr.take());
    let status = wait_bounded(&mut child, execution_deadline);
    if status.is_none() {
        kill_process_group(pid);
        let _ = child.kill();
    }
    let direct_reaped = status.is_some() || reap_direct_child(&mut child, deadline);
    let cleanup = terminate_adopted_descendants(pid, deadline);
    let captured_stdout = join_bounded(stdout, deadline);
    let captured_stderr = join_bounded(stderr, deadline);

    let outcome = match cleanup {
        // A command cutoff is already a non-passing wait result; preserve its
        // timeout classification even when killing the process group leaves
        // an adopted child for cleanup to reap.
        Cleanup::Violation if status.is_none() => SupervisorOutcome::CouldNotRun,
        Cleanup::Violation => SupervisorOutcome::ContainmentViolation,
        Cleanup::Clean
            if direct_reaped
                && status.is_some()
                && captured_stdout.is_some()
                && captured_stderr.is_some() =>
        {
            SupervisorOutcome::Completed
        }
        Cleanup::Clean if direct_reaped => SupervisorOutcome::CouldNotRun,
        Cleanup::Clean | Cleanup::Unproven => SupervisorOutcome::ContainmentUnproven,
    };
    response(
        outcome,
        status.and_then(|status| status.code()),
        captured_stdout.unwrap_or_default(),
        captured_stderr.unwrap_or_default(),
    )
}

#[cfg(not(target_os = "linux"))]
fn run_supervisor(_request: SupervisorRequest) -> SupervisorResponse {
    response(
        SupervisorOutcome::ContainmentUnavailable,
        None,
        Vec::new(),
        Vec::new(),
    )
}

#[cfg(test)]
fn configured_command(argv: &[String], cwd: &Path) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]).current_dir(cwd);
    apply_environment(&mut command);
    command
}

fn command_from_request(request: &SupervisorRequest) -> Command {
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .current_dir(&request.cwd)
        .env_clear();
    if let Some(path) = &request.path {
        command.env("PATH", path);
    }
    if let Some(home) = &request.home {
        command.env("HOME", home);
    }
    if let Some(ci) = &request.ci {
        command.env("CI", ci);
    }
    command
}

#[cfg(test)]
fn apply_environment(command: &mut Command) {
    let path = std::env::var_os("PATH");
    let home = std::env::var_os("HOME");
    let ci = std::env::var_os("CI");
    command.env_clear();
    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(home) = home {
        command.env("HOME", home);
    }
    if let Some(ci) = ci {
        command.env("CI", ci);
    }
}

fn prepare_command(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_own_process_group(command);
}

fn wait_bounded(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Err(_) => return None,
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn reap_direct_child(child: &mut std::process::Child, deadline: Instant) -> bool {
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
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn join_bounded(handle: Option<thread::JoinHandle<Vec<u8>>>, deadline: Instant) -> Option<Vec<u8>> {
    let handle = handle?;
    while !handle.is_finished() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
    handle.join().ok()
}

fn drain_bounded<R: Read + Send + 'static>(
    stream: Option<R>,
) -> Option<thread::JoinHandle<Vec<u8>>> {
    stream.map(|mut stream| {
        thread::spawn(move || {
            let mut captured = Vec::new();
            let _ = (&mut stream)
                .take(MAX_CAPTURE_BYTES)
                .read_to_end(&mut captured);
            let mut discard = [0_u8; 8 * 1024];
            while let Ok(read) = stream.read(&mut discard) {
                if read == 0 {
                    break;
                }
            }
            captured
        })
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cleanup {
    Clean,
    Violation,
    Unproven,
}

#[cfg(target_os = "linux")]
fn terminate_adopted_descendants(direct_pid: u32, deadline: Instant) -> Cleanup {
    let mut found = false;
    let mut quiet_since = None;
    loop {
        let reaped_adopted = match reap_exited_children(direct_pid as libc::pid_t) {
            Ok(reaped) => reaped,
            Err(()) => return Cleanup::Unproven,
        };
        if reaped_adopted {
            // An adopted descendant can already be a zombie before the first
            // procfs scan. Treat that activity exactly like an observed live
            // descendant and restart the quiescence interval.
            found = true;
            quiet_since = None;
        }
        let children = match direct_children() {
            Ok(children) => children,
            Err(()) => return Cleanup::Unproven,
        };
        if children.is_empty() {
            let quiet_since = quiet_since.get_or_insert_with(Instant::now);
            if quiet_since.elapsed() >= QUIESCENCE {
                return if found {
                    Cleanup::Violation
                } else {
                    Cleanup::Clean
                };
            }
        } else {
            found = true;
            quiet_since = None;
            for pid in children {
                // SAFETY: every direct child of this dedicated supervisor was
                // created by the one configured command.
                unsafe {
                    let _ = libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Cleanup::Unproven;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(target_os = "linux")]
fn reap_exited_children(direct_pid: libc::pid_t) -> Result<bool, ()> {
    let mut reaped_adopted = false;
    loop {
        // SAFETY: waitpid with WNOHANG does not write through the null status pointer.
        let reaped = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
        match reaped {
            0 => return Ok(reaped_adopted),
            pid if pid > 0 => {
                reaped_adopted |= pid != direct_pid;
            }
            -1 => {
                let error = std::io::Error::last_os_error().raw_os_error();
                if error == Some(libc::EINTR) {
                    continue;
                }
                // ECHILD is the normal no-waitable-children result after the
                // direct command has been reaped; every other wait error is
                // containment-unproven rather than a clean cleanup.
                return (error == Some(libc::ECHILD))
                    .then_some(reaped_adopted)
                    .ok_or(());
            }
            _ => return Err(()),
        }
    }
}

#[cfg(target_os = "linux")]
fn direct_children() -> Result<Vec<libc::pid_t>, ()> {
    let path = format!("/proc/self/task/{}/children", std::process::id());
    let raw = std::fs::read_to_string(path).map_err(|_| ())?;
    raw.split_whitespace()
        .map(|pid| pid.parse::<libc::pid_t>().map_err(|_| ()))
        .collect()
}

fn response(
    outcome: SupervisorOutcome,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> SupervisorResponse {
    SupervisorResponse {
        outcome,
        code,
        stdout_hex: encode_hex(&stdout),
        stderr_hex: encode_hex(&stderr),
    }
}

fn unproven_response() -> SupervisorResponse {
    response(
        SupervisorOutcome::ContainmentUnproven,
        None,
        Vec::new(),
        Vec::new(),
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn set_own_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setpgid is async-signal-safe and touches no shared Rust state.
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
fn set_own_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    // SAFETY: negative pid selects the configured command's process group.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_binary_capture() {
        let bytes = [0, 1, 15, 16, 127, 255];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes.to_vec()));
        assert!(decode_hex("0").is_none());
        assert!(decode_hex("xx").is_none());
    }
}
