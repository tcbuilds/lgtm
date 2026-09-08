use std::ffi::{OsStr, OsString};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::io::{ErrorKind, Read};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::process::Stdio;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

const REQUEST_ENV: &str = "LGTM_INTERNAL_COMMAND_SUPERVISOR_REQUEST";
const MAX_CAPTURE_BYTES: u64 = 256 * 1024;
const MAX_CAPTURE_LIMIT_BYTES: u64 = 1024 * 1024;
#[cfg(all(target_os = "linux", not(test)))]
const MAX_RESPONSE_BYTES: usize = (MAX_CAPTURE_LIMIT_BYTES as usize * 4) + 16 * 1024;
// Request paths and PATH/HOME/CI are hex-encoded so Unix byte strings remain
// lossless without expanding each byte into a JSON array element. Keep every
// field and the complete JSON envelope below Linux's per-environment-entry
// limit, even when all fields are near their configured bounds.
const MAX_REQUEST_PATH_BYTES: usize = 8 * 1024;
const MAX_REQUEST_ENV_BYTES: usize = 8 * 1024;
const MAX_REQUEST_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_REQUEST_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_REQUEST_ENVELOPE_BYTES: usize = 96 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const QUIESCENCE: Duration = Duration::from_millis(20);
const CLEANUP_RESERVE: Duration = Duration::from_millis(50);
const REQUEST_TIMEOUT_RESERVE_MS: u64 = 50;

pub fn platform_id() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(target_os = "linux")]
pub const CONTAINMENT_VERSION: &str = "linux-isolated-subreaper-v3";
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
    pub(crate) cwd_identity: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SupervisorRequest {
    argv: Vec<String>,
    repository_root: String,
    workspace_root: String,
    cwd: String,
    #[serde(default)]
    timeout_ms: Option<String>,
    #[serde(default)]
    deadline_ns: Option<String>,
    #[serde(default)]
    environment: Option<Vec<EncodedEnvironment>>,
    #[serde(default = "default_capture_limit")]
    capture_limit: u64,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    home: Option<String>,
    #[serde(default)]
    ci: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EncodedEnvironment {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SupervisorResponse {
    outcome: SupervisorOutcome,
    code: Option<i32>,
    stdout_hex: String,
    stderr_hex: String,
    #[serde(default)]
    stdout_truncated: bool,
    #[serde(default)]
    stderr_truncated: bool,
    #[serde(default)]
    cwd_identity: Option<String>,
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
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    deadline: Instant,
) -> Result<Captured, ContainedRunError> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        let environment = ["PATH", "HOME", "CI"]
            .into_iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect();
        run_command_with_deadline(
            command,
            environment,
            repository_root,
            workspace_root,
            cwd,
            deadline,
            MAX_CAPTURE_BYTES,
        )
    }
    // Unit tests share one process and cannot exec the normal CLI entry point.
    // Keep the test-only direct path bounded too: unlike the production path it
    // cannot create a dedicated subreaper, but it must never abandon a reader
    // thread when a descendant retains one of the captured pipes.
    #[cfg(all(unix, test))]
    {
        let command = configured_command(argv, &repository_root.join(cwd));
        let captured = run_test_command_with_deadline(command, deadline)?;
        #[cfg(target_os = "linux")]
        {
            let cwd_capability =
                crate::fsutil::open_directory_capability(repository_root, workspace_root, cwd)
                    .map_err(|_| ContainedRunError::ContainmentUnproven)?;
            let cwd_identity = crate::fsutil::directory_identity(&cwd_capability)
                .map_err(|_| ContainedRunError::ContainmentUnproven)?;
            Ok(Captured {
                code: captured.code,
                stdout: captured.stdout,
                stderr: captured.stderr,
                cwd_identity: Some(cwd_identity),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (repository_root, workspace_root, cwd);
            Ok(Captured {
                code: captured.code,
                stdout: captured.stdout,
                stderr: captured.stderr,
                cwd_identity: None,
            })
        }
    }
    // Unsupported platforms have no safe nonblocking descriptor primitive for
    // this test-only fallback. Production remains fail-closed above.
    #[cfg(all(not(unix), test))]
    {
        let _ = (argv, repository_root, workspace_root, cwd, deadline);
        Err(ContainedRunError::ContainmentUnavailable)
    }
    #[cfg(all(not(target_os = "linux"), not(test)))]
    {
        let _ = (argv, repository_root, workspace_root, cwd, deadline);
        Err(ContainedRunError::ContainmentUnavailable)
    }
}

#[cfg(all(target_os = "linux", not(test)))]
pub(crate) fn bounded_environment_snapshot() -> Result<Vec<(OsString, OsString)>, ()> {
    let mut snapshot = Vec::new();
    let mut total_bytes = 0_usize;
    for (name, value) in std::env::vars_os() {
        if snapshot.len() >= MAX_REQUEST_ENVIRONMENT_ENTRIES {
            return Err(());
        }
        let encoded_name = encode_environment_value(name.as_os_str())?;
        let encoded_value = encode_environment_value(value.as_os_str())?;
        total_bytes = total_bytes
            .checked_add(encoded_name.len())
            .and_then(|bytes| bytes.checked_add(encoded_value.len()))
            .ok_or(())?;
        if total_bytes > MAX_REQUEST_ENVIRONMENT_BYTES {
            return Err(());
        }
        snapshot.push((name, value));
    }
    Ok(snapshot)
}

#[cfg(all(target_os = "linux", not(test)))]
pub(crate) fn run_command_with_deadline(
    command: Command,
    environment: Vec<(OsString, OsString)>,
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    deadline: Instant,
    capture_limit: u64,
) -> Result<Captured, ContainedRunError> {
    run_via_supervisor(
        command,
        environment,
        repository_root,
        workspace_root,
        cwd,
        deadline,
        capture_limit,
    )
}

#[cfg(all(target_os = "linux", not(test)))]
fn run_via_supervisor(
    command: Command,
    environment: Vec<(OsString, OsString)>,
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    deadline: Instant,
    capture_limit: u64,
) -> Result<Captured, ContainedRunError> {
    valid_capture_limit(capture_limit).ok_or(ContainedRunError::CouldNotRun)?;
    let deadline_ns = monotonic_deadline_ns(deadline).ok_or(ContainedRunError::CouldNotRun)?;
    let argv = command_argv(&command).ok_or(ContainedRunError::CouldNotRun)?;
    let request = build_request_with_deadline(
        &argv,
        &environment,
        repository_root,
        workspace_root,
        cwd,
        deadline_ns,
        capture_limit,
    )
    .map_err(|_| ContainedRunError::CouldNotRun)?;
    let serialized = serialize_request(&request).map_err(|_| ContainedRunError::CouldNotRun)?;
    let executable = std::env::current_exe().map_err(|_| ContainedRunError::CouldNotRun)?;
    let mut supervisor = Command::new(executable);
    supervisor
        .arg("__command-supervisor")
        .env_clear()
        .env(REQUEST_ENV, serialized);
    let captured = crate::checks::gitleaks::runner::run_details_with_deadline_and_limit(
        supervisor,
        deadline,
        (MAX_RESPONSE_BYTES as u64) + 1,
    )
    .ok_or(ContainedRunError::ContainmentUnproven)?;
    if !supervisor_capture_is_bounded(&captured, MAX_RESPONSE_BYTES)
        || captured.code != Some(0)
        || captured.stdout.len() > MAX_RESPONSE_BYTES
    {
        return Err(ContainedRunError::ContainmentUnproven);
    }
    let response: SupervisorResponse = serde_json::from_slice(&captured.stdout)
        .map_err(|_| ContainedRunError::ContainmentUnproven)?;
    let stdout = decode_hex(&response.stdout_hex).ok_or(ContainedRunError::ContainmentUnproven)?;
    let stderr = decode_hex(&response.stderr_hex).ok_or(ContainedRunError::ContainmentUnproven)?;
    if response.stdout_truncated
        || response.stderr_truncated
        || stdout.len() > capture_limit as usize
        || stderr.len() > capture_limit as usize
    {
        return Err(ContainedRunError::ContainmentUnproven);
    }
    match response.outcome {
        SupervisorOutcome::Completed => Ok(Captured {
            code: response.code,
            stdout,
            stderr,
            cwd_identity: response.cwd_identity,
        }),
        SupervisorOutcome::CouldNotRun => Err(ContainedRunError::CouldNotRun),
        SupervisorOutcome::ContainmentUnavailable => Err(ContainedRunError::ContainmentUnavailable),
        SupervisorOutcome::ContainmentViolation => Err(ContainedRunError::ContainmentViolation),
        SupervisorOutcome::ContainmentUnproven => Err(ContainedRunError::ContainmentUnproven),
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn command_argv(command: &Command) -> Option<Vec<String>> {
    let program = command.get_program().to_str()?.to_string();
    let mut argv = vec![program];
    argv.extend(
        command
            .get_args()
            .map(|argument| argument.to_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
    );
    Some(argv)
}

#[cfg(any(target_os = "linux", all(unix, test)))]
struct NonblockingCapture<R> {
    stream: Option<R>,
    bytes: Vec<u8>,
    truncated: bool,
    failed: bool,
    limit: usize,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl<R: Read + AsRawFd> NonblockingCapture<R> {
    fn new(stream: Option<R>, limit: usize) -> Option<Self> {
        let stream = stream?;
        set_nonblocking(stream.as_raw_fd()).ok()?;
        Some(Self {
            stream: Some(stream),
            bytes: Vec::new(),
            truncated: false,
            failed: false,
            limit,
        })
    }

    fn read_available(&mut self) -> bool {
        let Some(stream) = self.stream.as_mut() else {
            return true;
        };
        let mut buffer = [0_u8; 8 * 1024];
        match stream.read(&mut buffer) {
            Ok(0) => {
                self.stream = None;
                true
            }
            Ok(read) => {
                let remaining = self.limit.saturating_sub(self.bytes.len());
                let accepted = read.min(remaining);
                self.bytes.extend_from_slice(&buffer[..accepted]);
                self.truncated |= accepted < read;
                true
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => true,
            Err(_) => {
                self.failed = true;
                self.stream = None;
                false
            }
        }
    }

    fn is_closed(&self) -> bool {
        self.stream.is_none()
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
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

#[cfg(all(target_os = "linux", not(test)))]
fn monotonic_deadline_ns(deadline: Instant) -> Option<u64> {
    let now = monotonic_now_ns()?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    now.checked_add(remaining.as_nanos().min(u128::from(u64::MAX)) as u64)
}

#[cfg(target_os = "linux")]
fn monotonic_now_ns() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one timespec to a valid local pointer.
    (unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0)
        .then(|| {
            (time.tv_sec as u64)
                .checked_mul(1_000_000_000)?
                .checked_add(time.tv_nsec as u64)
        })
        .flatten()
}

/// Hidden CLI entry point. It is intentionally an exec boundary: only this
/// short-lived process becomes a Linux child subreaper.
#[doc(hidden)]
pub fn run_from_environment() -> ExitCode {
    let response = std::env::var(REQUEST_ENV)
        .ok()
        .filter(|raw| request_payload_is_bounded(raw))
        .and_then(|raw| serde_json::from_str::<SupervisorRequest>(&raw).ok())
        .filter(request_is_valid)
        .map_or_else(unproven_response, run_supervisor);
    match serde_json::to_writer(std::io::stdout().lock(), &response) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(target_os = "linux")]
fn run_supervisor(request: SupervisorRequest) -> SupervisorResponse {
    if !request_is_valid(&request) {
        return unproven_response();
    }
    let capture_limit = match valid_capture_limit(request.capture_limit) {
        Some(limit) => limit,
        None => return unproven_response(),
    };
    let deadline = match request_deadline(&request) {
        Some(deadline) => deadline,
        None => return unproven_response(),
    };
    if direct_children().is_err() {
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

    let Some(execution_deadline) = deadline.checked_sub(CLEANUP_RESERVE) else {
        return unproven_response();
    };
    let (mut command, cwd_capability) = match command_from_request(&request) {
        Ok(command) => command,
        Err(_) => return unproven_response(),
    };
    let Ok(cwd_identity) = crate::fsutil::directory_identity(&cwd_capability) else {
        return unproven_response();
    };
    prepare_command(&mut command, cwd_capability.as_raw_fd());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            let mut response =
                response(SupervisorOutcome::CouldNotRun, None, Vec::new(), Vec::new());
            response.cwd_identity = Some(cwd_identity);
            return response;
        }
    };
    let pid = child.id();
    let Some(mut stdout) = NonblockingCapture::new(child.stdout.take(), capture_limit) else {
        cleanup_spawned_command(&mut child, pid, deadline);
        return unproven_response();
    };
    let Some(mut stderr) = NonblockingCapture::new(child.stderr.take(), capture_limit) else {
        cleanup_spawned_command(&mut child, pid, deadline);
        return unproven_response();
    };
    let status = wait_and_drain(&mut child, &mut stdout, &mut stderr, execution_deadline);
    if status.is_none() {
        kill_process_group(pid);
        let _ = child.kill();
    }
    let direct_reaped = status.is_some() || reap_direct_child(&mut child, deadline);
    let cleanup = terminate_adopted_descendants(pid, deadline);
    let captured_stdout = finish_capture(&mut stdout, deadline);
    let captured_stderr = finish_capture(&mut stderr, deadline);

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
    let identity_still_current =
        request_cwd_identity(&request).is_some_and(|identity| identity == cwd_identity);
    let outcome = if identity_still_current {
        outcome
    } else {
        SupervisorOutcome::ContainmentUnproven
    };
    let mut response = response(
        outcome,
        identity_still_current
            .then(|| status.and_then(|status| status.code()))
            .flatten(),
        captured_stdout
            .as_ref()
            .map_or_else(Vec::new, |capture| capture.bytes.clone()),
        captured_stderr
            .as_ref()
            .map_or_else(Vec::new, |capture| capture.bytes.clone()),
    );
    if let Some(capture) = captured_stdout {
        response.stdout_truncated = capture.truncated;
    }
    if let Some(capture) = captured_stderr {
        response.stderr_truncated = capture.truncated;
    }
    response.cwd_identity = Some(cwd_identity);
    response
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

#[cfg(all(unix, test))]
fn run_test_command_with_deadline(
    mut command: Command,
    deadline: Instant,
) -> Result<Captured, ContainedRunError> {
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(ContainedRunError::CouldNotRun);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_own_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|_| ContainedRunError::CouldNotRun)?;
    let pid = child.id();
    let Some(mut stdout) = NonblockingCapture::new(child.stdout.take(), MAX_CAPTURE_BYTES as usize)
    else {
        kill_process_group(pid);
        let _ = child.kill();
        let _ = reap_direct_child(&mut child, deadline);
        return Err(ContainedRunError::ContainmentUnproven);
    };
    let Some(mut stderr) = NonblockingCapture::new(child.stderr.take(), MAX_CAPTURE_BYTES as usize)
    else {
        kill_process_group(pid);
        let _ = child.kill();
        let _ = reap_direct_child(&mut child, deadline);
        return Err(ContainedRunError::ContainmentUnproven);
    };

    let status = wait_and_drain(&mut child, &mut stdout, &mut stderr, deadline);
    if status.is_none() {
        kill_process_group(pid);
        let _ = child.kill();
    }
    let direct_reaped = status.is_some() || reap_direct_child(&mut child, deadline);
    let process_group_survived = if status.is_some() {
        test_process_group_exists(pid)
    } else {
        Some(false)
    };
    // Always issue the bounded group cleanup before trying to close either
    // capture stream. This also handles same-group descendants that outlive a
    // successfully waited direct child.
    kill_process_group(pid);
    let captured_stdout = finish_capture(&mut stdout, deadline);
    let captured_stderr = finish_capture(&mut stderr, deadline);

    let Some(process_group_survived) = process_group_survived else {
        return Err(ContainedRunError::ContainmentUnproven);
    };
    if process_group_survived {
        return Err(ContainedRunError::ContainmentViolation);
    }
    if status.is_none() {
        return Err(ContainedRunError::CouldNotRun);
    }
    if !direct_reaped {
        return Err(ContainedRunError::ContainmentUnproven);
    }
    let (Some(stdout), Some(stderr)) = (captured_stdout, captured_stderr) else {
        return Err(ContainedRunError::CouldNotRun);
    };
    if stdout.truncated || stderr.truncated {
        return Err(ContainedRunError::CouldNotRun);
    }
    Ok(Captured {
        code: status.and_then(|status| status.code()),
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        cwd_identity: None,
    })
}

#[cfg(all(unix, test))]
fn test_process_group_exists(pid: u32) -> Option<bool> {
    // SAFETY: signal zero only probes the configured command's process group.
    let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
    if result == 0 {
        return Some(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Some(false),
        Some(libc::EPERM) => Some(true),
        _ => None,
    }
}

fn request_cwd_identity(request: &SupervisorRequest) -> Option<String> {
    let repository_root = decode_path(&request.repository_root)?;
    let workspace_root = decode_path(&request.workspace_root)?;
    let cwd = decode_path(&request.cwd)?;
    let capability =
        crate::fsutil::open_directory_capability(&repository_root, &workspace_root, &cwd).ok()?;
    crate::fsutil::directory_identity(&capability).ok()
}

fn supervisor_capture_is_bounded(
    captured: &crate::checks::gitleaks::runner::Captured,
    response_limit: usize,
) -> bool {
    !captured.process_group_survived && captured.stderr.len() <= response_limit
}

fn request_payload_is_bounded(raw: &str) -> bool {
    raw.len() <= MAX_REQUEST_ENVELOPE_BYTES
}

fn request_is_valid(request: &SupervisorRequest) -> bool {
    if request.argv.is_empty()
        || request.argv[0].is_empty()
        || request.argv.iter().any(|argument| argument.contains('\0'))
    {
        return false;
    }
    if !encoded_path_is_valid(&request.repository_root)
        || !encoded_path_is_valid(&request.workspace_root)
        || !encoded_path_is_valid(&request.cwd)
        || valid_capture_limit(request.capture_limit).is_none()
    {
        return false;
    }
    let environment_is_valid = request.environment.as_deref().map_or_else(
        || {
            [&request.path, &request.home, &request.ci]
                .into_iter()
                .flatten()
                .all(|value| encoded_environment_value_is_valid(value))
        },
        encoded_environment_entries_are_valid,
    );
    environment_is_valid && serialize_request(request).is_ok()
}

fn encoded_path_is_valid(value: &str) -> bool {
    value.len() <= MAX_REQUEST_PATH_BYTES.saturating_mul(2) && decode_path(value).is_some()
}

fn encoded_environment_value_is_valid(value: &str) -> bool {
    value.len() <= MAX_REQUEST_ENV_BYTES.saturating_mul(2) && decode_environment(value).is_some()
}

fn encoded_environment_name_is_valid(value: &str) -> bool {
    value.len() <= MAX_REQUEST_ENV_BYTES.saturating_mul(2)
        && decode_environment_name(value).is_some()
}

fn encoded_environment_entries_are_valid(environment: &[EncodedEnvironment]) -> bool {
    if environment.len() > MAX_REQUEST_ENVIRONMENT_ENTRIES {
        return false;
    }
    let mut total_bytes = 0_usize;
    environment.iter().all(|entry| {
        if !encoded_environment_name_is_valid(&entry.name)
            || !encoded_environment_value_is_valid(&entry.value)
        {
            return false;
        }
        let Some(next_total) = total_bytes
            .checked_add(entry.name.len())
            .and_then(|total| total.checked_add(entry.value.len()))
        else {
            return false;
        };
        total_bytes = next_total;
        total_bytes <= MAX_REQUEST_ENVIRONMENT_BYTES
    })
}

#[cfg(target_os = "linux")]
fn request_deadline(request: &SupervisorRequest) -> Option<Instant> {
    if let Some(raw_deadline) = &request.deadline_ns {
        let deadline_ns = raw_deadline.parse::<u64>().ok()?;
        let now_ns = monotonic_now_ns()?;
        let remaining_ns = deadline_ns.checked_sub(now_ns)?;
        return Instant::now().checked_add(Duration::from_nanos(remaining_ns));
    }
    let timeout_ms = request.timeout_ms.as_deref()?.parse::<u64>().ok()?;
    (timeout_ms > 0).then(|| Instant::now().checked_add(Duration::from_millis(timeout_ms)))?
}

fn command_from_request(
    request: &SupervisorRequest,
) -> Result<(Command, std::fs::File), ContainedRunError> {
    let repository_root =
        decode_path(&request.repository_root).ok_or(ContainedRunError::ContainmentUnproven)?;
    let workspace_root =
        decode_path(&request.workspace_root).ok_or(ContainedRunError::ContainmentUnproven)?;
    let cwd = decode_path(&request.cwd).ok_or(ContainedRunError::ContainmentUnproven)?;
    let cwd_capability =
        crate::fsutil::open_directory_capability(&repository_root, &workspace_root, &cwd)
            .map_err(|_| ContainedRunError::ContainmentUnproven)?;
    let mut command = Command::new(&request.argv[0]);
    command.args(&request.argv[1..]).env_clear();
    if let Some(environment) = &request.environment {
        for entry in environment {
            let name = decode_environment_name(&entry.name)
                .ok_or(ContainedRunError::ContainmentUnproven)?;
            let value =
                decode_environment(&entry.value).ok_or(ContainedRunError::ContainmentUnproven)?;
            command.env(name, value);
        }
    } else {
        for (name, value) in [
            ("PATH", &request.path),
            ("HOME", &request.home),
            ("CI", &request.ci),
        ] {
            if let Some(value) = value {
                let value =
                    decode_environment(value).ok_or(ContainedRunError::ContainmentUnproven)?;
                command.env(name, value);
            }
        }
    }
    Ok((command, cwd_capability))
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

#[cfg(target_os = "linux")]
fn prepare_command(command: &mut Command, cwd_fd: std::os::fd::RawFd) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_own_process_group(command);
    set_current_directory(command, cwd_fd);
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn wait_and_drain(
    child: &mut std::process::Child,
    stdout: &mut NonblockingCapture<std::process::ChildStdout>,
    stderr: &mut NonblockingCapture<std::process::ChildStderr>,
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
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn finish_capture<R: Read + AsRawFd>(
    capture: &mut NonblockingCapture<R>,
    deadline: Instant,
) -> Option<NonblockingCapture<R>> {
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
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
    let limit = capture.limit;
    (!capture.failed).then(|| {
        std::mem::replace(
            capture,
            NonblockingCapture {
                stream: None,
                bytes: Vec::new(),
                truncated: false,
                failed: false,
                limit,
            },
        )
    })
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

#[cfg(target_os = "linux")]
fn cleanup_spawned_command(child: &mut std::process::Child, pid: u32, deadline: Instant) {
    kill_process_group(pid);
    let _ = child.kill();
    // The direct child and every adopted descendant must get a bounded cleanup
    // attempt even when capture setup failed before the normal wait path.
    let _ = reap_direct_child(child, deadline);
    let _ = terminate_adopted_descendants(pid, deadline);
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cleanup {
    Clean,
    Violation,
    Unproven,
}

#[cfg(target_os = "linux")]
fn cleanup_decision(
    found: bool,
    quiet_elapsed: Duration,
    deadline_remaining: Duration,
) -> Option<Cleanup> {
    if quiet_elapsed >= QUIESCENCE {
        return Some(if found {
            Cleanup::Violation
        } else {
            Cleanup::Clean
        });
    }
    deadline_remaining.is_zero().then_some(Cleanup::Unproven)
}

#[cfg(target_os = "linux")]
fn terminate_adopted_descendants(direct_pid: u32, deadline: Instant) -> Cleanup {
    let mut found = false;
    let mut quiet_since = None;
    let mut observation_uncertain = false;
    loop {
        let reaped_adopted = match reap_exited_children(direct_pid as libc::pid_t, deadline) {
            Ok(reaped) => reaped,
            Err(()) => {
                observation_uncertain = true;
                false
            }
        };
        if reaped_adopted {
            // An adopted descendant can already be a zombie before the first
            // procfs scan. Treat that activity exactly like an observed live
            // descendant and restart the quiescence interval.
            found = true;
            quiet_since = None;
        }
        let children = match direct_children() {
            Ok(children) => Some(children),
            Err(()) => {
                observation_uncertain = true;
                None
            }
        };
        if let Some(children) = children {
            if children.is_empty() {
                if observation_uncertain {
                    quiet_since = None;
                } else {
                    let quiet_since = quiet_since.get_or_insert_with(Instant::now);
                    if let Some(cleanup) = cleanup_decision(
                        found,
                        quiet_since.elapsed(),
                        deadline.saturating_duration_since(Instant::now()),
                    ) {
                        return cleanup;
                    }
                }
            } else {
                found = true;
                quiet_since = None;
                for pid in children {
                    // SAFETY: every direct child of this dedicated supervisor
                    // was created by the one configured command.
                    unsafe {
                        let _ = libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        } else {
            quiet_since = None;
        }
        if observation_uncertain {
            // Group cleanup remains useful while procfs or waitpid observation
            // is unavailable, but it cannot establish proof for this run.
            kill_process_group(direct_pid);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Cleanup::Unproven;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(target_os = "linux")]
fn reap_exited_children(direct_pid: libc::pid_t, deadline: Instant) -> Result<bool, ()> {
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
                    if Instant::now() < deadline {
                        continue;
                    }
                    return Err(());
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

fn build_request(
    argv: &[String],
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    timeout_ms: u64,
) -> Result<SupervisorRequest, ()> {
    let environment = ["PATH", "HOME", "CI"]
        .into_iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
        .collect::<Vec<_>>();
    build_request_with_relative_timeout(
        argv,
        &environment,
        repository_root,
        workspace_root,
        cwd,
        timeout_ms,
    )
}

fn build_request_with_relative_timeout(
    argv: &[String],
    environment: &[(OsString, OsString)],
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    timeout_ms: u64,
) -> Result<SupervisorRequest, ()> {
    if argv.is_empty() || argv[0].is_empty() || argv.iter().any(|argument| argument.contains('\0'))
    {
        return Err(());
    }
    Ok(SupervisorRequest {
        argv: argv.to_vec(),
        repository_root: encode_path(repository_root).ok_or(())?,
        workspace_root: encode_path(workspace_root).ok_or(())?,
        cwd: encode_path(cwd).ok_or(())?,
        timeout_ms: Some(format!("{timeout_ms:020}")),
        deadline_ns: None,
        environment: Some(encode_environment_entries(environment)?),
        capture_limit: MAX_CAPTURE_BYTES,
        path: None,
        home: None,
        ci: None,
    })
}

#[cfg(all(target_os = "linux", not(test)))]
fn build_request_with_deadline(
    argv: &[String],
    environment: &[(OsString, OsString)],
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    deadline_ns: u64,
    capture_limit: u64,
) -> Result<SupervisorRequest, ()> {
    if argv.is_empty() || argv[0].is_empty() || argv.iter().any(|argument| argument.contains('\0'))
    {
        return Err(());
    }
    valid_capture_limit(capture_limit).ok_or(())?;
    Ok(SupervisorRequest {
        argv: argv.to_vec(),
        repository_root: encode_path(repository_root).ok_or(())?,
        workspace_root: encode_path(workspace_root).ok_or(())?,
        cwd: encode_path(cwd).ok_or(())?,
        timeout_ms: None,
        deadline_ns: Some(deadline_ns.to_string()),
        environment: Some(encode_environment_entries(environment)?),
        capture_limit,
        path: None,
        home: None,
        ci: None,
    })
}

fn encode_environment_entries(
    environment: &[(OsString, OsString)],
) -> Result<Vec<EncodedEnvironment>, ()> {
    if environment.len() > MAX_REQUEST_ENVIRONMENT_ENTRIES {
        return Err(());
    }
    let mut total_bytes = 0_usize;
    let mut encoded = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let encoded_name = encode_environment_value(name.as_os_str())?;
        let encoded_value = encode_environment_value(value.as_os_str())?;
        total_bytes = total_bytes
            .checked_add(encoded_name.len())
            .and_then(|bytes| bytes.checked_add(encoded_value.len()))
            .ok_or(())?;
        if total_bytes > MAX_REQUEST_ENVIRONMENT_BYTES {
            return Err(());
        }
        encoded.push(EncodedEnvironment {
            name: encoded_name,
            value: encoded_value,
        });
    }
    Ok(encoded)
}

#[cfg(test)]
fn request_is_transportable_with_environment(
    argv: &[String],
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    timeout_ms: u64,
) -> bool {
    build_request(argv, repository_root, workspace_root, cwd, timeout_ms)
        .and_then(|request| serialize_request(&request))
        .is_ok()
}

fn serialize_request(request: &SupervisorRequest) -> Result<String, ()> {
    let serialized = serde_json::to_string(request).map_err(|_| ())?;
    (serialized.len() <= MAX_REQUEST_ENVELOPE_BYTES)
        .then_some(serialized)
        .ok_or(())
}

pub fn request_is_transportable(
    argv: &[String],
    repository_root: &Path,
    workspace_root: &Path,
    cwd: &Path,
    timeout_ms: u64,
) -> bool {
    let timeout_ms = timeout_ms.saturating_sub(REQUEST_TIMEOUT_RESERVE_MS);
    build_request(argv, repository_root, workspace_root, cwd, timeout_ms)
        .and_then(|request| serialize_request(&request))
        .is_ok()
}

fn encode_path(path: &Path) -> Option<String> {
    #[cfg(unix)]
    let bytes = path.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let bytes = path.to_str()?.as_bytes();
    (bytes.len() <= MAX_REQUEST_PATH_BYTES && !bytes.contains(&0)).then(|| encode_hex(bytes))
}

fn default_capture_limit() -> u64 {
    MAX_CAPTURE_BYTES
}

fn valid_capture_limit(limit: u64) -> Option<usize> {
    (limit > 0 && limit <= MAX_CAPTURE_LIMIT_BYTES)
        .then_some(limit)
        .and_then(|limit| usize::try_from(limit).ok())
}

fn encode_environment_value(value: &OsStr) -> Result<String, ()> {
    #[cfg(unix)]
    let bytes = value.as_bytes();
    #[cfg(not(unix))]
    let bytes = value.to_str().ok_or(())?.as_bytes();
    if bytes.len() > MAX_REQUEST_ENV_BYTES || bytes.contains(&0) {
        return Err(());
    }
    Ok(encode_hex(bytes))
}

fn decode_environment(value: &str) -> Option<OsString> {
    let bytes = decode_hex(value)?;
    if bytes.len() > MAX_REQUEST_ENV_BYTES || bytes.contains(&0) {
        return None;
    }
    #[cfg(unix)]
    {
        Some(OsString::from_vec(bytes))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes).ok().map(OsString::from)
    }
}

fn decode_environment_name(value: &str) -> Option<OsString> {
    let name = decode_environment(value)?;
    #[cfg(unix)]
    let bytes = name.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let bytes = name.to_str()?.as_bytes();
    (!bytes.is_empty() && !bytes.contains(&b'=')).then_some(name)
}

fn decode_path(value: &str) -> Option<PathBuf> {
    let bytes = decode_hex(value)?;
    if bytes.len() > MAX_REQUEST_PATH_BYTES || bytes.contains(&0) {
        return None;
    }
    #[cfg(unix)]
    {
        Some(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes)
            .ok()
            .map(|value| PathBuf::from(OsString::from(value)))
    }
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
        stdout_truncated: false,
        stderr_truncated: false,
        cwd_identity: None,
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

#[cfg(target_os = "linux")]
fn set_current_directory(command: &mut Command, cwd_fd: std::os::fd::RawFd) {
    use std::os::unix::process::CommandExt;
    // SAFETY: cwd_fd is retained by the parent until spawn completes and is a
    // directory opened with O_DIRECTORY|O_NOFOLLOW.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(cwd_fd) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

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

    #[cfg(target_os = "linux")]
    struct EscapedProcessGuard {
        pid_file: PathBuf,
        marker_file: Option<PathBuf>,
    }

    #[cfg(target_os = "linux")]
    impl Drop for EscapedProcessGuard {
        fn drop(&mut self) {
            let read_pid = || {
                std::fs::read_to_string(&self.pid_file)
                    .ok()
                    .and_then(|raw| raw.trim().parse::<libc::pid_t>().ok())
                    .filter(|pid| *pid > 0)
            };
            let pid = if self
                .marker_file
                .as_ref()
                .is_some_and(|marker_file| !marker_file.exists())
            {
                let read_deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    let pid = read_pid();
                    if pid.is_some() || Instant::now() >= read_deadline {
                        break pid;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            } else {
                read_pid()
            };
            if let Some(pid) = pid {
                // SAFETY: the fixture records the PID of the process it just
                // started; SIGKILL is bounded cleanup for this test-owned PID.
                unsafe {
                    let _ = libc::kill(pid, libc::SIGKILL);
                }
                let cleanup_deadline = Instant::now() + Duration::from_secs(1);
                while Instant::now() < cleanup_deadline {
                    // SAFETY: signal zero only probes the test-owned fixture.
                    let alive = unsafe { libc::kill(pid, 0) == 0 };
                    if !alive {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            }
            let _ = std::fs::remove_file(&self.pid_file);
            if let Some(marker_file) = &self.marker_file {
                let _ = std::fs::remove_file(marker_file);
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn current_thread_count() -> usize {
        std::fs::read_dir("/proc/self/task")
            .expect("Linux thread directory")
            .count()
    }

    #[cfg(unix)]
    #[test]
    fn shared_test_mode_api_returns_stdout_and_stderr() {
        let root = std::env::current_dir().expect("current directory");
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf supervisor-stdout; printf supervisor-stderr >&2".to_string(),
        ];
        let captured = run_with_deadline(
            &argv,
            &root,
            Path::new("."),
            Path::new("."),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("shared test-mode command API");

        assert_eq!(captured.code, Some(0));
        assert_eq!(captured.stdout, b"supervisor-stdout");
        assert_eq!(captured.stderr, b"supervisor-stderr");
        #[cfg(target_os = "linux")]
        assert!(captured.cwd_identity.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_mode_escaped_pipe_holder_returns_bounded_without_reader_threads() {
        if let Some(pid_file) = std::env::var_os("LGTM_SUPERVISOR_ESCAPED_PID_FILE") {
            let marker_file = std::env::var_os("LGTM_SUPERVISOR_ESCAPED_MARKER_FILE")
                .map(PathBuf::from)
                .expect("escaped-pipe watchdog marker");
            let root = std::env::current_dir().expect("current directory");
            let pid_file = PathBuf::from(pid_file);
            let _guard = EscapedProcessGuard {
                pid_file: pid_file.clone(),
                marker_file: None,
            };
            let command = format!(
                "setsid sh -c 'exec sleep 30' & escaped=$!; printf '%s' \"$escaped\" > '{}'; printf supervisor-parent-stdout; printf supervisor-parent-stderr >&2; exit 0",
                pid_file.display()
            );
            let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command];
            let threads_before = current_thread_count();
            let started = Instant::now();
            let result = run_with_deadline(
                &argv,
                &root,
                Path::new("."),
                Path::new("."),
                Instant::now() + Duration::from_millis(350),
            );
            let elapsed = started.elapsed();

            assert!(result.is_err(), "open escaped pipes must fail closed");
            assert!(
                pid_file.exists(),
                "fixture must record an escaped process before returning"
            );
            assert!(
                elapsed < Duration::from_secs(2),
                "bounded test runner took {elapsed:?}"
            );
            assert_eq!(
                current_thread_count(),
                threads_before,
                "test runner must not abandon pipe-drain threads"
            );
            std::fs::write(&marker_file, b"ran").expect("watchdog marker");
            return;
        }

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let pid_file = std::env::temp_dir().join(format!(
            "lgtm-supervisor-escaped-{}-{unique}.pid",
            std::process::id()
        ));
        let marker_file = std::env::temp_dir().join(format!(
            "lgtm-supervisor-escaped-{}-{unique}.marker",
            std::process::id()
        ));
        let _guard = EscapedProcessGuard {
            pid_file: pid_file.clone(),
            marker_file: Some(marker_file.clone()),
        };
        let _ = std::fs::remove_file(&marker_file);
        let mut child = Command::new(std::env::current_exe().expect("test executable"));
        child
            .arg("test_mode_escaped_pipe_holder_returns_bounded_without_reader_threads")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("LGTM_SUPERVISOR_ESCAPED_PID_FILE", pid_file.as_os_str())
            .env(
                "LGTM_SUPERVISOR_ESCAPED_MARKER_FILE",
                marker_file.as_os_str(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = child.spawn().expect("watchdog test process");
        let watchdog_deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Err(_) => break None,
                Ok(None) => {}
            }
            let remaining = watchdog_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(POLL_INTERVAL.min(remaining));
        };

        assert!(
            marker_file.exists(),
            "watchdog child must execute the escaped-pipe regression"
        );
        assert!(
            status.is_some_and(|status| status.success()),
            "watchdog child must finish successfully: {status:?}"
        );
    }

    #[test]
    fn supervisor_capture_rejects_survivors_and_oversized_stderr() {
        let captured = crate::checks::gitleaks::runner::Captured {
            code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            process_group_survived: false,
        };
        assert!(supervisor_capture_is_bounded(&captured, 0));

        let mut survived = captured;
        survived.process_group_survived = true;
        assert!(!supervisor_capture_is_bounded(&survived, usize::MAX));

        let oversized = crate::checks::gitleaks::runner::Captured {
            code: Some(0),
            stdout: Vec::new(),
            stderr: vec![0],
            process_group_survived: false,
        };
        assert!(!supervisor_capture_is_bounded(&oversized, 0));
    }

    #[test]
    fn environment_transport_rejects_too_many_entries_and_bytes() {
        let too_many = (0..=MAX_REQUEST_ENVIRONMENT_ENTRIES)
            .map(|index| (OsString::from(format!("N{index}")), OsString::from("v")))
            .collect::<Vec<_>>();
        let too_large = vec![(
            OsString::from("NAME"),
            OsString::from("x".repeat(MAX_REQUEST_ENVIRONMENT_BYTES)),
        )];

        assert!(encode_environment_entries(&too_many).is_err());
        assert!(encode_environment_entries(&too_large).is_err());
    }

    #[test]
    fn capture_limit_accepts_ruff_bound_and_rejects_unbounded_values() {
        assert_eq!(
            valid_capture_limit(MAX_CAPTURE_BYTES),
            Some(MAX_CAPTURE_BYTES as usize)
        );
        assert_eq!(
            valid_capture_limit(MAX_CAPTURE_LIMIT_BYTES),
            Some(MAX_CAPTURE_LIMIT_BYTES as usize)
        );
        assert!(valid_capture_limit(0).is_none());
        assert!(valid_capture_limit(MAX_CAPTURE_LIMIT_BYTES + 1).is_none());
    }

    #[cfg(target_os = "linux")]
    fn valid_request_fixture() -> SupervisorRequest {
        SupervisorRequest {
            argv: vec!["true".to_string()],
            repository_root: encode_path(Path::new(".")).expect("path encoding"),
            workspace_root: encode_path(Path::new(".")).expect("path encoding"),
            cwd: encode_path(Path::new(".")).expect("path encoding"),
            timeout_ms: Some("1000".to_string()),
            deadline_ns: None,
            environment: None,
            capture_limit: MAX_CAPTURE_BYTES,
            path: None,
            home: None,
            ci: None,
        }
    }

    #[test]
    fn receiver_rejects_oversized_raw_envelopes_before_parsing() {
        assert!(request_payload_is_bounded(
            &"x".repeat(MAX_REQUEST_ENVELOPE_BYTES)
        ));
        assert!(!request_payload_is_bounded(
            &"x".repeat(MAX_REQUEST_ENVELOPE_BYTES + 1)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_rejects_oversized_envelopes() {
        let mut request = valid_request_fixture();
        request.argv = vec!["x".repeat(MAX_REQUEST_ENVELOPE_BYTES)];
        assert!(!request_is_valid(&request));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_rejects_oversized_environment() {
        let mut too_many = valid_request_fixture();
        too_many.environment = Some(
            (0..=MAX_REQUEST_ENVIRONMENT_ENTRIES)
                .map(|index| EncodedEnvironment {
                    name: encode_hex(format!("N{index}").as_bytes()),
                    value: encode_hex(b"v"),
                })
                .collect(),
        );
        assert!(!request_is_valid(&too_many));

        let mut too_large = valid_request_fixture();
        too_large.environment = Some(vec![EncodedEnvironment {
            name: encode_hex(b"NAME"),
            value: "aa".repeat(MAX_REQUEST_ENVIRONMENT_BYTES),
        }]);
        assert!(!request_is_valid(&too_large));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_preserves_legacy_relative_environment() {
        let mut request = valid_request_fixture();
        request.environment = None;
        request.path = Some(encode_hex(b"/usr/bin"));
        request.home = Some(encode_hex(b"/tmp"));
        request.ci = Some(encode_hex(b"1"));
        assert!(request_is_valid(&request));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_accepts_modern_environment() {
        let mut request = valid_request_fixture();
        request.environment = Some(vec![EncodedEnvironment {
            name: encode_hex(b"PATH"),
            value: encode_hex(b"/usr/bin"),
        }]);
        assert!(request_is_valid(&request));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_rejects_each_invalid_argument_shape() {
        let mut empty_argv = valid_request_fixture();
        empty_argv.argv.clear();
        assert!(!request_is_valid(&empty_argv));

        let mut empty_program = valid_request_fixture();
        empty_program.argv[0].clear();
        assert!(!request_is_valid(&empty_program));

        let mut nul_argument = valid_request_fixture();
        nul_argument.argv.push("contains\0nul".to_string());
        assert!(!request_is_valid(&nul_argument));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_rejects_each_invalid_path_or_capture_field() {
        let mut invalid_repository_root = valid_request_fixture();
        invalid_repository_root.repository_root = "not-hex".to_string();
        assert!(!request_is_valid(&invalid_repository_root));

        let mut invalid_workspace_root = valid_request_fixture();
        invalid_workspace_root.workspace_root = "not-hex".to_string();
        assert!(!request_is_valid(&invalid_workspace_root));

        let mut invalid_cwd = valid_request_fixture();
        invalid_cwd.cwd = "not-hex".to_string();
        assert!(!request_is_valid(&invalid_cwd));

        let mut invalid_capture_limit = valid_request_fixture();
        invalid_capture_limit.capture_limit = 0;
        assert!(!request_is_valid(&invalid_capture_limit));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_accepts_exact_environment_entry_limit() {
        let mut request = valid_request_fixture();
        request.environment = Some(
            (0..MAX_REQUEST_ENVIRONMENT_ENTRIES)
                .map(|index| EncodedEnvironment {
                    name: encode_hex(format!("N{index}").as_bytes()),
                    value: encode_hex(b"v"),
                })
                .collect(),
        );
        assert!(request_is_valid(&request));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receiver_request_validation_rejects_invalid_environment_name_or_value() {
        let mut invalid_name = valid_request_fixture();
        invalid_name.environment = Some(vec![EncodedEnvironment {
            name: encode_hex(b"NAME=INVALID"),
            value: encode_hex(b"value"),
        }]);
        assert!(!request_is_valid(&invalid_name));

        let mut invalid_value = valid_request_fixture();
        invalid_value.environment = Some(vec![EncodedEnvironment {
            name: encode_hex(b"NAME"),
            value: "not-hex".to_string(),
        }]);
        assert!(!request_is_valid(&invalid_value));
    }

    #[test]
    fn environment_validation_accepts_exact_encoded_byte_limit() {
        let value_length = MAX_REQUEST_ENVIRONMENT_BYTES / 8 - 1;
        let exact = (0..4)
            .map(|_| EncodedEnvironment {
                name: encode_hex(b"N"),
                value: "aa".repeat(value_length),
            })
            .collect::<Vec<_>>();

        assert_eq!(
            exact
                .iter()
                .map(|entry| entry.name.len() + entry.value.len())
                .sum::<usize>(),
            MAX_REQUEST_ENVIRONMENT_BYTES
        );
        assert!(encoded_environment_entries_are_valid(&exact));
    }

    #[test]
    fn hex_round_trips_binary_capture() {
        let bytes = [0, 1, 15, 16, 127, 255];
        assert_eq!(decode_hex(&encode_hex(&bytes)), Some(bytes.to_vec()));
        assert!(decode_hex("0").is_none());
        assert!(decode_hex("xx").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn path_transport_round_trips_non_utf8_bytes() {
        let path = PathBuf::from(OsString::from_vec(b"repo-\xff/checks".to_vec()));
        let encoded = encode_path(&path).expect("bounded path encoding");
        assert_eq!(decode_path(&encoded), Some(path));
    }

    #[cfg(unix)]
    #[test]
    fn environment_transport_accepts_exact_limit_and_rejects_one_byte_over() {
        let exact = OsString::from_vec(vec![b'x'; MAX_REQUEST_ENV_BYTES]);
        let over = OsString::from_vec(vec![b'x'; MAX_REQUEST_ENV_BYTES + 1]);
        assert!(encode_environment_value(&exact).is_ok());
        assert!(encode_environment_value(&over).is_err());
    }

    #[test]
    fn transport_preflight_rejects_nul_arguments() {
        assert!(!request_is_transportable_with_environment(
            &["check".to_string(), "\0".to_string()],
            Path::new("."),
            Path::new("."),
            Path::new("."),
            1_000,
        ));
    }

    #[test]
    fn transport_preflight_uses_fixed_timeout_wire_width() {
        let argv = vec!["check".to_string(), "x".repeat(90_000)];
        assert_eq!(
            request_is_transportable_with_environment(
                &argv,
                Path::new("."),
                Path::new("."),
                Path::new("."),
                1,
            ),
            request_is_transportable_with_environment(
                &argv,
                Path::new("."),
                Path::new("."),
                Path::new("."),
                u64::MAX,
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_absolute_deadline_does_not_fall_back_to_relative_timeout() {
        let request = SupervisorRequest {
            argv: vec!["true".to_string()],
            repository_root: encode_path(Path::new(".")).expect("path encoding"),
            workspace_root: encode_path(Path::new(".")).expect("path encoding"),
            cwd: encode_path(Path::new(".")).expect("path encoding"),
            timeout_ms: Some("1000".to_string()),
            deadline_ns: Some("not-a-monotonic-deadline".to_string()),
            environment: None,
            capture_limit: MAX_CAPTURE_BYTES,
            path: None,
            home: None,
            ci: None,
        };
        assert!(request_deadline(&request).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn expired_absolute_deadline_does_not_fall_back_to_relative_timeout() {
        let request = SupervisorRequest {
            argv: vec!["true".to_string()],
            repository_root: encode_path(Path::new(".")).expect("path encoding"),
            workspace_root: encode_path(Path::new(".")).expect("path encoding"),
            cwd: encode_path(Path::new(".")).expect("path encoding"),
            timeout_ms: Some("1000".to_string()),
            deadline_ns: Some("0".to_string()),
            environment: None,
            capture_limit: MAX_CAPTURE_BYTES,
            path: None,
            home: None,
            ci: None,
        };
        assert!(request_deadline(&request).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_relative_deadline_remains_accepted_without_absolute_value() {
        let request = SupervisorRequest {
            argv: vec!["true".to_string()],
            repository_root: encode_path(Path::new(".")).expect("path encoding"),
            workspace_root: encode_path(Path::new(".")).expect("path encoding"),
            cwd: encode_path(Path::new(".")).expect("path encoding"),
            timeout_ms: Some("1000".to_string()),
            deadline_ns: None,
            environment: None,
            capture_limit: MAX_CAPTURE_BYTES,
            path: None,
            home: None,
            ci: None,
        };
        assert!(request_deadline(&request).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn expired_empty_cleanup_deadline_is_unproven_before_quiescence() {
        assert_eq!(
            cleanup_decision(false, Duration::ZERO, Duration::ZERO),
            Some(Cleanup::Unproven)
        );
    }
}
