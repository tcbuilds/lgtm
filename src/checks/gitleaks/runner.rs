use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::report::{MAX_CAPTURE_BYTES, ScanOutcome, classify_exit};

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn run_captured(command: Command) -> Option<(Option<i32>, Vec<u8>)> {
    run_details(command).map(|details| (details.code, details.stdout))
}

pub(crate) fn run_captured_with_deadline(
    command: Command,
    deadline: Instant,
) -> Option<(Option<i32>, Vec<u8>)> {
    run_details_with_deadline(command, deadline).map(|details| (details.code, details.stdout))
}

pub(crate) struct Captured {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) process_group_survived: bool,
}

pub(crate) fn run_details(command: Command) -> Option<Captured> {
    run_details_with_timeout(command, SUBPROCESS_TIMEOUT)
}

pub(crate) fn run_details_with_timeout(command: Command, timeout: Duration) -> Option<Captured> {
    run_details_with_deadline(command, deadline_after(timeout))
}

/// Run a command with one absolute deadline covering child wait and pipe drain.
/// A successful parent that leaves descendants holding its pipes open is not a
/// success: the process group is killed and the result remains unverified.
pub(crate) fn run_details_with_deadline(command: Command, deadline: Instant) -> Option<Captured> {
    run_details_with_deadline_and_limit(command, deadline, MAX_CAPTURE_BYTES)
}

pub(crate) fn run_details_with_deadline_and_limit(
    mut command: Command,
    deadline: Instant,
    capture_limit: u64,
) -> Option<Captured> {
    prepare_command(&mut command);
    let mut child = command.spawn().ok()?;
    let pid = child.id();
    let stdout = drain_bounded(child.stdout.take(), capture_limit);
    let stderr = drain_bounded(child.stderr.take(), capture_limit);
    let status = wait_bounded(&mut child, pid, deadline);
    let process_group_survived = status.is_some() && process_group_exists(pid);
    if status.is_none() {
        kill_child(&mut child, pid);
    }
    let captured = join_bounded(stdout, deadline);
    if captured.is_none() {
        kill_process_group(pid);
    }
    let stderr = join_bounded(stderr, deadline);
    if captured.is_none() || stderr.is_none() {
        kill_process_group(pid);
        return None;
    }
    // Required checks are synchronous gates. Do not let a successful parent
    // leave delayed descendants alive to mutate configuration after the exact
    // snapshot has been checked but before authorization is returned.
    kill_process_group(pid);
    status.map(|status| Captured {
        code: status.code(),
        stdout: captured.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
        process_group_survived,
    })
}

pub(super) fn run_scan_with_deadline(
    mut command: Command,
    report_path: &Path,
    deadline: Instant,
) -> ScanOutcome {
    set_own_process_group(&mut command);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ScanOutcome::Unverified("gitleaks binary not found".to_string());
        }
        Err(error) => {
            return ScanOutcome::Unverified(format!("could not start gitleaks ({error})"));
        }
    };
    let pid = child.id();
    let stdout = drain_bounded(child.stdout.take(), MAX_CAPTURE_BYTES);
    let stderr = drain_bounded(child.stderr.take(), MAX_CAPTURE_BYTES);
    let status = wait_bounded(&mut child, pid, deadline);
    if status.is_none() {
        kill_child(&mut child, pid);
    }
    let cleanup = cleanup_process_group(pid, deadline);
    let captured_stdout = join_bounded(stdout, deadline);
    let captured_stderr = join_bounded(stderr, deadline);
    if captured_stdout.is_none() || captured_stderr.is_none() {
        return ScanOutcome::Unverified(
            "gitleaks output did not close before the deadline".to_string(),
        );
    }
    classify_after_cleanup(cleanup, status, report_path)
}

fn prepare_command(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_own_process_group(command);
}

fn wait_bounded(
    child: &mut Child,
    pid: u32,
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
            kill_child(child, pid);
            return None;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

fn kill_child(child: &mut Child, pid: u32) {
    kill_process_group(pid);
    let _ = child.kill();
    let _ = child.wait();
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

fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

fn drain_bounded<R: Read + Send + 'static>(
    stream: Option<R>,
    capture_limit: u64,
) -> Option<thread::JoinHandle<Vec<u8>>> {
    stream.map(|mut stream| {
        thread::spawn(move || {
            let mut captured = Vec::new();
            let _ = (&mut stream).take(capture_limit).read_to_end(&mut captured);
            let mut void = [0_u8; 8 * 1024];
            while let Ok(read) = stream.read(&mut void) {
                if read == 0 {
                    break;
                }
            }
            captured
        })
    })
}

#[cfg(unix)]
fn set_own_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setpgid is async-signal-safe and this pre-exec closure touches no shared state.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessGroupState {
    Gone,
    Alive,
}

fn kill_process_group(pid: u32) {
    let _ = terminate_process_group(pid);
}

fn terminate_process_group(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        // SAFETY: kill has no memory-safety preconditions; negative pid selects the child group.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(format!("kill process group {pid}: {error}"))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err("process-group cleanup is unsupported on this target".to_string())
    }
}

fn cleanup_process_group(pid: u32, deadline: Instant) -> Result<(), String> {
    match process_group_state(pid)? {
        ProcessGroupState::Gone => Ok(()),
        ProcessGroupState::Alive => {
            terminate_process_group(pid)?;
            prove_process_group_gone(pid, deadline)
        }
    }
}

fn prove_process_group_gone(pid: u32, deadline: Instant) -> Result<(), String> {
    loop {
        match process_group_state(pid)? {
            ProcessGroupState::Gone => return Ok(()),
            ProcessGroupState::Alive => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(format!(
                        "process group {pid} remained alive at the cleanup deadline"
                    ));
                }
                thread::sleep(POLL_INTERVAL.min(remaining));
            }
        }
    }
}

fn process_group_exists(pid: u32) -> bool {
    matches!(process_group_state(pid), Ok(ProcessGroupState::Alive))
}

fn process_group_state(pid: u32) -> Result<ProcessGroupState, String> {
    #[cfg(unix)]
    {
        // SAFETY: signal zero performs existence/permission checking only.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), 0) };
        if result == 0 {
            return Ok(ProcessGroupState::Alive);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(ProcessGroupState::Gone);
        }
        if error.raw_os_error() == Some(libc::EPERM) {
            return Ok(ProcessGroupState::Alive);
        }
        Err(format!("probe process group {pid}: {error}"))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err("process-group probing is unsupported on this target".to_string())
    }
}

fn classify_after_cleanup(
    cleanup: Result<(), String>,
    status: Option<ExitStatus>,
    report_path: &Path,
) -> ScanOutcome {
    let Some(status) = status else {
        return ScanOutcome::Unverified("gitleaks timed out or could not be waited on".to_string());
    };
    if let Err(error) = cleanup {
        return ScanOutcome::Unverified(format!(
            "could not prove gitleaks process-group cleanup: {error}"
        ));
    }
    classify_exit(status.code(), report_path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn group_kill_closes_pipe_inheriting_child() {
        // Keep the direct shell alive while it waits for a same-group child.
        // The child holds both inherited pipes until the process-group kill;
        // production escaped-descendant behavior is covered at its boundary.
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("( printf child; printf error >&2; exec /bin/sleep 120 ) & wait");
        prepare_command(&mut command);
        let mut child = command.spawn().expect("shell spawned");
        let pid = child.id();
        let stdout = drain_bounded(child.stdout.take(), MAX_CAPTURE_BYTES);
        let stderr = drain_bounded(child.stderr.take(), MAX_CAPTURE_BYTES);
        thread::sleep(Duration::from_millis(200));
        kill_child(&mut child, pid);
        let deadline = deadline_after(Duration::from_secs(2));
        assert_eq!(join_bounded(stdout, deadline), Some(b"child".to_vec()));
        assert_eq!(join_bounded(stderr, deadline), Some(b"error".to_vec()));
    }

    #[test]
    fn absolute_deadline_covers_pipe_inheriting_child_cleanup() {
        // The direct shell waits for its same-group child, so the timeout must
        // kill the whole group and bound the inherited-pipe drain as well.
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("( printf child; printf error >&2; exec /bin/sleep 120 ) & wait");
        let started = Instant::now();
        let captured = run_details_with_timeout(command, Duration::from_millis(100));
        assert!(captured.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn successful_scan_kills_pipe_closing_descendant_before_classifying() {
        let group_path =
            std::env::temp_dir().join(format!("lgtm-gitleaks-group-{}.pid", std::process::id()));
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            // Close both captured pipes in the surviving descendant. The
            // process-group proof, not pipe draining, must gate classification.
            .arg("(sleep 120) >/dev/null 2>&1 & printf '%s' \"$$\" > \"$1\"; exit 0")
            .arg("lgtm-gitleaks-test")
            .arg(&group_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let outcome = run_scan_with_deadline(
            command,
            Path::new("unused-report.json"),
            deadline_after(Duration::from_secs(2)),
        );
        let group_id = std::fs::read_to_string(&group_path)
            .expect("scan wrote its process-group id")
            .trim()
            .parse::<u32>()
            .expect("scan wrote a numeric process-group id");
        let cleanup = prove_process_group_gone(group_id, deadline_after(Duration::from_secs(2)));
        if cleanup.is_err() {
            // Keep the mutation proof from leaking its intentionally surviving
            // descendant after this test fails.
            kill_process_group(group_id);
            let _ = prove_process_group_gone(group_id, deadline_after(Duration::from_secs(2)));
        }
        std::fs::remove_file(group_path).ok();
        assert!(cleanup.is_ok(), "process group survived the returned scan");
        assert!(matches!(
            outcome,
            ScanOutcome::Findings(findings) if findings.is_empty()
        ));
    }

    #[test]
    fn cleanup_failure_is_unverified_before_classifying_exit() {
        use std::os::unix::process::ExitStatusExt;

        let outcome = classify_after_cleanup(
            Err("group remained alive".to_string()),
            Some(ExitStatus::from_raw(0)),
            Path::new("unused-report.json"),
        );
        assert!(matches!(
            outcome,
            ScanOutcome::Unverified(reason) if reason.contains("process-group cleanup")
        ));
    }

    #[test]
    fn live_process_group_is_unproven_after_expired_deadline() {
        // The current test process owns this group, so it is a stable live
        // group for proving that an expired cleanup deadline cannot pass.
        let group_id = unsafe { libc::getpgrp() } as u32;
        assert_eq!(process_group_state(group_id), Ok(ProcessGroupState::Alive));
        assert!(prove_process_group_gone(group_id, Instant::now()).is_err());
    }
}
