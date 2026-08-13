use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::report::{MAX_CAPTURE_BYTES, ScanOutcome, classify_exit};

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

pub(crate) fn run_captured(command: Command) -> Option<(Option<i32>, Vec<u8>)> {
    run_details(command).map(|details| (details.code, details.stdout))
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

pub(super) fn run_scan(mut command: Command, report_path: &Path) -> ScanOutcome {
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
    let deadline = deadline_after(SUBPROCESS_TIMEOUT);
    let status = wait_bounded(&mut child, pid, deadline);
    if status.is_none() {
        kill_child(&mut child, pid);
    }
    let captured_stdout = join_bounded(stdout, deadline);
    let captured_stderr = join_bounded(stderr, deadline);
    if captured_stdout.is_none() || captured_stderr.is_none() {
        kill_process_group(pid);
        return ScanOutcome::Unverified(
            "gitleaks output did not close before the deadline".to_string(),
        );
    }
    status.map_or_else(
        || ScanOutcome::Unverified("gitleaks timed out or could not be waited on".to_string()),
        |status| classify_exit(status.code(), report_path),
    )
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

#[cfg(unix)]
fn kill_process_group(pid: u32) {
    // SAFETY: kill has no memory-safety preconditions; negative pid selects the child group.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) {}

#[cfg(unix)]
fn process_group_exists(pid: u32) -> bool {
    // SAFETY: signal zero performs existence/permission checking only.
    unsafe {
        if libc::kill(-(pid as libc::pid_t), 0) == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(not(unix))]
fn process_group_exists(_pid: u32) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn group_kill_closes_grandchild_pipes() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("( sleep 120 & ) ; sleep 120");
        prepare_command(&mut command);
        let mut child = command.spawn().expect("shell spawned");
        let pid = child.id();
        let stdout = drain_bounded(child.stdout.take(), MAX_CAPTURE_BYTES);
        let stderr = drain_bounded(child.stderr.take(), MAX_CAPTURE_BYTES);
        thread::sleep(Duration::from_millis(200));
        kill_child(&mut child, pid);
        let deadline = deadline_after(Duration::from_secs(2));
        assert!(join_bounded(stdout, deadline).is_some());
        assert!(join_bounded(stderr, deadline).is_some());
    }

    #[test]
    fn absolute_deadline_covers_detached_descendant_pipe_drain() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 120 & exit 0");
        let started = Instant::now();
        let captured = run_details_with_timeout(command, Duration::from_millis(100));
        assert!(captured.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
