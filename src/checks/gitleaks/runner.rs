use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::report::{MAX_CAPTURE_BYTES, ScanOutcome, classify_exit};

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
#[cfg(all(target_os = "linux", not(test)))]
const CONTAINMENT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(all(target_os = "linux", not(test)))]
const CONTAINMENT_QUIESCENCE: Duration = Duration::from_millis(100);
#[cfg(all(target_os = "linux", not(test)))]
static PROCESS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn run_captured(command: Command) -> Option<(Option<i32>, Vec<u8>)> {
    run_details(command).map(|details| (details.code, details.stdout))
}

pub(crate) struct Captured {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

#[cfg_attr(test, allow(dead_code))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum ContainedRunError {
    CouldNotRun,
    ContainmentUnavailable,
    ContainmentUnproven,
}

pub(crate) fn run_details(command: Command) -> Option<Captured> {
    run_details_with_timeout(command, SUBPROCESS_TIMEOUT)
}

pub(crate) fn run_details_with_timeout(command: Command, timeout: Duration) -> Option<Captured> {
    run_details_with_deadline(command, deadline_after(timeout))
}

pub(crate) fn run_contained_with_deadline(
    command: Command,
    deadline: Instant,
) -> Result<Captured, ContainedRunError> {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        let guard =
            lock_process_until(deadline).ok_or(ContainedRunError::ContainmentUnavailable)?;
        let containment = DescendantContainment::acquire(guard)?;
        let result = run_details_with_deadline_inner(command, deadline);
        if !containment.terminate_descendants() {
            return Err(ContainedRunError::ContainmentUnproven);
        }
        result.ok_or(ContainedRunError::CouldNotRun)
    }
    // The Rust unit-test harness runs unrelated subprocess tests concurrently
    // in one process. Enabling a process-wide subreaper there would adopt those
    // unrelated children; production containment is exercised end to end by
    // tests/commands.rs through the real lgtm binary instead.
    #[cfg(all(target_os = "linux", test))]
    {
        run_details_with_deadline(command, deadline).ok_or(ContainedRunError::CouldNotRun)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command, deadline);
        Err(ContainedRunError::ContainmentUnavailable)
    }
}

/// Run a command with one absolute deadline covering child wait and pipe drain.
/// A successful parent that leaves descendants holding its pipes open is not a
/// success: the process group is killed and the result remains unverified.
pub(crate) fn run_details_with_deadline(command: Command, deadline: Instant) -> Option<Captured> {
    run_details_with_deadline_inner(command, deadline)
}

fn run_details_with_deadline_inner(mut command: Command, deadline: Instant) -> Option<Captured> {
    prepare_command(&mut command);
    let mut child = command.spawn().ok()?;
    let pid = child.id();
    let stdout = drain_bounded(child.stdout.take());
    let stderr = drain_bounded(child.stderr.take());
    let status = wait_bounded(&mut child, pid, deadline);
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
    let stdout = drain_bounded(child.stdout.take());
    let stderr = drain_bounded(child.stderr.take());
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
) -> Option<thread::JoinHandle<Vec<u8>>> {
    stream.map(|mut stream| {
        thread::spawn(move || {
            let mut captured = Vec::new();
            let _ = (&mut stream)
                .take(MAX_CAPTURE_BYTES)
                .read_to_end(&mut captured);
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

#[cfg(all(target_os = "linux", not(test)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessIdentity {
    pid: libc::pid_t,
    start_time: u64,
}

#[cfg(all(target_os = "linux", not(test)))]
struct DescendantContainment {
    baseline: Vec<ProcessIdentity>,
    original_subreaper: libc::c_int,
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(all(target_os = "linux", not(test)))]
impl DescendantContainment {
    fn acquire(guard: std::sync::MutexGuard<'static, ()>) -> Result<Self, ContainedRunError> {
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
        // SAFETY: prctl only changes this process's child-reparenting behavior.
        let enabled =
            inspected && unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0;
        if !enabled {
            return Err(ContainedRunError::ContainmentUnavailable);
        }
        let baseline = match direct_children() {
            Ok(baseline) => baseline,
            Err(()) => {
                // SAFETY: restore the state changed immediately above before failing closed.
                unsafe {
                    let _ = libc::prctl(libc::PR_SET_CHILD_SUBREAPER, original_subreaper, 0, 0, 0);
                }
                return Err(ContainedRunError::ContainmentUnavailable);
            }
        };
        Ok(Self {
            baseline,
            original_subreaper,
            _guard: guard,
        })
    }

    fn terminate_descendants(&self) -> bool {
        let deadline = deadline_after(CONTAINMENT_CLEANUP_TIMEOUT);
        let mut quiet_since = None;
        loop {
            let children = match direct_children() {
                Ok(children) => children,
                Err(()) => return false,
            };
            let spawned: Vec<_> = children
                .into_iter()
                .filter(|child| !self.baseline.contains(child))
                .collect();
            if spawned.is_empty() {
                let quiet_since = quiet_since.get_or_insert_with(Instant::now);
                if quiet_since.elapsed() >= CONTAINMENT_QUIESCENCE {
                    return true;
                }
            } else {
                quiet_since = None;
                for child in &spawned {
                    // SAFETY: these PIDs are current direct children identified by PID and start time.
                    unsafe {
                        let _ = libc::kill(child.pid, libc::SIGKILL);
                        let _ = libc::waitpid(child.pid, std::ptr::null_mut(), libc::WNOHANG);
                    }
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

#[cfg(all(target_os = "linux", not(test)))]
impl Drop for DescendantContainment {
    fn drop(&mut self) {
        // SAFETY: restore the process-wide state observed while holding the same lock.
        unsafe {
            let _ = libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                self.original_subreaper,
                0,
                0,
                0,
            );
        }
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn lock_process_until(deadline: Instant) -> Option<std::sync::MutexGuard<'static, ()>> {
    loop {
        match PROCESS_LOCK.try_lock() {
            Ok(guard) => return Some(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => return None,
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

#[cfg(all(target_os = "linux", not(test)))]
fn direct_children() -> Result<Vec<ProcessIdentity>, ()> {
    let path = format!("/proc/self/task/{}/children", std::process::id());
    let raw = std::fs::read_to_string(path).map_err(|_| ())?;
    raw.split_whitespace()
        .map(|pid| pid.parse::<libc::pid_t>().map_err(|_| ()))
        .filter_map(|pid| match pid {
            Ok(pid) => match process_identity(pid) {
                Ok(Some(identity)) => Some(Ok(identity)),
                Ok(None) => None,
                Err(()) => Some(Err(())),
            },
            Err(()) => Some(Err(())),
        })
        .collect()
}

#[cfg(all(target_os = "linux", not(test)))]
fn process_identity(pid: libc::pid_t) -> Result<Option<ProcessIdentity>, ()> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let fields = stat.rsplit_once(") ").ok_or(())?.1;
    let start_time = fields
        .split_whitespace()
        .nth(19)
        .ok_or(())?
        .parse()
        .map_err(|_| ())?;
    Ok(Some(ProcessIdentity { pid, start_time }))
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
        let stdout = drain_bounded(child.stdout.take());
        let stderr = drain_bounded(child.stderr.take());
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
