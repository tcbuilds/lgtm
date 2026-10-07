#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, ExitStatus};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const TEST_PROCESS_MODE: &str = "LGTM_TEST_PROCESS_MODE";
#[cfg(target_os = "linux")]
const TEST_HELPER_MODE: &str = "helper";
#[cfg(target_os = "linux")]
const TEST_WORKER_MODE: &str = "worker";
#[cfg(target_os = "linux")]
const TEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const TEST_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "linux")]
const TEST_HELPER_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const TEST_HELPER_KILL_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const TEST_REAPER_QUIESCENCE: Duration = Duration::from_millis(50);
#[cfg(target_os = "linux")]
const TEST_POLL_INTERVAL: Duration = Duration::from_millis(20);

// Keep the subreaper in a one-test helper and run the body in a separate
// worker. The helper can reap adopted descendants while the worker waits
// inside the code under test without stealing its direct-child status.
pub(crate) fn run_in_isolated_process(test_name: &str, body: impl FnOnce()) {
    #[cfg(target_os = "linux")]
    match std::env::var(TEST_PROCESS_MODE).as_deref() {
        Ok(TEST_WORKER_MODE) => body(),
        Ok(TEST_HELPER_MODE) => run_test_helper(test_name),
        _ => {
            let status = spawn_test_process(test_name, TEST_HELPER_MODE);
            assert!(status.success(), "isolated test helper failed: {status:?}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = test_name;
        body();
    }
}

#[cfg(target_os = "linux")]
fn spawn_test_process(test_name: &str, mode: &str) -> ExitStatus {
    let executable = std::env::current_exe().expect("test executable available");
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg(test_name)
        .env(TEST_PROCESS_MODE, mode)
        .spawn()
        .expect("isolated test process spawned");
    match wait_child(&mut child, deadline_after(TEST_HELPER_TIMEOUT)) {
        Ok(Some(status)) => status,
        Ok(None) => {
            terminate_child(&mut child).unwrap_or_else(|error| {
                panic!("terminate isolated test helper: {error}");
            });
            wait_child(&mut child, deadline_after(TEST_HELPER_KILL_TIMEOUT))
                .unwrap_or_else(|error| panic!("reap isolated test helper: {error}"))
                .unwrap_or_else(|| panic!("isolated test helper did not exit after termination"))
        }
        Err(error) => {
            let _ = terminate_child(&mut child);
            panic!("wait for isolated test helper: {error}");
        }
    }
}

#[cfg(target_os = "linux")]
fn run_test_helper(test_name: &str) {
    enable_test_subreaper();
    let executable = std::env::current_exe().expect("test executable available");
    let mut worker = Command::new(executable)
        .arg("--exact")
        .arg(test_name)
        .env(TEST_PROCESS_MODE, TEST_WORKER_MODE)
        .spawn()
        .expect("isolated test worker spawned");
    let worker_pid = worker.id();
    match supervise_test_worker(&mut worker, worker_pid) {
        Ok(status) => assert!(status.success(), "isolated test worker failed: {status:?}"),
        Err(error) => panic!("isolated test cleanup failed: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn enable_test_subreaper() {
    // SAFETY: prctl receives only immediate integer arguments; this helper
    // is a dedicated child process for one test and cannot alter siblings.
    let result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    assert_eq!(result, 0, "test helper could not become a subreaper");
}

// Keep the worker and cleanup deadlines in one control loop so child ownership
// and the transition to cleanup stay explicit across failure paths.
#[cfg(target_os = "linux")]
fn supervise_test_worker(worker: &mut Child, worker_pid: u32) -> Result<ExitStatus, String> {
    let worker_deadline = deadline_after(TEST_PROCESS_TIMEOUT);
    let mut cleanup_deadline = None;
    let mut worker_status = None;
    let mut worker_failure = None;
    let mut cleanup_errors = Vec::new();
    let mut child_enumeration_failed = false;
    let mut quiet_since = None;

    loop {
        if worker_status.is_none() {
            match worker.try_wait() {
                Ok(Some(status)) => {
                    worker_status = Some(status);
                    cleanup_deadline = Some(deadline_after(TEST_CLEANUP_TIMEOUT));
                }
                Ok(None) if cleanup_deadline.is_none() && Instant::now() >= worker_deadline => {
                    worker_failure = Some("isolated test worker timed out".to_string());
                    cleanup_deadline = Some(deadline_after(TEST_CLEANUP_TIMEOUT));
                    request_worker_termination(worker, &mut cleanup_errors);
                }
                Ok(None) => {}
                Err(error) => {
                    worker_failure = Some(format!("wait for isolated test worker ({error})"));
                    cleanup_deadline.get_or_insert_with(|| deadline_after(TEST_CLEANUP_TIMEOUT));
                    request_worker_termination(worker, &mut cleanup_errors);
                }
            }
        }

        let children = match isolated_children() {
            Ok(children) => Some(children),
            Err(error) => {
                if !child_enumeration_failed {
                    cleanup_errors.push(error);
                    child_enumeration_failed = true;
                    if cleanup_deadline.is_none() {
                        cleanup_deadline = Some(deadline_after(TEST_CLEANUP_TIMEOUT));
                        request_worker_termination(worker, &mut cleanup_errors);
                    }
                }
                None
            }
        };
        let mut has_adopted_children = false;
        if let Some(children) = children {
            for child_pid in children {
                if child_pid == worker_pid {
                    continue;
                }
                has_adopted_children = true;
                match reap_isolated_child(child_pid) {
                    Ok(true) => {}
                    Ok(false) if cleanup_deadline.is_some() => {
                        if let Err(error) = kill_isolated_child(child_pid) {
                            cleanup_errors.push(error);
                        }
                    }
                    Ok(false) => {}
                    Err(error) => cleanup_errors.push(error),
                }
            }
        }

        if let Some(deadline) = cleanup_deadline {
            if worker_status.is_some() && !has_adopted_children {
                let quiet_since = quiet_since.get_or_insert_with(Instant::now);
                if quiet_since.elapsed() >= TEST_REAPER_QUIESCENCE {
                    if let Some(error) = worker_failure {
                        return Err(error);
                    }
                    if !cleanup_errors.is_empty() {
                        return Err(cleanup_errors.join("; "));
                    }
                    if let Some(status) = worker_status.take() {
                        return Ok(status);
                    }
                }
            } else {
                quiet_since = None;
            }
            if Instant::now() >= deadline {
                cleanup_errors.push("isolated child cleanup exceeded its deadline".to_string());
                return Err(cleanup_errors.join("; "));
            }
        }
        thread::sleep(TEST_POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn request_worker_termination(worker: &mut Child, errors: &mut Vec<String>) {
    if let Err(error) = terminate_child(worker)
        && error != "isolated child was already gone"
    {
        errors.push(format!("terminate isolated test worker: {error}"));
    }
}

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut Child) -> Result<(), String> {
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err("isolated child was already gone".to_string())
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn wait_child(child: &mut Child, deadline: Instant) -> Result<Option<ExitStatus>, String> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Err(error) => return Err(format!("wait for isolated child ({error})")),
            Ok(None) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        thread::sleep(TEST_POLL_INTERVAL.min(remaining));
    }
}

#[cfg(target_os = "linux")]
fn isolated_children() -> Result<BTreeSet<u32>, String> {
    let tasks = std::fs::read_dir("/proc/self/task")
        .map_err(|error| format!("read isolated task list: {error}"))?;
    let mut children = BTreeSet::new();
    for task in tasks {
        let task = task.map_err(|error| format!("read isolated task entry: {error}"))?;
        let task_id = task
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok());
        let Some(task_id) = task_id else {
            continue;
        };
        let path = format!("/proc/self/task/{task_id}/children");
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("read isolated child list: {error}")),
        };
        for pid in raw.split_whitespace() {
            let pid = pid
                .parse::<u32>()
                .map_err(|error| format!("parse isolated child pid: {error}"))?;
            if pid == 0 {
                return Err("isolated child list contained pid 0".to_string());
            }
            children.insert(pid);
        }
    }
    Ok(children)
}

#[cfg(target_os = "linux")]
fn reap_isolated_child(pid: u32) -> Result<bool, String> {
    // SAFETY: pid was enumerated as a direct child of this dedicated
    // subreaper; the null status pointer is valid with WNOHANG.
    let result = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
    if result == 0 {
        return Ok(false);
    }
    if result == pid as libc::pid_t {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EINTR) {
        return Ok(false);
    }
    if matches!(error.raw_os_error(), Some(libc::ECHILD) | Some(libc::ESRCH)) {
        // The child can disappear from the wait set between procfs enumeration
        // and waitpid; the next task scan is the authoritative inventory.
        return Ok(true);
    }
    Err(format!("reap isolated child {pid}: {error}"))
}

#[cfg(target_os = "linux")]
fn kill_isolated_child(pid: u32) -> Result<(), String> {
    // SAFETY: pid was enumerated as a direct child of this dedicated
    // subreaper, so SIGKILL cannot target an unrelated process group.
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(format!("kill isolated child {pid}: {error}"))
}

#[cfg(target_os = "linux")]
fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}
