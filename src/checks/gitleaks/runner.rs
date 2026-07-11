use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::report::{MAX_CAPTURE_BYTES, ScanOutcome, classify_exit};

const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const DRAIN_JOIN_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn run_captured(mut command: Command) -> Option<(Option<i32>, Vec<u8>)> {
    prepare_command(&mut command);
    let mut child = command.spawn().ok()?;
    let pid = child.id();
    let stdout = drain_bounded(child.stdout.take());
    let stderr = drain_bounded(child.stderr.take());
    let status = wait_bounded(child, pid);
    let captured = join_bounded(stdout, DRAIN_JOIN_TIMEOUT).unwrap_or_default();
    let _ = join_bounded(stderr, DRAIN_JOIN_TIMEOUT);
    status.map(|status| (status.code(), captured))
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
    let status = wait_bounded(child, pid);
    let _ = join_bounded(stdout, DRAIN_JOIN_TIMEOUT);
    let _ = join_bounded(stderr, DRAIN_JOIN_TIMEOUT);
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

fn wait_bounded(child: Child, pid: u32) -> Option<std::process::ExitStatus> {
    let child = Arc::new(Mutex::new(child));
    let (sender, receiver) = mpsc::channel();
    let waiter = Arc::clone(&child);
    let watcher = thread::spawn(move || {
        loop {
            let poll = waiter
                .lock()
                .map_err(|_| ())
                .map(|mut guard| guard.try_wait());
            match poll {
                Ok(Ok(Some(status))) => {
                    let _ = sender.send(Ok(status));
                    return;
                }
                Ok(Ok(None)) => thread::sleep(POLL_INTERVAL),
                Ok(Err(_)) | Err(()) => {
                    let _ = sender.send(Err(()));
                    return;
                }
            }
        }
    });
    let outcome = match receiver.recv_timeout(SUBPROCESS_TIMEOUT) {
        Ok(Ok(status)) => Some(status),
        Ok(Err(())) => None,
        Err(_) => {
            kill_child(&child, pid);
            None
        }
    };
    let _ = watcher.join();
    outcome
}

fn kill_child(child: &Arc<Mutex<Child>>, pid: u32) {
    kill_process_group(pid);
    let mut guard = child
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = guard.kill();
    let _ = guard.wait();
}

fn join_bounded(
    handle: Option<thread::JoinHandle<Vec<u8>>>,
    deadline: Duration,
) -> Option<Vec<u8>> {
    let handle = handle?;
    let start = Instant::now();
    while !handle.is_finished() {
        if start.elapsed() >= deadline {
            return None;
        }
        thread::sleep(POLL_INTERVAL);
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
        let child = Arc::new(Mutex::new(child));
        kill_child(&child, pid);
        assert!(join_bounded(stdout, DRAIN_JOIN_TIMEOUT).is_some());
        assert!(join_bounded(stderr, DRAIN_JOIN_TIMEOUT).is_some());
    }
}
