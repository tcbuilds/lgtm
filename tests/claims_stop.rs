mod common;
#[cfg(unix)]
#[path = "../src/test_support.rs"]
mod test_support;

use std::io::Read;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::TempRepo;
use serde_json::json;

const TEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TEST_CAPTURE_BYTES: u64 = 1024 * 1024;

// Regular-file capture avoids pipe backpressure and waiting for descendant EOF.
fn run_bounded_process(
    repo: &TempRepo,
    mut command: Command,
    input: Option<&str>,
    timeout: Duration,
) -> Output {
    let deadline = Instant::now() + timeout;
    let input = input.unwrap_or_default();
    assert!(input.len() as u64 <= MAX_TEST_CAPTURE_BYTES);
    repo.write(".lgtm/test-process/stdin", input);
    let capture = repo.path().join(".lgtm/test-process");
    command
        .stdin(std::fs::File::open(capture.join("stdin")).expect("fixture input"))
        .stdout(std::fs::File::create(capture.join("stdout")).expect("stdout capture"))
        .stderr(std::fs::File::create(capture.join("stderr")).expect("stderr capture"));
    prepare_fixture_process(&mut command);
    let mut child = command.spawn().expect("fixture process starts");
    let status = loop {
        if let Some(status) = child.try_wait().expect("fixture process status") {
            break status;
        }
        if Instant::now() >= deadline {
            kill_fixture_group(child.id());
            child.kill().expect("timed-out fixture process is killed");
            child.wait().expect("timed-out fixture process is reaped");
            panic!("fixture process exceeded {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    kill_fixture_group(child.id());
    Output {
        status,
        stdout: read_fixture_capture(capture.join("stdout")),
        stderr: read_fixture_capture(capture.join("stderr")),
    }
}

fn read_fixture_capture(path: std::path::PathBuf) -> Vec<u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .expect("capture file opens")
        .take(MAX_TEST_CAPTURE_BYTES + 1)
        .read_to_end(&mut bytes)
        .expect("capture file reads");
    assert!(bytes.len() as u64 <= MAX_TEST_CAPTURE_BYTES);
    bytes
}

fn prepare_fixture_process(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        // SAFETY: only async-safe process-local resource limits change after fork.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: MAX_TEST_CAPTURE_BYTES as libc::rlim_t,
                    rlim_max: MAX_TEST_CAPTURE_BYTES as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = command;
}

fn kill_fixture_group(pid: u32) {
    #[cfg(unix)]
    {
        // The owned process group may already be gone; direct-child reaping is separate.
        // SAFETY: the fixture owns the group whose identifier is its child's PID.
        unsafe {
            let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

fn run_stop(repo: &TempRepo, claim: &str) -> Output {
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[{"id":"verify","language":"shell","root":".","commands":[{"argv":["true"],"cwd":".","timeout_seconds":30,"tier":"full","purpose":"verify","source":"test","confidence":"high"}],"coverage":[]}],"disabled_rules":[],"severity_overrides":{}}"#,
    );
    repo.write("transcript.jsonl", &format!("{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n", serde_json::to_string(claim).expect("claim serializes")));
    let payload = json!({ "cwd": repo.path(), "session_id": "claims", "transcript_path": repo.path().join("transcript.jsonl"), "tier": "full" });
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.current_dir(repo.path()).args(["hook", "stop"]);
    run_bounded_process(
        repo,
        command,
        Some(&format!("{payload}\n")),
        TEST_PROCESS_TIMEOUT,
    )
}

#[cfg(unix)]
#[test]
fn fixture_process_captures_output_larger_than_pipe_capacity() {
    let repo = TempRepo::new();
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "/usr/bin/head -c 300000 /dev/zero; /usr/bin/head -c 300000 /dev/zero >&2",
    ]);
    let output = run_bounded_process(&repo, command, None, Duration::from_secs(2));
    assert!(output.status.success());
    assert_eq!(output.stdout, vec![0; 300000]);
    assert_eq!(output.stderr, vec![0; 300000]);
}

#[cfg(unix)]
#[test]
fn fixture_process_timeout_kills_and_reaps_stalled_child() {
    let repo = TempRepo::new();
    let mut command = Command::new("/bin/sleep");
    command.arg("20");
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_bounded_process(&repo, command, None, Duration::from_millis(100))
    }));
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(unix)]
#[test]
fn fixture_process_does_not_wait_for_descendant_output_eof() {
    test_support::run_in_isolated_process(
        "fixture_process_does_not_wait_for_descendant_output_eof",
        || {
            let repo = TempRepo::new();
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "/bin/sleep 20 & printf 'retained\\n'; exit 0"]);
            let started = Instant::now();
            let output = run_bounded_process(&repo, command, None, Duration::from_secs(2));
            assert!(output.status.success());
            assert_eq!(output.stdout, b"retained\n");
            assert!(started.elapsed() < Duration::from_secs(1));
        },
    );
}

#[test]
fn unsupported_success_claim_does_not_veto_completion() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`cargo test` passed");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("no checks ran"));
    assert!(output.stderr.is_empty());
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
}

#[test]
fn matching_command_claim_does_not_trigger_verification() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`true` passed successfully");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("no checks ran"));
    assert!(!repo.exists(".lgtm/evidence/evidence.jsonl"));
}

#[test]
fn operational_lgtm_claim_does_not_block_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`lgtm doctor` passed; the hook probe succeeded.");
    assert!(output.status.success());
}
