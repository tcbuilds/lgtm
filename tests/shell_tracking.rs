#![cfg(unix)]

//! End-to-end regression coverage for Bash pre/post edit attribution.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use lgtm::checks::Status;
use lgtm::checks::diff::{Stage, evaluate_at};
use serde_json::{Value, json};

mod common;
use common::TempRepo;

const LEDGER: &str = ".lgtm/evidence/current-task.results.jsonl";
const BASELINE: &str = ".lgtm/evidence/current-task.baseline.json";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CAPTURE_BYTES: u64 = 1024 * 1024;
const SESSION_ID: &str = "shell-tracking";
static CAPTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct CaptureDirectory(PathBuf);

impl CaptureDirectory {
    fn new() -> Self {
        let counter = CAPTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "lgtm-shell-capture-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("capture directory should be unique and creatable");
        Self(path)
    }
}

impl Drop for CaptureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_bounded(mut command: Command, input: Option<&str>) -> Output {
    let capture = CaptureDirectory::new();
    let stdout_path = capture.0.join("stdout");
    let stderr_path = capture.0.join("stderr");
    let stdin = if let Some(input) = input {
        let path = capture.0.join("stdin");
        fs::write(&path, input).expect("subprocess input should be writable");
        Stdio::from(File::open(path).expect("subprocess input should be readable"))
    } else {
        Stdio::null()
    };

    command
        .stdin(stdin)
        .stdout(Stdio::from(
            File::create(stdout_path.clone()).expect("stdout capture should open"),
        ))
        .stderr(Stdio::from(
            File::create(stderr_path.clone()).expect("stderr capture should open"),
        ));
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    // SAFETY: the child only needs a process-local output-file size limit before exec.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: MAX_CAPTURE_BYTES as libc::rlim_t,
                rlim_max: MAX_CAPTURE_BYTES as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("fixture subprocess should start");
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("fixture subprocess status") {
            break status;
        }
        if Instant::now() >= deadline {
            kill_process_group(child.id());
            let _ = child.kill();
            child.wait().expect("timed-out subprocess should be reaped");
            panic!("fixture subprocess exceeded {PROCESS_TIMEOUT:?}");
        }
        thread::sleep(Duration::from_millis(10));
    };

    kill_process_group(child.id());
    Output {
        status,
        stdout: read_capture(&stdout_path),
        stderr: read_capture(&stderr_path),
    }
}

fn read_capture(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .expect("subprocess capture should open")
        .take(MAX_CAPTURE_BYTES + 1)
        .read_to_end(&mut bytes)
        .expect("subprocess capture should read");
    assert!(
        bytes.len() as u64 <= MAX_CAPTURE_BYTES,
        "subprocess output exceeded the capture limit"
    );
    bytes
}

fn kill_process_group(pid: u32) {
    // SAFETY: run_bounded starts the child in a new process group using its PID.
    unsafe {
        let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

fn run_git(repo: &TempRepo, args: &[&str]) {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo.path()).args(args);
    let output = run_bounded(command, None);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tracked_repo() -> TempRepo {
    let repo = TempRepo::new();
    for (path, contents) in [
        ("clean.txt", "clean base\n"),
        ("dirty.txt", "dirty base\n"),
        ("untouched-dirty.txt", "untouched base\n"),
        ("deleted.txt", "delete me\n"),
        ("rename-source.txt", "rename this tracked file\n"),
    ] {
        repo.write(path, contents);
    }
    run_git(&repo, &["init", "-q"]);
    run_git(&repo, &["add", "--", "."]);
    run_git(
        &repo,
        &[
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
    );
    repo.write(".git/info/exclude", "\n/.lgtm/\n");
    repo
}

fn write_preexisting_changes(repo: &TempRepo) {
    repo.write("dirty.txt", "dirty before shell\n");
    repo.write("untouched-dirty.txt", "user's unrelated edit\n");
    repo.write("baseline-untracked.txt", "user's untracked file\n");
}

fn run_hook(repo: &TempRepo, event: &str, tool_use_id: &str, command_text: &str) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": SESSION_ID,
        "tool_use_id": tool_use_id,
        "tool_name": "Bash",
        "tool_input": { "command": command_text },
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.current_dir(repo.path()).args(["hook", event]);
    run_bounded(command, Some(&format!("{payload}\n")))
}

fn run_shell_script(repo: &TempRepo, script: &str) {
    let mut command = Command::new("sh");
    command.current_dir(repo.path()).args(["-c", script]);
    let output = run_bounded(command, None);
    assert!(
        output.status.success(),
        "shell script failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_records(repo: &TempRepo) -> Vec<Value> {
    if !repo.exists(LEDGER) {
        return Vec::new();
    }
    repo.read(LEDGER)
        .lines()
        .map(|line| serde_json::from_str(line).expect("ledger row should be JSON"))
        .collect()
}

fn edited_paths(records: &[Value]) -> BTreeSet<String> {
    records
        .iter()
        .filter_map(|record| record["edited_file"].as_str().map(str::to_string))
        .collect()
}

fn stop_results(repo: &TempRepo) -> Vec<Value> {
    let payload = json!({"cwd": repo.path(), "session_id": SESSION_ID, "tier": "targeted"});
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.current_dir(repo.path()).args(["hook", "stop"]);
    let output = run_bounded(command, Some(&payload.to_string()));
    assert!(
        repo.exists(".lgtm/evidence/evidence.jsonl"),
        "Stop failed: {:?}",
        output
    );
    let records = repo.read(".lgtm/evidence/evidence.jsonl");
    let record: Value = serde_json::from_str(records.lines().last().expect("Stop record")).unwrap();
    record["results"].as_array().expect("Stop results").clone()
}

fn assert_tracking_uncertain(repo: &TempRepo) {
    assert!(
        stop_results(repo).iter().any(|result| {
            result["rule_id"] == "current-task-evidence" && result["status"] == "unverified"
        }),
        "Stop must retain missing or ambiguous shell evidence"
    );
}

fn baseline_paths(repo: &TempRepo) -> BTreeSet<String> {
    repo.read_json(BASELINE)["diff_files_before"]
        .as_array()
        .expect("baseline should contain the original diff file list")
        .iter()
        .map(|path| {
            path.as_str()
                .expect("baseline paths should be strings")
                .to_string()
        })
        .collect()
}

#[test]
fn shell_changes_are_attributed_without_claiming_untouched_user_files() {
    let repo = tracked_repo();
    write_preexisting_changes(&repo);
    let script = concat!(
        "printf '%s\\n' 'new file' > added.txt; ",
        "printf '%s\\n' 'shell edit' >> clean.txt; ",
        "printf '%s\\n' 'shell edit' > dirty.txt; ",
        "rm deleted.txt; ",
        "mv rename-source.txt rename-target.txt"
    );

    let pre = run_hook(&repo, "pre-tool-use", "tool-1", script);
    assert!(
        pre.status.success(),
        "pre-tool-use failed: {:?}",
        pre.stderr
    );
    assert!(
        pre.stdout.is_empty(),
        "allowed Bash pre-hook should be silent"
    );
    assert!(
        repo.exists(BASELINE),
        "Bash pre-tool-use should capture a baseline for the tool call"
    );

    let baseline = baseline_paths(&repo);
    for path in ["dirty.txt", "untouched-dirty.txt", "baseline-untracked.txt"] {
        assert!(
            baseline.contains(path),
            "original dirty path missing: {path}"
        );
    }
    for path in ["clean.txt", "deleted.txt", "rename-source.txt"] {
        assert!(
            !baseline.contains(path),
            "clean pre-edit path was incorrectly in the baseline: {path}"
        );
    }

    run_shell_script(&repo, script);
    assert_eq!(repo.read("dirty.txt"), "shell edit\n");
    assert_eq!(repo.read("clean.txt"), "clean base\nshell edit\n");
    assert!(!repo.exists("deleted.txt"));
    assert!(repo.exists("rename-target.txt"));

    let post = run_hook(&repo, "post-tool-use", "tool-1", script);
    assert!(
        post.status.success(),
        "post-tool-use failed: {:?}",
        post.stderr
    );
    let records = read_records(&repo);
    let edited = edited_paths(&records);
    for path in [
        "added.txt",
        "clean.txt",
        "dirty.txt",
        "deleted.txt",
        "rename-source.txt",
        "rename-target.txt",
    ] {
        assert!(
            edited.contains(path),
            "shell edit was not attributed: {path}; got {edited:?}"
        );
    }
    for path in ["untouched-dirty.txt", "baseline-untracked.txt"] {
        assert!(
            !edited.contains(path),
            "unchanged preexisting user path was falsely attributed: {path}"
        );
    }

    let results = evaluate_at(repo.path(), &edited, Some(&baseline), None, Stage::Stop);
    let preserve = results
        .iter()
        .find(|result| result.rule_id == "preserve-unrelated-user-changes")
        .expect("diff evaluation should include the preserve-user-changes result");
    assert_eq!(
        preserve.status,
        Status::Passed,
        "the ledger paths and captured baseline should account for this shell change set"
    );
    let results = stop_results(&repo);
    assert!(
        results.iter().any(|result| {
            result["rule_id"] == "preserve-unrelated-user-changes" && result["status"] == "passed"
        }),
        "real Stop must include deleted and renamed paths: {results:?}"
    );
    repo.write("not-observed.txt", "external edit");
    assert!(
        stop_results(&repo).iter().any(|result| {
            result["rule_id"] == "preserve-unrelated-user-changes" && result["status"] == "failed"
        }),
        "Stop must still flag changes outside the hook window"
    );
}

#[path = "shell_tracking/lifecycle.rs"]
mod lifecycle;
