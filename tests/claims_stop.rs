mod common;

use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use common::TempRepo;
use serde_json::json;

const TEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TEST_CAPTURE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
enum HookEnvironment {
    Inherited,
    #[cfg(target_os = "linux")]
    FixtureBin,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum FullStopMode {
    Stop,
    Check,
}

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

fn run_hook(
    repo: &TempRepo,
    args: &[&str],
    payload: &serde_json::Value,
    environment: HookEnvironment,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lgtm"));
    command.args(args);
    match environment {
        HookEnvironment::Inherited => {}
        #[cfg(target_os = "linux")]
        HookEnvironment::FixtureBin => {
            let path = format!(
                "{}:{}",
                repo.path().join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            );
            command.env("PATH", path);
        }
    }
    run_bounded_process(
        repo,
        command,
        Some(&format!("{payload}\n")),
        TEST_PROCESS_TIMEOUT,
    )
}

fn run_stop(repo: &TempRepo, claim: &str) -> Output {
    repo.write(
        ".lgtm/config.json",
        r#"{"version":"2","profile":"default","workspaces":[{"id":"verify","language":"shell","root":".","commands":[{"argv":["true"],"cwd":".","timeout_seconds":30,"tier":"full","purpose":"verify","source":"test","confidence":"high"}],"coverage":[]}],"disabled_rules":[],"severity_overrides":{}}"#,
    );
    repo.write("transcript.jsonl", &format!("{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":{}}}]}}}}\n", serde_json::to_string(claim).expect("claim serializes")));
    let payload = json!({ "cwd": repo.path(), "session_id": "claims", "transcript_path": repo.path().join("transcript.jsonl"), "tier": "full" });
    run_hook(
        repo,
        &["hook", "stop"],
        &payload,
        HookEnvironment::Inherited,
    )
}

#[cfg(target_os = "linux")]
fn run_pre_tool_use_command(repo: &TempRepo, session_id: &str, command_text: &str) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "tool_name": "Bash",
        "tool_input": {"command": command_text}
    });
    run_hook(
        repo,
        &["hook", "pre-tool-use"],
        &payload,
        HookEnvironment::FixtureBin,
    )
}

#[cfg(target_os = "linux")]
fn run_full_stop_mode(repo: &TempRepo, session_id: &str, mode: FullStopMode) -> Output {
    let payload = json!({
        "cwd": repo.path(),
        "session_id": session_id,
        "check": matches!(mode, FullStopMode::Check),
        "tier": "full"
    });
    run_hook(
        repo,
        &["hook", "stop"],
        &payload,
        HookEnvironment::FixtureBin,
    )
}

#[cfg(target_os = "linux")]
fn run_full_stop(repo: &TempRepo, session_id: &str) -> Output {
    run_full_stop_mode(repo, session_id, FullStopMode::Stop)
}

#[cfg(target_os = "linux")]
fn run_full_check(repo: &TempRepo, session_id: &str) -> Output {
    run_full_stop_mode(repo, session_id, FullStopMode::Check)
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
    let repo = TempRepo::new();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "/bin/sleep 20 & printf 'retained\\n'; exit 0"]);
    let started = Instant::now();
    let output = run_bounded_process(&repo, command, None, Duration::from_secs(2));
    assert!(output.status.success());
    assert_eq!(output.stdout, b"retained\n");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn unsupported_success_claim_blocks_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`cargo test` passed");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("evidence-claims-honest"));
}

// Production command containment is available on Linux; macOS must surface
// configured commands as unavailable rather than claim that they passed.
#[cfg(target_os = "linux")]
#[test]
fn matching_required_command_claim_passes_honesty_check() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`true` passed successfully");
    assert!(output.status.success());
    let evidence = repo.read(".lgtm/evidence/evidence.jsonl");
    assert!(evidence.contains("evidence-claims-honest"));
    assert!(evidence.contains("\"status\":\"passed\""));
}

#[test]
fn operational_lgtm_claim_does_not_block_stop() {
    let repo = TempRepo::new();
    let output = run_stop(&repo, "`lgtm doctor` passed; the hook probe succeeded.");
    assert!(output.status.success());
}

#[cfg(target_os = "linux")]
fn clean_gitleaks_script() -> &'static str {
    "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n"
}

#[cfg(target_os = "linux")]
fn write_full_gate_config(repo: &TempRepo, command_argv: &[&Path]) {
    let command_argv = command_argv
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    repo.write(
        ".lgtm/config.json",
        &json!({
            "version": "2",
            "profile": "default",
            "workspaces": [{
                "id": "verify",
                "language": "shell",
                "root": ".",
                "commands": [{
                    "argv": command_argv,
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "tier": "full",
                    "purpose": "verify",
                    "source": "test",
                    "confidence": "high"
                }],
                "coverage": []
            }],
            "disabled_rules": [],
            "severity_overrides": {}
        })
        .to_string(),
    );
}

#[cfg(target_os = "linux")]
fn set_gate_fixture_executables(repo: &TempRepo, command: &Path) {
    let gitleaks = repo.path().join("bin/gitleaks");
    for executable in [command, gitleaks.as_path()] {
        std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o700))
            .expect("fixture executable");
    }
}

#[cfg(target_os = "linux")]
fn run_fixture_git(repo: &TempRepo, args: &[&str]) {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo.path()).args(args);
    let output = run_bounded_process(repo, command, None, TEST_PROCESS_TIMEOUT);
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn initialize_gate_fixture_git(repo: &TempRepo, staged_paths: &[&str]) {
    run_fixture_git(repo, &["init", "-q"]);
    let mut add_args = vec!["add"];
    add_args.extend_from_slice(staged_paths);
    run_fixture_git(repo, &add_args);
    run_fixture_git(
        repo,
        &[
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "user.name=test",
            "commit",
            "-qm",
            "initial",
        ],
    );
}

#[cfg(target_os = "linux")]
fn oversized_gate_fixture() -> (TempRepo, String) {
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    let repo = oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nIFS= read -r state < \"$2\"\ncase \"$state\" in\n    *mutated*) exit 7 ;;\nesac\nexit 0\n",
        clean_gitleaks_script(),
        &initial,
    );
    (repo, filler)
}

#[cfg(target_os = "linux")]
fn oversized_truncating_gate_fixture() -> (TempRepo, String) {
    // The fake scanner changes the initially oversized source before reporting
    // clean, so the pre-scanner latch must survive that normalization.
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    let repo = oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nsource=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    if [ \"$1\" = --source ]; then source=\"$2\"; shift 2; continue; fi\n    shift\ndone\nif [ -n \"$source\" ]; then : > \"$source\"; fi\nprintf '[]\\n' > \"$report\"\n",
        &initial,
    );
    (repo, filler)
}

#[cfg(target_os = "linux")]
fn configured_command_truncating_gate_fixture() -> TempRepo {
    let filler = "x".repeat(256 * 1024);
    let initial = format!("{{\"state\":\"initial\",\"padding\":\"{filler}\"}}\n");
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\n: > \"$2\"\nexit 0\n",
        clean_gitleaks_script(),
        &initial,
    )
}

#[cfg(target_os = "linux")]
fn configured_command_oversized_from_empty_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nprintf '%*s' 262145 '' > \"$2\"\nexit 0\n",
        clean_gitleaks_script(),
        "",
    )
}

#[cfg(target_os = "linux")]
fn scanner_oversized_then_command_empty_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\n: > \"$2\"\nexit 0\n",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nsource=\nwhile [ \"$#\" -gt 0 ]; do\n    case \"$1\" in\n        --report-path) report=\"$2\"; shift 2 ;;\n        --source) source=\"$2\"; shift 2 ;;\n        *) shift ;;\n    esac\ndone\ncase \"$source\" in\n    */src/oversized.json)\n        printf '%*s' 262145 '' >> \"$source\"\n        printf 'scanner-mutated\\n' > \"${source%/*}/scanner-mutated\"\n        ;;\nesac\nprintf '[]\\n' > \"$report\"\n",
        "{\"state\":\"initial\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn scanner_valid_content_then_command_restores_pre_scan_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        r#"#!/bin/sh
printf x >> "$1"
printf '{"state":"a"}\n' > "$2"
exit 0
"#,
        r#"#!/bin/sh
if [ "$1" = version ]; then printf 'fixture\n'; exit 0; fi
report=
source=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --report-path) report="$2"; shift 2 ;;
        --source) source="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [ -n "$source" ]; then printf '{"state":"b"}\n' > "$source"; fi
printf '[]\n' > "$report"
"#,
        "{\"state\":\"a\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn configured_command_valid_content_mutation_fixture() -> TempRepo {
    oversized_gate_fixture_with_command(
        r#"#!/bin/sh
printf x >> "$1"
printf '{"state":"b"}\n' > "$2"
exit 0
"#,
        clean_gitleaks_script(),
        "{\"state\":\"a\"}\n",
    )
}

#[cfg(target_os = "linux")]
fn oversized_gate_fixture_with_command(
    command_script: &str,
    gitleaks_script: &str,
    initial_contents: &str,
) -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/oversized-check");
    let counter = repo.path().join("full-gate-runs");
    let touched = repo.path().join("src/oversized.json");
    repo.write("bin/oversized-check", command_script);
    // Keep the full-gate result deterministic without depending on a host
    // gitleaks installation.
    repo.write("bin/gitleaks", gitleaks_script);
    set_gate_fixture_executables(&repo, &command);
    repo.write("src/oversized.json", initial_contents);
    write_full_gate_config(
        &repo,
        &[command.as_path(), counter.as_path(), touched.as_path()],
    );

    initialize_gate_fixture_git(
        &repo,
        &[
            "bin/oversized-check",
            "bin/gitleaks",
            "src/oversized.json",
            ".lgtm/config.json",
        ],
    );

    repo
}

#[cfg(target_os = "linux")]
fn symlink_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/symlink-check");
    let counter = repo.path().join("full-gate-runs");
    let link = repo.path().join("src/tracked.json");

    repo.write(".gitignore", "vendor/\n");
    repo.write(
        "bin/symlink-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nif /bin/grep -q '\"state\":\"mutated\"' \"$2\"; then exit 7; fi\nexit 0\n",
    );
    repo.write(
        "bin/gitleaks",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n",
    );
    repo.write("src/ordinary.rs", "fn value() -> u8 { 1 }\n");
    repo.write("vendor/ignored.json", "{\"state\":\"initial\"}\n");
    std::os::unix::fs::symlink("../vendor/ignored.json", &link)
        .expect("tracked supported-extension symlink");

    set_gate_fixture_executables(&repo, &command);
    write_full_gate_config(
        &repo,
        &[command.as_path(), counter.as_path(), link.as_path()],
    );

    initialize_gate_fixture_git(
        &repo,
        &[
            ".gitignore",
            "bin/symlink-check",
            "bin/gitleaks",
            "src/ordinary.rs",
            "src/tracked.json",
            ".lgtm/config.json",
        ],
    );

    repo
}

#[cfg(target_os = "linux")]
fn extensionless_directory_symlink_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/directory-symlink-check");
    let counter = repo.path().join("full-gate-runs");
    let hidden = repo.path().join("src/hidden");
    let touched = repo.path().join("src/hidden/state.json");

    repo.write(".gitignore", "vendor/");
    repo.write(
        "bin/directory-symlink-check",
        r#"#!/bin/sh
printf x >> "$1"
IFS= read -r state < "$2"
case "$state" in
    *mutated*) exit 7 ;;
esac
exit 0
"#,
    );
    repo.write("bin/gitleaks", clean_gitleaks_script());
    repo.write("src/ordinary.rs", "fn value() -> u8 { 1 }\n");
    repo.write("vendor/hidden/state.json", "{\"state\":\"initial\"}\n");
    std::os::unix::fs::symlink("../vendor/hidden", &hidden)
        .expect("extensionless directory symlink");

    set_gate_fixture_executables(&repo, &command);
    write_full_gate_config(
        &repo,
        &[command.as_path(), counter.as_path(), touched.as_path()],
    );

    initialize_gate_fixture_git(
        &repo,
        &[
            ".gitignore",
            "bin/directory-symlink-check",
            "bin/gitleaks",
            "src/ordinary.rs",
            "src/hidden",
            ".lgtm/config.json",
        ],
    );

    repo
}

#[cfg(target_os = "linux")]
fn overdepth_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/overdepth-check");
    let counter = repo.path().join("full-gate-runs");
    let mut overdepth_file = String::from("deep");
    for index in 0..9 {
        overdepth_file.push_str(&format!("/depth-{index}"));
    }
    overdepth_file.push_str("/over.rs");

    repo.write(
        "bin/overdepth-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    repo.write("bin/gitleaks", clean_gitleaks_script());
    repo.write("src/ordinary.rs", "fn ordinary() -> u8 { 1 }\n");
    repo.write(&overdepth_file, "fn over() -> u8 { 1 }\n");
    set_gate_fixture_executables(&repo, &command);
    write_full_gate_config(&repo, &[command.as_path(), counter.as_path()]);

    let staged_paths = [
        "bin/overdepth-check",
        "bin/gitleaks",
        "src/ordinary.rs",
        ".lgtm/config.json",
        overdepth_file.as_str(),
    ];
    initialize_gate_fixture_git(&repo, &staged_paths);

    repo
}

#[cfg(target_os = "linux")]
#[test]
fn overdepth_scanner_uncertainty_forces_same_session_full_gate_rerun() {
    let repo = overdepth_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "overdepth-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    let decision: serde_json::Value = serde_json::from_slice(&first.stdout).expect("deny decision");
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("repository-source-scan"))
    );
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "scanner over-depth uncertainty persists the non-reusable sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance carries scanner over-depth uncertainty"
    );

    let second = run_pre_tool_use_command(&repo, "overdepth-retry", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    let decision: serde_json::Value = serde_json::from_slice(&second.stdout).expect("retry denial");
    assert_eq!(decision["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "scanner over-depth uncertainty forces a same-session full-gate rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_unchanged_file_reruns_staged_commit_gate() {
    let repo = oversized_gate_fixture_with_command(
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
        clean_gitleaks_script(),
        "{\"state\":\"stable\"}\n",
    );
    let first = run_pre_tool_use_command(&repo, "ordinary-reuse", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_ne!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "bounded ordinary content should produce reusable digest evidence"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"], first_record["touched_files_digest"],
        "nested command provenance should match the generated top-level digest"
    );

    let second = run_pre_tool_use_command(&repo, "ordinary-reuse", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "staged commits require a fresh full gate even when workspace evidence is unchanged"
    );
}

#[cfg(target_os = "linux")]
fn unresolved_ledger_gate_fixture() -> TempRepo {
    let repo = TempRepo::new();
    let command = repo.path().join("bin/unresolved-check");
    let counter = repo.path().join("full-gate-runs");
    let session_id = "unresolved-ledger-retry";

    repo.write(
        "bin/unresolved-check",
        "#!/bin/sh\nprintf x >> \"$1\"\nexit 0\n",
    );
    // Keep the full Stop deterministic without depending on a host gitleaks
    // installation.
    repo.write(
        "bin/gitleaks",
        "#!/bin/sh\nif [ \"$1\" = version ]; then printf 'fixture\\n'; exit 0; fi\nreport=\nwhile [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = --report-path ]; then report=\"$2\"; shift 2; continue; fi\n    shift\ndone\nprintf '[]\\n' > \"$report\"\n",
    );
    set_gate_fixture_executables(&repo, &command);

    // Keep the anchor under a test path so the Stop diff-association policy
    // has no missing-source obligation unrelated to this reuse regression.
    repo.write("tests/anchor.rs", "fn anchor() -> u8 { 1 }\n");
    // Keep both candidates in one no-committed-secrets record: the valid
    // edited_file anchors the scanned path while the unresolved location must
    // still make the candidate set non-reusable.
    let anchor_record = json!({
        "session_id": session_id,
        "edited_file": "tests/anchor.rs",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "passed",
            "severity": "error",
            "message": "clean",
            "locations": [{"file": "src/missing.rs", "line": 1}],
            "evidence": {
                "check": "gitleaks.detect",
                "tool_version": null,
                "finding_descriptions": []
            }
        }
    });
    repo.write(
        ".lgtm/evidence/current-task.results.jsonl",
        &format!("{anchor_record}\n"),
    );
    write_full_gate_config(&repo, &[command.as_path(), counter.as_path()]);

    // The diff association check must see a real repository so a passing Stop
    // record is not obscured by an unrelated git-unavailable result.
    initialize_gate_fixture_git(
        &repo,
        &[
            "bin/unresolved-check",
            "bin/gitleaks",
            "tests/anchor.rs",
            ".lgtm/config.json",
        ],
    );

    repo
}

#[cfg(target_os = "linux")]
#[test]
fn unresolved_ledger_candidate_propagates_uncertainty_to_precommit_rerun() {
    let repo = unresolved_ledger_gate_fixture();
    let first = run_full_stop(&repo, "unresolved-ledger-retry");
    assert!(first.status.success(), "full Stop: {:?}", first.stderr);
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("full Stop evidence record"),
    )
    .expect("full Stop evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the missing location ledger candidate makes the Stop digest uncertain"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the full Stop command evidence is passing"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "uncertainty propagates to passing command provenance"
    );

    let second = run_pre_tool_use_command(&repo, "unresolved-ledger-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "pre-commit gate: {:?}",
        second.stderr
    );
    assert!(
        second.stdout.is_empty(),
        "a passing rerun emits no decision"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain Stop record must not be reused by pre-commit"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn tracked_symlink_to_ignored_target_forces_same_session_full_gate_rerun() {
    let repo = symlink_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "symlink-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the omitted symlink makes the touched set non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    repo.write("vendor/ignored.json", "{\"state\":\"mutated\"}\n");
    let second = run_pre_tool_use_command(&repo, "symlink-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the command must observe the mutated symlink target"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the target mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "uncertain symlink evidence must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn extensionless_directory_symlink_forces_same_session_full_gate_rerun() {
    let repo = extensionless_directory_symlink_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "directory-symlink-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the extensionless directory symlink makes the candidate set non-reusable"
    );

    repo.write(
        "vendor/hidden/state.json",
        r#"{"state":"mutated"}
"#,
    );
    let second = run_pre_tool_use_command(&repo, "directory-symlink-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the rerun command must observe the mutated hidden target"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the target mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "an extensionless directory symlink must force a same-session full-gate rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_mutation_reruns_same_session_full_gate() {
    let (repo, filler) = oversized_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "oversized-retry", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "oversized touched content is recorded as non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    // Keep the replacement oversized so both attempts are in the same
    // bounded-overflow class, while changing the content the command reads.
    repo.write(
        "src/oversized.json",
        &format!("{{\"state\":\"mutated\",\"padding\":\"{filler}\"}}\n"),
    );
    let second = run_pre_tool_use_command(&repo, "oversized-retry", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision"
    );
    let decision: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("retry deny decision JSON");
    assert_eq!(
        decision["hookSpecificOutput"]["permissionDecision"], "deny",
        "the mutated oversized file must not authorize evidence reuse"
    );
    assert!(
        decision["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .is_some_and(|reason| reason.contains("exit status 7")),
        "the ordinary full gate must observe the mutation"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the retry must execute the full command instead of reusing evidence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_truncation_by_gitleaks_latches_non_reusable_full_gate_evidence() {
    let (repo, _filler) = oversized_truncating_gate_fixture();
    let first = run_full_check(&repo, "oversized-truncate");
    assert!(
        first.status.success(),
        "first full check: {:?}",
        first.stderr
    );
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the fake gitleaks scanner truncates the scanned file"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the pre-scan oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves the pre-scan uncertainty"
    );

    let second = run_pre_tool_use_command(&repo, "oversized-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain first attempt must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_empty_replacement_does_not_reuse_same_session_evidence() {
    let (repo, _filler) = oversized_gate_fixture();
    let first = run_pre_tool_use_command(&repo, "oversized-empty", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "oversized touched content persists the uncertain sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance carries the non-reusable sentinel"
    );

    // A regular empty replacement must not match the persisted uncertain
    // digest from the oversized first attempt.
    repo.write("src/oversized.json", "");
    let replacement =
        run_pre_tool_use_command(&repo, "oversized-empty", "git commit -m empty-replacement");
    assert!(
        replacement.status.success(),
        "empty replacement gate: {:?}",
        replacement.stderr
    );
    assert!(
        replacement.stdout.is_empty(),
        "empty replacement full gate should pass"
    );
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "an empty replacement must rerun instead of reusing oversized evidence"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_file_truncation_by_configured_command_latches_non_reusable_evidence() {
    let repo = configured_command_truncating_gate_fixture();
    let first =
        run_pre_tool_use_command(&repo, "oversized-command-truncate", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the configured command truncates the initially oversized source"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "the pre-command oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves the pre-command uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured truncating command exits successfully"
    );

    let second =
        run_pre_tool_use_command(&repo, "oversized-command-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "the uncertain first attempt must rerun the configured full command"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn post_command_oversized_file_persists_uncertainty_and_forces_same_session_rerun() {
    let repo = configured_command_oversized_from_empty_fixture();
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the touched file starts empty"
    );

    let first = run_pre_tool_use_command(&repo, "post-command-oversized", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first full gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/oversized.json").len(),
        256 * 1024 + 1,
        "the configured command makes the touched file oversized"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "post-command oversized content persists the non-reusable sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance preserves post-command uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured command passes despite making the file oversized"
    );

    repo.write("src/oversized.json", "");
    let second = run_pre_tool_use_command(&repo, "post-command-oversized", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "post-command uncertainty must force a same-session rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn scanner_oversized_then_configured_command_empty_latches_non_reusable_evidence() {
    let repo = scanner_oversized_then_command_empty_fixture();
    let first = run_full_check(&repo, "scanner-command-truncate");
    assert!(
        first.status.success(),
        "first full check: {:?}",
        first.stderr
    );
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(
        repo.read("src/scanner-mutated"),
        "scanner-mutated\n",
        "the fake scanner must mutate the target before its clean report"
    );
    assert_eq!(
        repo.read("src/oversized.json"),
        "",
        "the configured command restores a representable empty source"
    );

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "scanner-introduced oversized content makes the first record non-reusable"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "command provenance preserves scanner-introduced uncertainty"
    );
    assert_eq!(
        first_record["commands"][0]["exit_code"],
        json!(0),
        "the configured normalizing command exits successfully"
    );

    let second = run_pre_tool_use_command(&repo, "scanner-command-truncate", "git commit -m retry");
    assert!(
        second.status.success(),
        "retry hook should return a decision: {:?}",
        second.stderr
    );
    assert!(second.stdout.is_empty(), "second full gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "scanner-introduced uncertainty must force a same-session rerun"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn valid_scanner_mutation_requires_post_scan_digest_equality() {
    let repo = scanner_valid_content_then_command_restores_pre_scan_fixture();
    let first = run_full_check(&repo, "scanner-valid-equality");
    assert!(
        first.status.success(),
        "first full check: {:?}",
        first.stderr
    );
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(repo.read("src/oversized.json"), "{\"state\":\"a\"}\n");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "a valid scanner A-to-B mutation must latch the non-reusable sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance must carry the scanner latch"
    );

    let second = run_pre_tool_use_command(&repo, "scanner-valid-equality", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    assert!(second.stdout.is_empty(), "retry gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "a scanner-valid mutation must force a same-session rerun even after command normalization"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn valid_configured_command_mutation_requires_post_command_digest_equality() {
    let repo = configured_command_valid_content_mutation_fixture();
    let first = run_pre_tool_use_command(&repo, "command-valid-equality", "git commit -m first");
    assert!(first.status.success(), "first gate: {:?}", first.stderr);
    assert!(first.stdout.is_empty(), "first gate should pass");
    assert_eq!(repo.read("full-gate-runs"), "x");
    assert_eq!(repo.read("src/oversized.json"), "{\"state\":\"b\"}\n");

    let first_record: serde_json::Value = serde_json::from_str(
        repo.read(".lgtm/evidence/evidence.jsonl")
            .lines()
            .next_back()
            .expect("first evidence record"),
    )
    .expect("first evidence is JSON");
    assert_eq!(
        first_record["touched_files_digest"],
        json!("0".repeat(64)),
        "a valid configured-command A-to-B mutation must latch the sentinel"
    );
    assert_eq!(
        first_record["commands"][0]["touched_files_digest"],
        json!("0".repeat(64)),
        "nested command provenance must carry the post-command mismatch"
    );

    let second = run_pre_tool_use_command(&repo, "command-valid-equality", "git commit -m retry");
    assert!(second.status.success(), "retry gate: {:?}", second.stderr);
    assert!(second.stdout.is_empty(), "retry gate should pass");
    assert_eq!(
        repo.read("full-gate-runs"),
        "xx",
        "a configured-command valid mutation must force a same-session rerun"
    );
}
