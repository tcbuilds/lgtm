use super::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use super::evidence::{
    MAX_EVIDENCE_BYTES, MAX_EVIDENCE_RECORDS, MAX_MUST_KEEP_RECORDS, append_evidence,
    is_must_keep_record, trim_records,
};
use super::input::{HookInput, ToolInput, edited_file};
use super::target::{resolve_target, unverified_target};

struct TempDir {
    path: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    fn new() -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("lgtm-post-tool-{}-{unique}", std::process::id());
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).expect("temp dir creatable");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run_capture(stdin: &str) -> (String, ExitCode) {
    let mut input = stdin.as_bytes();
    let mut output = Vec::new();
    let code = run(&mut input, &mut output);
    (
        String::from_utf8(output).expect("stdout must be UTF-8"),
        code,
    )
}

#[test]
fn non_edit_tool_is_ignored_silently() {
    let stdin = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": { "file_path": "/etc/passwd" },
    })
    .to_string();
    let (out, code) = run_capture(&stdin);
    assert!(out.is_empty(), "a non-edit tool must emit nothing");
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn malformed_stdin_exits_zero_with_no_output() {
    let (out, code) = run_capture("{ not json");
    assert!(out.is_empty(), "malformed stdin must emit nothing");
    assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
}

#[test]
fn post_tool_native_language_check_reports_typescript_violation() {
    let temp = TempDir::new();
    let file = temp.path.join("App.tsx");
    std::fs::write(&file, "const value: any = input;\n").expect("fixture source");
    let (_, results) = scan_target(&temp.path, &file.to_string_lossy());
    let finding = results
        .iter()
        .find(|result| result.rule_id == "typescript-no-any")
        .expect("native TypeScript rule result");
    assert_eq!(finding.status, Status::Failed);
    assert_eq!(finding.locations[0].line, Some(1));
}

#[test]
fn post_tool_native_language_check_reports_rust_violation() {
    let temp = TempDir::new();
    let file = temp.path.join("lib.rs");
    std::fs::write(&file, "fn value() { let _ = input.unwrap(); }\n").expect("fixture source");
    let (_, results) = scan_target(&temp.path, &file.to_string_lossy());
    let finding = results
        .iter()
        .find(|result| result.rule_id == "rust-no-unwrap-expect")
        .expect("native Rust rule result");
    assert_eq!(finding.status, Status::Failed);
    assert_eq!(finding.locations[0].line, Some(1));
}

#[test]
fn post_tool_native_language_check_reports_go_violation() {
    let temp = TempDir::new();
    let file = temp.path.join("main.go");
    std::fs::write(&file, "package main\nfunc Run() { go func() {} }\n").expect("fixture source");
    let (_, results) = scan_target(&temp.path, &file.to_string_lossy());
    let finding = results
        .iter()
        .find(|result| result.rule_id == "go-goroutine-cancellation")
        .expect("native Go rule result");
    assert_eq!(finding.status, Status::Failed);
}

#[test]
fn edited_file_only_matches_edit_tools() {
    let mut input = HookInput {
        tool_name: Some("Read".to_string()),
        tool_input: Some(ToolInput {
            file_path: Some("/a.py".to_string()),
        }),
        ..HookInput::default()
    };
    assert_eq!(edited_file(&input), None, "Read is not an edit tool");

    input.tool_name = Some("Edit".to_string());
    assert_eq!(edited_file(&input), Some("/a.py".to_string()));

    input.tool_name = Some("MultiEdit".to_string());
    assert_eq!(edited_file(&input), Some("/a.py".to_string()));

    input.tool_input = Some(ToolInput {
        file_path: Some("   ".to_string()),
    });
    assert_eq!(edited_file(&input), None, "a blank path is ignored");
}

#[test]
fn evidence_record_is_appended_and_well_formed() {
    let temp = TempDir::new();
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "clean".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, Some("sess-1"), Some("src/app.py"), &result)
        .expect("append must succeed");

    let ledger = temp
        .path
        .join(".lgtm")
        .join("evidence")
        .join("current-task.results.jsonl");
    let contents = std::fs::read_to_string(&ledger).expect("ledger readable");
    let line = contents.lines().next().expect("one record present");
    let value: Value = serde_json::from_str(line).expect("record must be valid JSON");
    assert_eq!(value["session_id"], json!("sess-1"));
    assert_eq!(value["edited_file"], json!("src/app.py"));
    assert_eq!(value["result"]["rule_id"], json!("no-committed-secrets"));
    assert_eq!(value["result"]["status"], json!("passed"));
}

#[test]
fn oversized_ledger_rotates_to_stay_bounded() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");

    let filler_line = format!("{}\n", "x".repeat(1024));
    let line_count = (MAX_EVIDENCE_BYTES as usize / filler_line.len()) + 16;
    let mut seed = String::with_capacity(filler_line.len() * line_count);
    for _ in 0..line_count {
        seed.push_str(&filler_line);
    }
    std::fs::write(&path, &seed).expect("seed writable");
    assert!(seed.len() as u64 > MAX_EVIDENCE_BYTES);

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "clean".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, Some("sess-2"), Some("src/app.py"), &result)
        .expect("append must succeed");

    let size = std::fs::metadata(&path).expect("ledger present").len();
    assert!(
        size <= MAX_EVIDENCE_BYTES,
        "rotated ledger size {size} must not exceed the cap {MAX_EVIDENCE_BYTES}"
    );
    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    let last = contents.lines().next_back().expect("a record survives");
    let value: Value = serde_json::from_str(last).expect("survivor is valid JSON");
    assert_eq!(value["session_id"], json!("sess-2"), "newest record kept");
}

#[test]
fn block_reason_strips_control_characters() {
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "found\ta secret".to_string(),
        locations: Vec::new(),
        remediation: Some("remove\rit".to_string()),
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let reason = block_reason(&result);
    assert!(!reason.contains('\t'), "tabs stripped");
    assert!(!reason.contains('\r'), "carriage returns stripped");
    assert!(reason.contains("found"), "message text preserved");
}

#[test]
fn resolve_target_joins_relative_path_against_payload_cwd() {
    let temp = TempDir::new();
    std::fs::write(temp.path.join("edited.py"), "x = 1\n").expect("file writable");

    let resolved =
        resolve_target(&temp.path, "edited.py").expect("an existing relative file resolves");
    assert!(
        Path::new(&resolved).is_absolute(),
        "a relative path must resolve against the payload cwd, not stay relative"
    );
    assert!(
        resolved.ends_with("edited.py"),
        "the resolved path must name the edited file: {resolved}"
    );
}

#[test]
fn resolve_target_absent_file_is_unverified_not_passed() {
    let temp = TempDir::new();
    assert_eq!(
        resolve_target(&temp.path, "never-created.py"),
        None,
        "an absent file must not resolve, so the caller records it as skipped"
    );

    let result = unverified_target("never-created.py");
    assert_eq!(
        result.status,
        Status::Unverified,
        "an absent edited file must be skipped, never a verified-clean pass"
    );
}

#[test]
fn resolve_target_directory_is_unverified_not_scanned() {
    let temp = TempDir::new();
    let dir = temp.path.join("a-directory");
    std::fs::create_dir(&dir).expect("directory creatable");
    assert_eq!(
        resolve_target(&temp.path, "a-directory"),
        None,
        "a directory must not resolve as a scan target: scanning it would recurse a tree"
    );
}

#[cfg(unix)]
#[test]
fn resolve_target_fifo_is_unverified_not_scanned() {
    let temp = TempDir::new();
    let fifo = temp.path.join("a-fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())
        .expect("fifo path has no interior nul");
    // SAFETY: `mkfifo` takes a valid C string path and a mode; both are
    // well-formed here. A non-zero return is a benign creation failure the
    // assertion below surfaces.
    let made = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
    assert_eq!(made, 0, "fifo must be creatable for the test");

    assert_eq!(
        resolve_target(&temp.path, "a-fifo"),
        None,
        "a FIFO must not resolve as a scan target: a read of it would block"
    );
}

#[cfg(unix)]
#[test]
fn resolve_target_symlink_is_unverified_not_followed() {
    let temp = TempDir::new();
    let target = temp.path.join("real.py");
    std::fs::write(&target, "x = 1\n").expect("target writable");
    let link = temp.path.join("link.py");
    std::os::unix::fs::symlink(&target, &link).expect("symlink creatable");

    assert_eq!(
        resolve_target(&temp.path, "link.py"),
        None,
        "a symlink must not resolve as a scan target: symlink_metadata does not follow it"
    );
}

#[test]
fn resolve_target_rejects_regular_file_outside_repo() {
    let repo = TempDir::new();
    let outside = TempDir::new();
    let file = outside.path.join("outside.py");
    std::fs::write(&file, "value = 1\n").expect("outside fixture writable");

    assert_eq!(
        resolve_target(&repo.path, file.to_str().expect("UTF-8 path")),
        None,
        "an absolute regular file outside the canonical repo must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn evidence_lock_deadline_skips_persistence_when_contended() {
    use std::os::unix::io::AsRawFd;

    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let lock_path = dir.join("current-task.results.lock");

    // Hold the flock for the whole test so the appender's acquire is forced to
    // exhaust its retry deadline and fail rather than blocking forever.
    let holder = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .expect("holder lock file opens");
    // SAFETY: valid open fd, blocking exclusive lock; released on close.
    let rc = unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "the test must hold the lock");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "leak".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };

    let start = std::time::Instant::now();
    let outcome = append_evidence(&temp.path, Some("sess-lock"), Some("src/app.py"), &result);
    let elapsed = start.elapsed();

    // SAFETY: valid open fd, unlock; the holder is dropped right after.
    unsafe {
        let _ = libc::flock(holder.as_raw_fd(), libc::LOCK_UN);
    }

    assert!(
        outcome.is_err(),
        "a contended lock must make the append fail so the hook can fall back to skip, not hang"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the acquire must give up within its bounded deadline, took {elapsed:?}"
    );

    let ledger = dir.join("current-task.results.jsonl");
    assert!(
        !ledger.exists(),
        "a deadlined acquire must not have written any evidence"
    );
}

/// Build one serialized ledger line for the given session and status.
fn record_line(session: Option<&str>, status: Status, message: &str) -> String {
    record_line_with_path(session, None, status, message)
}

fn record_line_with_path(
    session: Option<&str>,
    edited_file: Option<&str>,
    status: Status,
    message: &str,
) -> String {
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status,
        severity: crate::policy::Severity::Error,
        message: message.to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    serde_json::to_string(&json!({
        "session_id": session,
        "edited_file": edited_file,
        "result": result
    }))
    .expect("record serializes")
}

#[test]
fn trim_records_preserves_failed_records_of_current_session() {
    let session = Some("sess-keep");
    let failed = record_line(session, Status::Failed, "leak found");
    let mut existing = String::new();
    existing.push_str(&failed);
    existing.push('\n');
    for index in 0..64 {
        existing.push_str(&record_line(
            session,
            Status::Passed,
            &format!("clean {index}"),
        ));
        existing.push('\n');
    }

    // A budget too small to hold every passed record forces eviction; the
    // failed record must survive regardless.
    let kept = trim_records(&existing, session, failed.len() + 32);

    assert!(
        kept.contains("leak found"),
        "a failed record of the current session must never be evicted by rotation"
    );
    assert!(
        kept.lines().count() < existing.lines().count(),
        "some droppable passed records must have been evicted to fit the budget"
    );
}

#[test]
fn trim_records_drops_oldest_passed_first() {
    let session = Some("sess-order");
    let mut existing = String::new();
    for index in 0..8 {
        existing.push_str(&record_line(
            session,
            Status::Passed,
            &format!("clean {index}"),
        ));
        existing.push('\n');
    }
    let per_record = existing.len() / 8;

    // Budget for roughly three records; the newest three must survive.
    let kept = trim_records(&existing, session, per_record * 3 + 1);

    assert!(
        !kept.contains("clean 0") && !kept.contains("clean 1"),
        "the oldest passed records must be dropped first: {kept}"
    );
    assert!(
        kept.contains("clean 7"),
        "the newest passed record must be retained: {kept}"
    );
}

#[test]
fn is_must_keep_record_ignores_other_sessions_and_passes() {
    let this = Some("sess-a");
    assert!(is_must_keep_record(
        &record_line(this, Status::Failed, "x"),
        this
    ));
    assert!(is_must_keep_record(
        &record_line(this, Status::Unverified, "x"),
        this
    ));
    assert!(
        !is_must_keep_record(&record_line(this, Status::Passed, "x"), this),
        "a passed record is droppable"
    );
    assert!(
        !is_must_keep_record(&record_line(Some("sess-b"), Status::Failed, "x"), this),
        "a failed record of another session is not must-keep for this session"
    );
    assert!(
        !is_must_keep_record("{ not json", this),
        "an unparseable line is not must-keep"
    );
}

#[test]
fn append_after_rotation_keeps_failed_and_stays_bounded() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");

    // Seed a ledger over the cap: one failed record followed by enough passed
    // filler to force a rotation on the next append.
    let mut seed = String::new();
    seed.push_str(&record_line(Some("sess-x"), Status::Failed, "planted leak"));
    seed.push('\n');
    let filler = record_line(Some("sess-x"), Status::Passed, &"y".repeat(1024));
    let line_count = (MAX_EVIDENCE_BYTES as usize / (filler.len() + 1)) + 16;
    for _ in 0..line_count {
        seed.push_str(&filler);
        seed.push('\n');
    }
    std::fs::write(&path, &seed).expect("seed writable");
    assert!(seed.len() as u64 > MAX_EVIDENCE_BYTES);

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "newest".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, Some("sess-x"), Some("src/app.py"), &result)
        .expect("append must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    assert!(
        std::fs::metadata(&path).expect("ledger metadata").len() <= MAX_EVIDENCE_BYTES,
        "rotation must keep the ledger within the hard cap"
    );
    assert!(
        contents.contains("planted leak"),
        "rotation must preserve the failed record of the current session"
    );
    assert!(
        contents.contains("newest"),
        "the new record must be appended after rotation"
    );
}

#[test]
fn append_crossing_under_cap_rotates_and_stays_bounded() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let session = Some("sess-boundary");
    let pass_line = format!(
        "{}\n",
        record_line_with_path(session, Some("src/app.py"), Status::Passed, "boundary")
    );
    let failed_line = format!(
        "{}\n",
        record_line_with_path(session, Some("src/app.py"), Status::Failed, "boundary")
    );
    let cap = MAX_EVIDENCE_BYTES as usize;
    let mut seed = String::new();
    while seed.len() + pass_line.len() + failed_line.len() <= cap {
        seed.push_str(&pass_line);
    }
    seed.push_str(&pass_line);
    assert!(
        seed.len() <= cap,
        "under-cap seed must fit before the append"
    );
    assert!(
        seed.len() + failed_line.len() > cap,
        "the real append must cross the cap"
    );
    assert!(
        seed.lines().count() > 1,
        "seed must contain multiple JSONL records"
    );
    assert!(
        seed.lines()
            .all(|line| serde_json::from_str::<Value>(line).is_ok()),
        "under-cap seed must be valid JSONL"
    );
    std::fs::write(&path, seed).expect("under-cap seed writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "boundary".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, session, Some("src/app.py"), &result)
        .expect("under-cap crossing append must succeed");

    let contents = std::fs::read_to_string(&path).expect("rotated ledger readable");
    assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
    assert!(contents.lines().count() > 1);
    assert!(
        contents
            .lines()
            .all(|line| serde_json::from_str::<Value>(line).is_ok())
    );
    let last: Value = serde_json::from_str(contents.lines().next_back().expect("new record"))
        .expect("new record remains valid JSON");
    assert_eq!(last["result"]["status"], "failed");
    assert_eq!(last["edited_file"], "src/app.py");
}

#[test]
fn repeated_current_session_failures_keep_recent_identity_within_bounds() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let sample = record_line_with_path(
        Some("sess-failure-burst"),
        Some("src/failure-0.py"),
        Status::Failed,
        "failure-0",
    );
    let target_records = MAX_EVIDENCE_BYTES as usize / sample.len() + MAX_MUST_KEEP_RECORDS + 32;
    let mut seed = String::new();
    for index in 0..target_records {
        seed.push_str(&record_line_with_path(
            Some("sess-failure-burst"),
            Some(&format!("src/failure-{index}.py")),
            Status::Failed,
            &format!("failure-{index}"),
        ));
        seed.push('\n');
        if seed.len() as u64 > MAX_EVIDENCE_BYTES {
            break;
        }
    }
    assert!(seed.len() as u64 > MAX_EVIDENCE_BYTES);
    assert!((seed.len() as u64) < MAX_EVIDENCE_BYTES * 2);
    let oldest = "src/failure-0.py";
    let newest_seed = format!("src/failure-{}.py", seed.lines().count() - 1);
    std::fs::write(&path, seed).expect("seed writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Unverified,
        severity: crate::policy::Severity::Error,
        message: "newest failure signal".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-failure-burst"),
        Some("src/latest.py"),
        &result,
    )
    .expect("append must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("survivors remain valid JSON"))
        .collect();
    let failure_like = values
        .iter()
        .filter(|value| {
            matches!(
                value["result"]["status"].as_str(),
                Some("failed" | "unverified")
            )
        })
        .count();
    assert!(failure_like <= MAX_MUST_KEEP_RECORDS + 1);
    assert!(
        values
            .iter()
            .any(|value| value["edited_file"] == newest_seed),
        "newest bounded failure identity must survive"
    );
    assert!(
        values
            .iter()
            .any(|value| value["edited_file"] == "src/latest.py"),
        "newly appended failure identity must survive"
    );
    assert!(
        values.iter().all(|value| value["edited_file"] != oldest),
        "oldest failure must be evicted once the bounded signal is full"
    );
}

#[test]
fn oversized_must_keep_survivor_is_compacted_and_retained() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let pass_line = record_line_with_path(
        Some("sess-large-failure"),
        Some("src/clean.py"),
        Status::Passed,
        "clean",
    );
    let empty_failure = record_line_with_path(
        Some("sess-large-failure"),
        Some("src/violating.py"),
        Status::Failed,
        "",
    );
    let message_len =
        MAX_EVIDENCE_BYTES as usize - empty_failure.len() - pass_line.len().div_ceil(2);
    let large_failure = record_line_with_path(
        Some("sess-large-failure"),
        Some("src/violating.py"),
        Status::Failed,
        &"x".repeat(message_len),
    );
    let seed = format!("{large_failure}\n");
    assert!(seed.len() as u64 <= MAX_EVIDENCE_BYTES);
    assert!(seed.len() + pass_line.len() + 1 > MAX_EVIDENCE_BYTES as usize);
    std::fs::write(&path, seed).expect("large failure ledger writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "clean".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-large-failure"),
        Some("src/clean.py"),
        &result,
    )
    .expect("append after large failure must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("retained records remain valid JSON"))
        .collect();
    let retained = values
        .iter()
        .find(|value| value["edited_file"] == "src/violating.py")
        .expect("large failed identity remains retained");
    assert_eq!(retained["result"]["status"], "failed");
    assert_eq!(retained["truncated"], true);
    assert_eq!(
        values.last().expect("pass append survives")["edited_file"],
        "src/clean.py"
    );
}

#[test]
fn near_cap_current_failure_survives_small_append_with_identity() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let session_id = "s".repeat(4 * 1024 + 1);
    let session = Some(session_id.as_str());
    let failure_prefix = record_line_with_path(session, Some("src/failure.py"), Status::Failed, "");
    let filler = record_line(session, Status::Passed, "filler");
    let message_len = MAX_EVIDENCE_BYTES as usize - failure_prefix.len() - filler.len() - 1;
    let failure = record_line_with_path(
        session,
        Some("src/failure.py"),
        Status::Failed,
        &"x".repeat(message_len),
    );
    assert!(failure.len() as u64 <= MAX_EVIDENCE_BYTES);
    std::fs::write(&path, format!("{failure}\n")).expect("near-cap ledger writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "small append".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, session, Some("src/clean.py"), &result)
        .expect("small append must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("retained records remain valid JSON"))
        .collect();
    let retained = values
        .iter()
        .find(|value| value["result"]["status"] == "failed")
        .expect("current-session failure remains retained");
    assert_eq!(retained["session_id"], session_id);
    assert_eq!(retained["edited_file"], "src/failure.py");
    assert_eq!(retained["truncated"], true);
    assert_eq!(retained["result"]["rule_id"], "no-committed-secrets");
}

#[test]
fn rotation_bounds_total_record_count_and_marks_dropped_records() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let mut seed = String::new();
    for index in 0..MAX_EVIDENCE_RECORDS {
        seed.push_str(&record_line(
            Some("sess-record-cap"),
            Status::Passed,
            &format!("pass-{index}"),
        ));
        seed.push('\n');
    }
    std::fs::write(&path, seed).expect("record-cap ledger writable");
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "record-cap append".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-record-cap"),
        Some("src/app.py"),
        &result,
    )
    .expect("record-cap append must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    assert!(contents.lines().count() <= MAX_EVIDENCE_RECORDS);
    assert!(contents.lines().any(|line| {
        let value: Value = serde_json::from_str(line).expect("retained records remain valid JSON");
        value["truncated"] == true && value["session_id"] == "sess-record-cap"
    }));
}

#[test]
fn oversized_single_result_is_compacted_without_exceeding_the_cap() {
    let temp = TempDir::new();
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "x".repeat(MAX_EVIDENCE_BYTES as usize + 1),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-compact"),
        Some("src/app.py"),
        &result,
    )
    .expect("oversized result is compacted");

    let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    assert!(
        std::fs::metadata(&path).expect("ledger metadata").len() <= MAX_EVIDENCE_BYTES,
        "a single oversized result must not exceed the ledger cap"
    );
    let value: Value = serde_json::from_str(
        std::fs::read_to_string(path)
            .expect("ledger readable")
            .trim(),
    )
    .expect("compact record is valid JSON");
    assert_eq!(value["truncated"], true);
    assert_eq!(value["session_id"], "sess-compact");
    assert_eq!(value["edited_file"], "src/app.py");
    assert_eq!(value["result"]["rule_id"], "no-committed-secrets");
    assert_eq!(value["result"]["status"], "failed");
}
