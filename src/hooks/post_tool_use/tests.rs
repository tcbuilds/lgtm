use super::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::adapter::{EncodedResponse, HookRequest};
use serde_json::Value;

use super::evidence::{
    MAX_EVIDENCE_BYTES, MAX_EVIDENCE_RECORDS, MAX_MUST_KEEP_RECORDS, MAX_RECORDED_PATHS,
    append_evidence, compact_existing_record, is_must_keep_record, trim_records,
};
use super::input::{HookInput, ToolInput, edited_file, read_file};
use super::target::{resolve_read_path, resolve_target, unverified_target};

struct PanicAdapter;

impl HookAdapter for PanicAdapter {
    fn fail_open_on_error(&self) -> bool {
        true
    }

    fn parse_request(&self, _: HookEvent, _: &str) -> Result<HookRequest, String> {
        panic!("test adapter panic");
    }

    fn encode_response(&self, _: HookEvent, _: HookResponse) -> Result<EncodedResponse, String> {
        panic!("test adapter panic");
    }
}

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
fn pi_panic_returns_fail_open_signal_for_shim_evidence() {
    let temp = TempDir::new();
    std::fs::create_dir(temp.path.join(".git")).expect("git marker");
    let file = temp.path.join("App.tsx");
    std::fs::write(&file, "const value: any = input;\n").expect("fixture source");
    let payload = json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": file },
        "cwd": temp.path,
    });
    let serialized = payload.to_string();
    let mut input = serialized.as_bytes();
    let mut output = Vec::new();
    let code = run_with_adapter(&mut input, &mut output, &PanicAdapter);
    assert_eq!(code, ExitCode::from(1));
    assert!(output.is_empty());
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
            path: None,
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
        path: None,
    });
    assert_eq!(edited_file(&input), None, "a blank path is ignored");

    input.tool_name = Some("Read".to_string());
    input.tool_input = Some(ToolInput {
        file_path: None,
        path: Some("/a.py".to_string()),
    });
    assert_eq!(read_file(&input), Some("/a.py".to_string()));
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
fn present_empty_ledger_is_preserved_and_rejected() {
    let temp = TempDir::new();
    let path = temp
        .path
        .join(".lgtm")
        .join("evidence")
        .join("current-task.results.jsonl");
    std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
    std::fs::write(&path, b"").expect("empty ledger writable");

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
    let outcome = append_evidence(
        &temp.path,
        Some("empty-session"),
        Some("src/app.py"),
        &result,
    );
    assert!(outcome.is_err(), "a present empty ledger must fail closed");
    assert_eq!(
        std::fs::read(&path).expect("empty ledger remains readable"),
        b""
    );
}

#[test]
fn unterminated_existing_jsonl_is_delimited_before_append() {
    let temp = TempDir::new();
    let path = temp
        .path
        .join(".lgtm")
        .join("evidence")
        .join("current-task.results.jsonl");
    std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
    let first = record_line(Some("first-session"), Status::Passed, "first");
    std::fs::write(&path, first.as_bytes()).expect("unterminated ledger writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "second".to_string(),
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
        Some("second-session"),
        Some("src/app.py"),
        &result,
    )
    .expect("append must delimit the existing JSONL record");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    let values: Vec<Value> = contents
        .lines()
        .map(|line| {
            serde_json::from_str(line).expect("each record remains independently valid JSON")
        })
        .collect();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0]["session_id"], "first-session");
    assert_eq!(values[1]["session_id"], "second-session");
}

#[test]
fn unterminated_ledger_delimiter_byte_forces_rotation_at_cap() {
    let temp = TempDir::new();
    let path = temp
        .path
        .join(".lgtm")
        .join("evidence")
        .join("current-task.results.jsonl");
    std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");

    let session = "delimiter-boundary";
    let incoming_line = format!(
        "{}\n",
        record_line_with_path(
            Some(session),
            Some("src/new.py"),
            Status::Passed,
            "incoming"
        )
    );
    let target = MAX_EVIDENCE_BYTES as usize - incoming_line.len();
    let prefix = record_line_with_path(Some("old-session"), Some("src/old.py"), Status::Passed, "");
    assert!(target > prefix.len());
    let existing = record_line_with_path(
        Some("old-session"),
        Some("src/old.py"),
        Status::Passed,
        &"x".repeat(target - prefix.len()),
    );
    assert_eq!(existing.len(), target);
    std::fs::write(&path, existing.as_bytes()).expect("unterminated ledger writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "incoming".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(&temp.path, Some(session), Some("src/new.py"), &result)
        .expect("the delimiter byte must trigger bounded rotation");

    let contents = std::fs::read_to_string(&path).expect("rotated ledger readable");
    assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("rotated JSONL remains valid"))
        .collect();
    assert_eq!(
        values.last().expect("incoming record survives")["session_id"],
        session
    );
}

#[test]
fn oversized_ledger_rotates_to_stay_bounded() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");

    let filler_line = format!(
        "{}\n",
        record_line(Some("filler"), Status::Passed, &"x".repeat(1024))
    );
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
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("every rotated line is valid JSONL"))
        .collect();
    assert!(
        values
            .iter()
            .any(|value| is_truncation_marker(value, "sess-2")),
        "dropping malformed filler records emits a dedicated loss marker"
    );
    let value = values.last().expect("a record survives");
    assert_eq!(value["session_id"], json!("sess-2"), "newest record kept");
}

#[test]
fn evidence_read_bound_accepts_exact_valid_ledger_and_rejects_one_byte_over() {
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "bounded append".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let exact_bound = (MAX_EVIDENCE_BYTES as usize) * 2;
    for (label, target, succeeds) in [
        ("read-bound-exact", exact_bound, true),
        ("read-bound-over", exact_bound + 1, false),
    ] {
        let temp = TempDir::new();
        let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("evidence directory");
        let empty = format!(
            "{}\n",
            record_line_with_path(
                Some("read-bound-session"),
                Some("src/old.py"),
                Status::Passed,
                "",
            )
        );
        let seed = format!(
            "{}\n",
            record_line_with_path(
                Some("read-bound-session"),
                Some("src/old.py"),
                Status::Passed,
                &"x".repeat(target - empty.len()),
            )
        );
        assert_eq!(seed.len(), target, "{label} fixture reaches its byte bound");
        assert!(
            serde_json::from_str::<Value>(&seed).is_ok(),
            "{label} fixture is syntactically valid JSON"
        );
        std::fs::write(&path, &seed).expect("read-bound ledger writable");

        let outcome = append_evidence(
            &temp.path,
            Some("read-bound-session"),
            Some("src/new.py"),
            &result,
        );
        if succeeds {
            outcome.expect("exact readable bound must rotate and append");
            let contents = std::fs::read_to_string(&path).expect("rotated ledger readable");
            assert!(contents.len() as u64 <= MAX_EVIDENCE_BYTES);
            assert!(
                contents
                    .lines()
                    .all(|line| serde_json::from_str::<Value>(line).is_ok()),
                "exact-bound rotation must preserve valid JSONL"
            );
        } else {
            assert!(outcome.is_err(), "one byte over the read bound must reject");
            assert_eq!(
                std::fs::read_to_string(&path).expect("over-bound ledger remains readable"),
                seed,
                "one-byte-over rejection must preserve existing bytes"
            );
        }
    }
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
fn resolve_read_path_normalizes_absolute_and_nested_paths() {
    let temp = TempDir::new();
    let workspace = temp.path.join("workspace");
    let source = temp.path.join("src/app.py");
    std::fs::create_dir_all(&workspace).expect("workspace creatable");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source parent");
    std::fs::write(&source, "value = 1\n").expect("source writable");
    let root = temp.path.to_string_lossy().into_owned();
    let nested = workspace.to_string_lossy().into_owned();
    let absolute = source.to_string_lossy().into_owned();

    assert_eq!(
        resolve_read_path(&temp.path, Some(&root), &absolute),
        Some("src/app.py".to_string())
    );
    assert_eq!(
        resolve_read_path(&temp.path, Some(&nested), "../src/app.py"),
        Some("src/app.py".to_string())
    );
    assert_eq!(
        resolve_read_path(&temp.path, Some(&nested), "../../outside.py"),
        None
    );
}

#[cfg(unix)]
#[test]
fn resolve_read_path_rejects_symlink_escape() {
    let temp = TempDir::new();
    let outside = TempDir::new();
    let outside_file = outside.path.join("outside.py");
    std::fs::write(&outside_file, "value = 1\n").expect("outside source writable");
    std::os::unix::fs::symlink(&outside_file, temp.path.join("link.py"))
        .expect("symlink creatable");

    assert_eq!(
        resolve_read_path(
            &temp.path,
            Some(temp.path.to_str().expect("UTF-8 root")),
            "link.py"
        ),
        None
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

fn is_truncation_marker(value: &Value, session_id: &str) -> bool {
    value["session_id"] == session_id
        && value["edited_file"].is_null()
        && value["truncated"] == true
        && value.get("persistence_failed").is_none()
        && value["result"]["rule_id"] == "current-task-evidence"
        && value["result"]["status"] == "unverified"
        && value["result"]["severity"] == "error"
        && value["result"]["message"]
            == "Older current-task evidence records were dropped at the bounded retention limit."
        && value["result"]["locations"] == json!([])
        && value["result"]["remediation"].is_null()
        && value["result"]["evidence"]["check"] == "evidence.current-task"
        && value["result"]["evidence"]["tool_version"].is_null()
        && value["result"]["evidence"]["finding_descriptions"] == json!([])
}

fn persistence_marker_value() -> Value {
    json!({
        "session_id": null,
        "edited_file": null,
        "result": {
            "rule_id": "current-task-evidence",
            "status": "unverified",
            "severity": "error",
            "message": "Current-task evidence could not be persisted within the bounded ledger limit.",
            "locations": [],
            "remediation": null,
            "evidence": {
                "check": "evidence.current-task",
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true,
        "persistence_failed": true
    })
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
    let kept = trim_records(&existing, session, failed.len() + 1_024).expect("trim succeeds");

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
    let kept = trim_records(&existing, session, per_record * 3 + 1).expect("trim succeeds");

    let survivors: Vec<_> = kept
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("survivor is valid JSON"))
        .filter_map(|value| value["result"]["message"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        survivors,
        [
            "Older current-task evidence records were dropped at the bounded retention limit.",
            "clean 7",
        ],
        "the newest maximal suffix and dedicated marker must survive"
    );
}

#[test]
fn trim_records_refuses_to_replace_tight_persistence_marker_with_retention_marker() {
    let persistence = persistence_marker_value();
    let persistence_line = format!("{persistence}\n");
    let retention_line = format!(
        "{}\n",
        json!({
            "session_id": "tight-session",
            "edited_file": null,
            "result": {
                "rule_id": "current-task-evidence",
                "status": "unverified",
                "severity": "error",
                "message": "Older current-task evidence records were dropped at the bounded retention limit.",
                "locations": [],
                "remediation": null,
                "evidence": {
                    "check": "evidence.current-task",
                    "tool_version": null,
                    "finding_descriptions": []
                }
            },
            "truncated": true
        })
    );
    assert!(persistence_line.len() > retention_line.len());

    let existing = format!(
        "{persistence_line}{}",
        record_line(None, Status::Passed, "clean")
    );
    let outcome = trim_records(&existing, Some("tight-session"), retention_line.len());
    assert!(
        outcome.is_err(),
        "rotation must fail rather than silently replacing a tight persistence marker with a generic retention marker"
    );
}

#[test]
fn trim_records_bounds_marker_candidates_and_keeps_older_canonical_marker() {
    let expected = persistence_marker_value();
    let persistence_line = format!("{expected}\n");
    // These lines carry both cheap marker signatures but cannot pass the typed
    // marker validation. More than the production candidate budget follows the
    // valid marker, so an unbounded JSON search would do needless work here.
    let marker_like = r#"{"message":"Current-task evidence could not be persisted within the bounded ledger limit.","persistence_failed":true}"#;
    let mut existing = persistence_line;
    for _ in 0..MAX_EVIDENCE_RECORDS {
        existing.push_str(marker_like);
        existing.push('\n');
    }

    let kept = trim_records(
        &existing,
        Some("later-session"),
        MAX_EVIDENCE_BYTES as usize,
    )
    .expect("bounded marker search must retain the canonical marker");
    assert!(
        kept.lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .is_some_and(|value| value == expected)
        }),
        "an older valid persistence marker must survive marker-like noise"
    );
}

#[test]
fn trim_records_rejects_ambiguous_noncanonical_marker_search() {
    let expected = persistence_marker_value();
    let noncanonical = format!(" {expected}\n");
    let marker_like = r#"{"message":"Current-task evidence could not be persisted within the bounded ledger limit.","persistence_failed":true}"#;
    let mut existing = noncanonical;
    for _ in 0..MAX_EVIDENCE_RECORDS {
        existing.push_str(marker_like);
        existing.push('\n');
    }

    let outcome = trim_records(
        &existing,
        Some("later-session"),
        MAX_EVIDENCE_BYTES as usize,
    );
    assert!(
        outcome.is_err(),
        "ambiguous noncanonical marker candidates must fail closed rather than downgrade the loss reason"
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
    let boundary_message = "boundary".to_string() + &"p".repeat(400);
    let pass_line = format!(
        "{}\n",
        record_line_with_path(
            session,
            Some("src/app.py"),
            Status::Passed,
            &boundary_message
        )
    );
    let append_message = boundary_message.clone() + &"f".repeat(256);
    let failed_line = format!(
        "{}\n",
        record_line_with_path(session, Some("src/app.py"), Status::Failed, &append_message)
    );
    let cap = MAX_EVIDENCE_BYTES as usize;
    let mut seed = String::new();
    while seed.len() + failed_line.len() <= cap {
        seed.push_str(&pass_line);
    }
    assert!(
        seed.len() <= cap,
        "under-cap seed must fit before the append"
    );
    assert!(
        seed.len() + failed_line.len() > cap,
        "the real append must cross the cap"
    );
    assert!(
        seed.lines().count() < MAX_EVIDENCE_RECORDS,
        "byte-pressure seed must remain below the record cap"
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
        message: append_message,
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
    assert!(contents.lines().any(|line| {
        let value: Value = serde_json::from_str(line).expect("marker remains valid JSON");
        is_truncation_marker(&value, "sess-boundary")
    }));
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
fn fewer_than_record_cap_must_keep_eviction_emits_session_marker() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let session = Some("sess-must-keep-eviction");
    let mut seed = String::new();
    for index in 0..=MAX_MUST_KEEP_RECORDS {
        seed.push_str(&record_line_with_path(
            session,
            Some(&format!("src/eviction-{index}.py")),
            Status::Failed,
            &"x".repeat(42_000),
        ));
        seed.push('\n');
    }
    assert!(seed.len() as u64 > MAX_EVIDENCE_BYTES);
    assert!(seed.lines().count() < MAX_EVIDENCE_RECORDS);
    std::fs::write(&path, &seed).expect("seed writable");

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
    append_evidence(&temp.path, session, Some("src/clean.py"), &result)
        .expect("append must succeed");

    let contents = std::fs::read_to_string(&path).expect("ledger readable");
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("retained record is valid JSON"))
        .collect();
    assert!(
        values
            .iter()
            .any(|value| is_truncation_marker(value, "sess-must-keep-eviction")),
        "must-keep eviction emits a dedicated loss marker"
    );
    assert!(
        values
            .iter()
            .any(|value| value["edited_file"] == "src/eviction-128.py"),
        "the newest actionable survivor retains path identity"
    );
}

#[test]
fn marker_fit_failure_preserves_existing_ledger_bytes() {
    let temp = TempDir::new();
    let dir = temp.path.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).expect("dir creatable");
    let path = dir.join("current-task.results.jsonl");
    let old = record_line_with_path(
        Some("old-session"),
        Some("src/old.py"),
        Status::Passed,
        &"o".repeat(MAX_EVIDENCE_BYTES as usize - 1_000),
    ) + "\n";
    assert!(old.len() as u64 <= MAX_EVIDENCE_BYTES);
    std::fs::write(&path, &old).expect("old ledger writable");

    let session_id = "s".repeat(4_000_000);
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "new failure".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let outcome = append_evidence(&temp.path, Some(&session_id), Some("src/new.py"), &result);
    assert!(
        outcome.is_err(),
        "an unfit marker must fail before replacement"
    );
    assert_eq!(
        std::fs::read(&path).expect("ledger remains readable"),
        old.into_bytes()
    );
}

#[test]
fn present_invalid_ledgers_are_preserved_and_rejected() {
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "new failure".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let over_bound = vec![b'x'; (MAX_EVIDENCE_BYTES as usize * 2) + 1];
    let schema_invalid = serde_json::json!({
        "session_id": "schema-invalid",
        "edited_file": "src/old.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "failed",
            "severity": "unknown",
            "message": "schema-invalid",
            "locations": [],
            "evidence": {"check": "gitleaks.detect"}
        }
    })
    .to_string()
        + "\n";
    let empty_session = serde_json::json!({
        "session_id": "",
        "edited_file": "src/old.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "failed",
            "severity": "error",
            "message": "empty session",
            "locations": [],
            "evidence": {"check": "gitleaks.detect"}
        }
    })
    .to_string()
        + "\n";
    let retention_with_false_persistence = serde_json::json!({
        "session_id": "retention-session",
        "edited_file": null,
        "result": {
            "rule_id": "current-task-evidence",
            "status": "unverified",
            "severity": "error",
            "message": "Older current-task evidence records were dropped at the bounded retention limit.",
            "locations": [],
            "remediation": null,
            "evidence": {
                "check": "evidence.current-task",
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true,
        "persistence_failed": false
    })
    .to_string()
        + "\n";
    for (label, old) in [
        ("invalid-utf8", vec![0xff, 0xfe]),
        ("malformed-json", b"{not-json}\n".to_vec()),
        ("schema-invalid", schema_invalid.into_bytes()),
        ("empty-session", empty_session.into_bytes()),
        (
            "retention-false-persistence",
            retention_with_false_persistence.into_bytes(),
        ),
        ("over-bound", over_bound),
    ] {
        let temp = TempDir::new();
        let path = temp
            .path
            .join(".lgtm")
            .join("evidence")
            .join("current-task.results.jsonl");
        std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
        std::fs::write(&path, &old).expect("invalid ledger writable");

        let outcome = append_evidence(&temp.path, Some(label), Some("src/new.py"), &result);
        assert!(outcome.is_err(), "{label} ledger must reject append");
        assert_eq!(std::fs::read(&path).expect("ledger remains readable"), old);
    }
}

#[test]
fn present_over_limit_locations_are_preserved_and_rejected() {
    let temp = TempDir::new();
    let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
    let locations: Vec<_> = (0..=MAX_RECORDED_PATHS)
        .map(|index| json!({"file": format!("src/existing-{index}.py"), "line": 1}))
        .collect();
    let old = format!(
        "{}\n",
        json!({
            "session_id": "over-limit-session",
            "edited_file": "src/existing.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "failed",
                "severity": "error",
                "message": "finding",
                "locations": locations,
                "evidence": {"check": "gitleaks.detect"}
            }
        })
    )
    .into_bytes();
    std::fs::write(&path, &old).expect("over-limit ledger writable");

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
    let outcome = append_evidence(
        &temp.path,
        Some("over-limit-session"),
        Some("src/new.py"),
        &result,
    );
    assert!(
        outcome.is_err(),
        "over-limit stored locations must fail closed"
    );
    assert_eq!(
        std::fs::read(&path).expect("over-limit ledger remains readable"),
        old
    );
}

#[test]
fn existing_exact_location_bound_is_appendable_and_preserves_identities() {
    let temp = TempDir::new();
    let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
    let locations: Vec<_> = (0..MAX_RECORDED_PATHS)
        .map(|index| json!({"file": format!("src/existing-{index}.py"), "line": 1}))
        .collect();
    let existing = json!({
        "session_id": "exact-location-session",
        "edited_file": "src/existing.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "passed",
            "severity": "error",
            "message": "clean",
            "locations": locations,
            "evidence": {"check": "gitleaks.detect"}
        }
    });
    std::fs::write(&path, format!("{existing}\n")).expect("exact-bound ledger writable");

    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "incoming".to_string(),
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
        Some("exact-location-session"),
        Some("src/new.py"),
        &result,
    )
    .expect("exact location bound must remain appendable");

    let values: Vec<Value> = std::fs::read_to_string(&path)
        .expect("exact-bound ledger readable")
        .lines()
        .map(|line| serde_json::from_str(line).expect("exact-bound record remains valid JSON"))
        .collect();
    assert_eq!(values.len(), 2);
    let locations = values[0]["result"]["locations"]
        .as_array()
        .expect("stored locations array");
    assert_eq!(locations.len(), MAX_RECORDED_PATHS);
    for (index, location) in locations.iter().enumerate() {
        assert_eq!(location["file"], json!(format!("src/existing-{index}.py")));
        assert_eq!(location["line"], json!(1));
    }
    assert_eq!(values[1]["edited_file"], json!("src/new.py"));
}

#[test]
fn persistence_marker_metadata_permutations_are_rejected_by_rotation() {
    let incoming = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Passed,
        severity: crate::policy::Severity::Error,
        message: "new record".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    type ValueMutation = fn(&mut Value);
    let cases: [(&str, ValueMutation); 7] = [
        ("missing-truncated", |value| {
            value
                .as_object_mut()
                .expect("marker object")
                .remove("truncated");
        }),
        ("false-truncated", |value| value["truncated"] = json!(false)),
        ("missing-persistence-failed", |value| {
            value
                .as_object_mut()
                .expect("marker object")
                .remove("persistence_failed");
        }),
        ("false-persistence-failed", |value| {
            value["persistence_failed"] = json!(false)
        }),
        ("non-null-session", |value| {
            value["session_id"] = json!("session")
        }),
        ("wrong-message", |value| {
            value["result"]["message"] = json!("not the persistence marker")
        }),
        ("ordinary-record-with-persistence-failed", |value| {
            value["session_id"] = json!("ordinary-session");
            value["edited_file"] = json!("src/ordinary.py");
            value["result"]["rule_id"] = json!("no-committed-secrets");
            value["result"]["status"] = json!("failed");
            value["result"]["message"] = json!("finding");
            value
                .as_object_mut()
                .expect("ordinary record object")
                .remove("truncated");
        }),
    ];

    for (label, mutate) in cases {
        let mut record = persistence_marker_value();
        mutate(&mut record);
        let old = format!("{record}\n").into_bytes();
        let temp = TempDir::new();
        let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("ledger directory");
        std::fs::write(&path, &old).expect("invalid marker writable");

        let outcome = append_evidence(&temp.path, Some(label), Some("src/new.py"), &incoming);
        assert!(outcome.is_err(), "{label} marker must be schema-invalid");
        assert_eq!(
            std::fs::read(&path).expect("invalid marker remains readable"),
            old,
            "{label} rotation must preserve invalid ledger bytes"
        );
    }
}

#[test]
fn irreducibly_oversized_record_persists_global_marker_for_stop() {
    let session_id = "s".repeat(MAX_EVIDENCE_BYTES as usize + 1);
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "small".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let temp = TempDir::new();
    append_evidence(&temp.path, Some(&session_id), Some("src/new.py"), &result)
        .expect("oversized input must persist a bounded fallback marker");

    let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    let value: Value = serde_json::from_str(
        std::fs::read_to_string(&path)
            .expect("fallback marker ledger readable")
            .trim(),
    )
    .expect("fallback marker is valid JSON");
    assert!(value["session_id"].is_null());
    assert!(value["edited_file"].is_null());
    assert_eq!(value["truncated"], true);
    assert_eq!(value["persistence_failed"], true);
    assert_eq!(value["result"]["rule_id"], "current-task-evidence");
    assert_eq!(value["result"]["status"], "unverified");
    assert_eq!(value["result"]["severity"], "error");
    assert_eq!(
        value["result"]["message"],
        "Current-task evidence could not be persisted within the bounded ledger limit."
    );
    assert_eq!(value["result"]["locations"], json!([]));
    assert!(value["result"]["remediation"].is_null());
    assert_eq!(
        value["result"]["evidence"]["check"],
        "evidence.current-task"
    );
    assert!(value["result"]["evidence"]["tool_version"].is_null());
    assert_eq!(
        value["result"]["evidence"]["finding_descriptions"],
        json!([])
    );

    let payload = json!({
        "cwd": &temp.path,
        "session_id": "normal-session",
    })
    .to_string();
    let mut input = payload.as_bytes();
    let mut output = Vec::new();
    let code = crate::hooks::stop::run(&mut input, &mut output);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let output = String::from_utf8(output).expect("Stop output is UTF-8");
    assert!(
        output.contains("UNVERIFIED current-task-evidence"),
        "{output}"
    );
    assert!(
        output.contains(
            "current-task evidence could not be persisted within the bounded ledger limit; repair or regenerate evidence"
        ),
        "{output}"
    );
    assert!(output.contains("lgtm: action required"), "{output}");
    assert!(!output.contains("lgtm: passed"), "{output}");
}

#[test]
fn compacted_persistence_marker_keeps_its_marker_kind() {
    let source = json!({
        "session_id": null,
        "edited_file": null,
        "result": {
            "rule_id": "current-task-evidence",
            "status": "unverified",
            "severity": "error",
            "message": "Current-task evidence could not be persisted within the bounded ledger limit.",
            "locations": [],
            "remediation": null,
            "evidence": {
                "check": "evidence.current-task",
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true,
        "persistence_failed": true
    })
    .to_string();
    let compacted = compact_existing_record(&source).expect("persistence marker compacts");
    let value: Value = serde_json::from_str(&compacted).expect("compacted marker is valid JSON");
    assert_eq!(value["persistence_failed"], true);
    assert_eq!(
        value["result"]["message"],
        "Current-task evidence could not be persisted within the bounded ledger limit."
    );

    #[derive(serde::Deserialize)]
    struct CurrentTaskRecord {
        session_id: Option<String>,
        #[serde(default)]
        edited_file: Option<String>,
        result: EnforcementResult,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        persistence_failed: bool,
    }
    let typed: CurrentTaskRecord = serde_json::from_str(&compacted)
        .expect("compacted persistence marker remains an EditRecord");
    assert!(typed.session_id.is_none());
    assert!(typed.edited_file.is_none());
    assert!(typed.truncated);
    assert!(typed.persistence_failed);
    assert_eq!(typed.result.status, Status::Unverified);

    let retention_source = json!({
        "session_id": "retention-session",
        "edited_file": null,
        "result": {
            "rule_id": "current-task-evidence",
            "status": "unverified",
            "severity": "error",
            "message": "Older current-task evidence records were dropped at the bounded retention limit.",
            "locations": [],
            "remediation": null,
            "evidence": {
                "check": "evidence.current-task",
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true
    })
    .to_string();
    let retention = compact_existing_record(&retention_source).expect("retention marker compacts");
    let retention_typed: CurrentTaskRecord =
        serde_json::from_str(&retention).expect("compacted retention marker remains an EditRecord");
    assert!(retention_typed.truncated);
    assert!(!retention_typed.persistence_failed);
    assert_eq!(
        retention_typed.result.message,
        "Older current-task evidence records were dropped at the bounded retention limit."
    );
}

#[test]
fn compacted_optional_location_line_remains_schema_valid() {
    let source = json!({
        "session_id": "location-session",
        "edited_file": "src/app.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "failed",
            "severity": "error",
            "message": "finding",
            "locations": [{"file": "src/app.py"}],
            "evidence": {"check": "gitleaks.detect"}
        }
    })
    .to_string();
    let compacted = compact_existing_record(&source).expect("record compacts");
    let value: Value = serde_json::from_str(&compacted).expect("compacted JSON is valid");
    let location = &value["result"]["locations"][0];
    assert_eq!(location["file"], "src/app.py");
    assert!(
        !location
            .as_object()
            .expect("location object")
            .contains_key("line"),
        "an absent optional line must stay absent, not become a schema-invalid null"
    );
}

#[test]
fn explicit_null_location_line_is_appendable_and_stop_usable() {
    let temp = TempDir::new();
    let source = temp.path.join("src/app.py");
    std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
    std::fs::write(&source, "value = 1\n").expect("source fixture");
    let ledger = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    std::fs::create_dir_all(ledger.parent().expect("ledger parent")).expect("evidence directory");

    // This is the compacted shape emitted by the baseline candidate: an
    // optional location line is explicit JSON null rather than absent.
    let compacted = json!({
        "session_id": "null-line-session",
        "edited_file": "src/app.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "failed",
            "severity": "error",
            "message": "Evidence record exceeded the ledger bound; details were truncated.",
            "locations": [{"file": "src/app.py", "line": null}],
            "remediation": null,
            "evidence": {
                "check": "gitleaks.detect",
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true
    })
    .to_string();
    std::fs::write(&ledger, format!("{compacted}\n")).expect("compacted ledger writable");

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
        Some("null-line-session"),
        Some("src/app.py"),
        &result,
    )
    .expect("explicit null line must remain appendable");

    let contents = std::fs::read_to_string(&ledger).expect("ledger readable");
    let first: Value =
        serde_json::from_str(contents.lines().next().expect("compacted record survives"))
            .expect("compacted record remains JSON");
    assert!(first["result"]["locations"][0]["line"].is_null());

    let payload = json!({
        "cwd": &temp.path,
        "session_id": "null-line-session",
    })
    .to_string();
    let mut input = payload.as_bytes();
    let mut output = Vec::new();
    let code = crate::hooks::stop::run(&mut input, &mut output);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let output = String::from_utf8(output).expect("Stop output is UTF-8");
    assert!(
        output.contains("current-task evidence record details were truncated"),
        "{output}"
    );
    assert!(output.contains("lgtm: action required"), "{output}");
    assert!(
        !output.contains("current-task evidence contains invalid record schema"),
        "{output}"
    );
}

#[test]
fn evidence_rotation_rejects_non_null_invalid_location_lines() {
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
    for (label, line) in [
        ("zero", json!(0)),
        ("negative", json!(-1)),
        ("fractional", json!(1.5)),
        ("string", json!("1")),
        ("boolean", json!(true)),
        ("object", json!({})),
        ("array", json!([])),
    ] {
        let temp = TempDir::new();
        let path = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
        std::fs::create_dir_all(path.parent().expect("ledger parent")).expect("evidence directory");
        let old = json!({
            "session_id": "invalid-line-session",
            "edited_file": "src/app.py",
            "result": {
                "rule_id": "no-committed-secrets",
                "status": "passed",
                "severity": "error",
                "message": "clean",
                "locations": [{"file": "src/app.py", "line": line}],
                "evidence": {"check": "gitleaks.detect"}
            }
        })
        .to_string()
            + "\n";
        std::fs::write(&path, &old).expect("invalid-line ledger writable");

        let outcome = append_evidence(
            &temp.path,
            Some("invalid-line-session"),
            Some("src/app.py"),
            &result,
        );
        assert!(outcome.is_err(), "{label} line must reject during rotation");
        assert_eq!(
            std::fs::read_to_string(&path).expect("invalid-line ledger remains readable"),
            old,
            "{label} rejection must preserve existing bytes"
        );
    }
}

#[test]
fn compaction_rejects_schema_invalid_records() {
    let source = json!({
        "session_id": "invalid-session",
        "edited_file": "src/app.py",
        "result": {
            "rule_id": "no-committed-secrets",
            "status": "failed",
            "severity": "error",
            "message": "missing locations",
            "evidence": {"check": "gitleaks.detect"}
        }
    })
    .to_string();
    assert!(
        compact_existing_record(&source).is_none(),
        "schema-invalid records must never be compacted into evidence"
    );
}

#[test]
fn persistence_failure_marker_survives_later_rotation_and_stop_reports_distinct_reason() {
    let oversized_session = "s".repeat(MAX_EVIDENCE_BYTES as usize + 1);
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "small".to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    let temp = TempDir::new();
    append_evidence(
        &temp.path,
        Some(&oversized_session),
        Some("src/too-large.py"),
        &result,
    )
    .expect("oversized input persists a fallback marker");

    let ledger = temp.path.join(".lgtm/evidence/current-task.results.jsonl");
    let marker = std::fs::read_to_string(&ledger).expect("fallback marker readable");
    let mut contents = marker.clone();
    for _ in 0..(MAX_EVIDENCE_RECORDS - MAX_MUST_KEEP_RECORDS - 1) {
        contents.push_str(&record_line(Some("later-session"), Status::Passed, "clean"));
        contents.push('\n');
    }
    for _ in 0..(MAX_MUST_KEEP_RECORDS + 1) {
        contents.push_str(&record_line(
            Some("later-session"),
            Status::Failed,
            "failure",
        ));
        contents.push('\n');
    }
    std::fs::write(&ledger, contents).expect("rotation fixture writable");

    append_evidence(
        &temp.path,
        Some("later-session"),
        Some("src/new.py"),
        &result,
    )
    .expect("later append rotates the bounded ledger");
    let persisted = std::fs::read_to_string(&ledger).expect("rotated ledger readable");
    assert!(
        persisted.lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .is_some_and(|value| value["persistence_failed"] == true)
        }),
        "global persistence marker must survive later rotation"
    );

    let payload = json!({
        "cwd": &temp.path,
        "session_id": "later-session",
    })
    .to_string();
    let mut input = payload.as_bytes();
    let mut output = Vec::new();
    let code = crate::hooks::stop::run(&mut input, &mut output);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    let output = String::from_utf8(output).expect("Stop output is UTF-8");
    assert!(
        output.contains(
            "current-task evidence could not be persisted within the bounded ledger limit; repair or regenerate evidence"
        ),
        "{output}"
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
    assert!(
        !is_truncation_marker(retained, "sess-large-failure"),
        "a compacted ordinary failure must not become the loss marker"
    );
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
    let values: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("retained record is valid JSON"))
        .collect();
    assert!(
        values
            .iter()
            .any(|value| is_truncation_marker(value, "sess-record-cap")),
        "record-cap eviction emits a dedicated loss marker"
    );
}

#[test]
fn producer_compacts_result_locations_above_the_path_bound() {
    let temp = TempDir::new();
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "finding".to_string(),
        locations: (0..513)
            .map(|index| crate::checks::Location {
                file: format!("src/generated-{index}.py"),
                line: Some(1),
            })
            .collect(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-path-bound"),
        Some("src/app.py"),
        &result,
    )
    .expect("path-heavy result is compacted");

    let value: Value = serde_json::from_str(
        std::fs::read_to_string(temp.path.join(".lgtm/evidence/current-task.results.jsonl"))
            .expect("ledger readable")
            .trim(),
    )
    .expect("compacted record is valid JSON");
    assert_eq!(value["session_id"], "sess-path-bound");
    assert_eq!(value["edited_file"], "src/app.py");
    assert_eq!(value["result"]["rule_id"], "no-committed-secrets");
    assert_eq!(value["result"]["status"], "failed");
    assert_eq!(value["result"]["locations"], json!([]));
    assert_eq!(value["truncated"], true);
}

#[test]
fn producer_preserves_exact_location_bound_without_truncation() {
    let temp = TempDir::new();
    let result = EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Failed,
        severity: crate::policy::Severity::Error,
        message: "finding".to_string(),
        locations: (0..MAX_RECORDED_PATHS)
            .map(|index| crate::checks::Location {
                file: format!("src/exact-{index}.py"),
                line: Some(1),
            })
            .collect(),
        remediation: None,
        evidence: crate::checks::ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    };
    append_evidence(
        &temp.path,
        Some("sess-path-exact"),
        Some("src/app.py"),
        &result,
    )
    .expect("exact path-bound result persists");

    let value: Value = serde_json::from_str(
        std::fs::read_to_string(temp.path.join(".lgtm/evidence/current-task.results.jsonl"))
            .expect("ledger readable")
            .trim(),
    )
    .expect("exact-bound record is valid JSON");
    assert_ne!(value["truncated"], true);
    assert_eq!(
        value["result"]["locations"]
            .as_array()
            .expect("locations array")
            .len(),
        MAX_RECORDED_PATHS
    );
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
