//! PostToolUse hook: run fast checks on the file an edit just touched.
//!
//! Claude Code invokes this after every tool call. This handler reads the
//! PostToolUse payload from stdin, extracts the file path a filesystem edit
//! touched (Edit / Write / MultiEdit), runs the gitleaks secret scan on it, and
//! decides what to tell the agent:
//!
//! - A secret finding (`failed`) emits the PostToolUse block envelope
//!   `{"decision":"block","reason":"…"}` on stdout so Claude sees the precise
//!   repair text and cannot proceed until it is fixed.
//! - A clean scan (`passed`) emits nothing and exits 0.
//! - An `unverified` result (gitleaks absent, timed out, or crashed) never
//!   blocks — a missing tool must not wedge a session (idea.md missing-tool
//!   behavior) — so it exits 0 with a one-line stderr note.
//! - Any non-filesystem tool is ignored: exit 0 silently.
//!
//! Every result is appended to the evidence ledger for the future Stop gate.
//!
//! Fail-safe is non-negotiable (idea.md §Design Constraints): any internal error
//! — malformed stdin, an unreadable cwd, a check crash — exits 0 with a
//! diagnostic on stderr and never blocks. A broken harness must never wedge an
//! agent session.

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::json;

use crate::checks::gitleaks;
use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

/// The maximum number of stdin bytes the hook reads. A PostToolUse payload is a
/// small JSON object; capping the read protects the hook from an unbounded or
/// hostile stdin. Anything past the cap is treated as malformed input on the
/// fail-safe path. Shares the SessionStart bound so the two hooks are consistent.
const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;

/// The tool names whose `tool_input.file_path` names a file a filesystem edit
/// touched. Any other tool is ignored — this hook only runs fast checks on
/// created or modified files.
const EDIT_TOOLS: [&str; 3] = ["Edit", "Write", "MultiEdit"];

/// The maximum size, in bytes, the evidence JSONL may reach before it is
/// truncated. A bounded ledger cannot grow without limit across a long session;
/// at or past this the oldest records are dropped to fit (see [`append_evidence`]).
const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;

/// The parsed subset of a Claude Code PostToolUse hook payload.
///
/// Parsing is lenient: unknown fields are ignored and every field is optional,
/// so a future Claude Code version adding or dropping keys does not break the
/// hook. Only the fields this handler acts on are modeled.
#[derive(Debug, Default, Deserialize)]
struct HookInput {
    /// The session that fired the hook; stored with each evidence record so the
    /// Stop gate can scope results to a session.
    #[serde(default)]
    session_id: Option<String>,
    /// The working directory Claude Code launched in; the repo root (and the
    /// evidence directory under it) is resolved from it.
    #[serde(default)]
    cwd: Option<String>,
    /// The tool that was called, e.g. `Edit`. Only [`EDIT_TOOLS`] are acted on.
    #[serde(default)]
    tool_name: Option<String>,
    /// The tool's input payload; `file_path` names the touched file for an edit.
    #[serde(default)]
    tool_input: Option<ToolInput>,
}

/// The subset of a tool's input the hook reads.
#[derive(Debug, Default, Deserialize)]
struct ToolInput {
    /// The file an Edit / Write / MultiEdit targeted. Absent for tools that do
    /// not touch a single file, which the hook ignores.
    #[serde(default)]
    file_path: Option<String>,
}

/// Handle a PostToolUse invocation, reading the payload from `input` and writing
/// any block decision to `output`.
///
/// Returns [`ExitCode::SUCCESS`] in every case. A secret finding writes the
/// block envelope to `output`; every other outcome — clean scan, unverified,
/// ignored tool, or any fail-safe path — writes nothing to `output`. The exit
/// code is always success: the block decision travels in the stdout JSON, not
/// the exit code, and the hook must never wedge a session by exiting non-zero.
pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    // Fail-safe totality: any panic in the handler is caught here and turned into
    // a diagnostic plus a success exit, so an unexpected panic (a poisoned lock, a
    // slicing bug, an allocation failure) can never crash the hook and wedge the
    // agent session. The unwind-safety assertion is sound because on a caught
    // panic nothing observable is left half-updated: `output` may have a partial
    // write, but the block envelope is line-delimited and a truncated line is
    // simply ignored by the consumer, and no shared in-process state is mutated.
    match catch_unwind(AssertUnwindSafe(|| run_inner(input, output))) {
        Ok(code) => code,
        Err(_) => {
            diagnostic(
                "run",
                "post-tool-use",
                "handler panicked; failing safe",
                false,
            );
            ExitCode::SUCCESS
        }
    }
}

/// The handler body, wrapped by [`run`] in a panic guard.
fn run_inner(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let mut raw = String::new();
    if let Err(error) = input.take(MAX_PAYLOAD_BYTES + 1).read_to_string(&mut raw) {
        diagnostic("read", "stdin", &error.to_string(), true);
        return ExitCode::SUCCESS;
    }
    if raw.len() as u64 > MAX_PAYLOAD_BYTES {
        diagnostic("read", "stdin", "payload exceeds maximum size", false);
        return ExitCode::SUCCESS;
    }

    let hook_input = match parse_input(&raw) {
        Ok(hook_input) => hook_input,
        Err(error) => {
            diagnostic("parse", "stdin", &error.to_string(), false);
            return ExitCode::SUCCESS;
        }
    };

    let Some(file_path) = edited_file(&hook_input) else {
        return ExitCode::SUCCESS;
    };

    // Resolve the repo root first: the touched file path is resolved against the
    // payload's cwd, not this hook process's cwd, and the evidence ledger lives
    // under the same root. An unresolvable cwd fails safe (exit 0) rather than
    // resolving the file against an unrelated directory.
    let Some(root) = repo_root(hook_input.cwd.as_deref()) else {
        return ExitCode::SUCCESS;
    };

    let result = match resolve_target(&root, &file_path) {
        Some(resolved) => {
            let mut result = gitleaks::scan(std::slice::from_ref(&resolved));
            if result.locations.is_empty() {
                result.locations.push(crate::checks::Location {
                    file: resolved,
                    line: None,
                });
            }
            result
        }
        None => unverified_target(&file_path),
    };

    persist(&root, hook_input.session_id.as_deref(), &result);

    match result.status {
        Status::Failed => emit_block(output, &result),
        Status::Unverified => {
            diagnostic(
                "scan",
                &result.rule_id,
                "secret scan unverified; not blocking",
                false,
            );
            ExitCode::SUCCESS
        }
        _ => ExitCode::SUCCESS,
    }
}

/// Resolve the touched `file_path` against the payload `root`, requiring the
/// result to name an existing regular file.
///
/// An absolute `file_path` is used as-is; a relative one is joined onto `root`
/// (the payload cwd), never this hook process's own working directory, so a
/// relative path scans the file the agent actually edited. Returns the resolved
/// path as a string only when it names a regular file, or `None` otherwise —
/// signalling the caller to record an `unverified` result.
///
/// The check is `symlink_metadata().is_file()`, not `exists()`: `exists()` also
/// admits directories, FIFOs, sockets, and device nodes, which would make
/// gitleaks recurse a whole directory tree or block forever on a `read` of a FIFO
/// or device. `symlink_metadata` does not follow a final symlink, so a symlink
/// planted at the path is itself rejected rather than being followed to whatever
/// it points at. Only a genuine regular file is a valid scan target; anything
/// else — absent, non-regular, outside the root, or a symlink — is unverified.
fn resolve_target(root: &Path, file_path: &str) -> Option<String> {
    let candidate = Path::new(file_path);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let metadata = std::fs::symlink_metadata(&resolved).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let canonical = std::fs::canonicalize(resolved).ok()?;
    canonical
        .starts_with(root)
        .then(|| canonical.to_string_lossy().into_owned())
}

/// An `unverified` result for a touched path that cannot be scanned safely.
///
/// A path the edit named but that, when the hook runs, is absent (deleted,
/// renamed, or never resolved) or is not a regular file (a directory, FIFO,
/// socket, device node, symlink, or path outside the repository) cannot prove
/// compliance. It is recorded as `unverified`, never as a silent pass.
fn unverified_target(file_path: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: "no-committed-secrets".to_string(),
        status: Status::Unverified,
        severity: Severity::Error,
        message: format!(
            "Secret scan unverified: the edited path is outside the repository, absent, or not a regular file ({}).",
            sanitize(file_path)
        ),
        locations: Vec::new(),
        remediation: Some(
            "Use a regular file contained by the repository and run the edit again.".to_string(),
        ),
        evidence: ResultEvidence {
            check: "gitleaks.detect".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

/// Strip control characters from a path before it enters an agent-facing
/// message, mirroring the check-side sanitizer so a crafted path cannot inject
/// structure into the skipped-result message.
fn sanitize(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}

/// Emit the PostToolUse block envelope carrying the result's repair text.
///
/// The reason is the result's message plus its remediation, sanitized against
/// control-character injection (the check already sanitizes tool-sourced text,
/// but the reason is assembled here so it is re-checked at the boundary). A
/// serialize or write failure falls safe: the block is dropped and the hook
/// exits success rather than wedging the session.
fn emit_block(output: &mut impl Write, result: &EnforcementResult) -> ExitCode {
    let reason = block_reason(result);
    let payload = json!({ "decision": "block", "reason": reason });
    let serialized = match serde_json::to_string(&payload) {
        Ok(serialized) => serialized,
        Err(error) => {
            diagnostic("serialize", "decision", &error.to_string(), false);
            return ExitCode::SUCCESS;
        }
    };
    if let Err(error) = writeln!(output, "{serialized}") {
        diagnostic("write", "decision", &error.to_string(), true);
    }
    ExitCode::SUCCESS
}

/// Assemble the agent-facing block reason from a failed result.
///
/// Joins the message and remediation into one block and strips control
/// characters so nothing tool- or repo-sourced can inject structure into the
/// reason string the agent is shown.
fn block_reason(result: &EnforcementResult) -> String {
    let mut reason = result.message.clone();
    if let Some(remediation) = &result.remediation {
        reason.push(' ');
        reason.push_str(remediation);
    }
    reason
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}

/// Emit one operator diagnostic to stderr in the standard shape
/// `action failed: entity=<id> reason=<cause> retryable=<bool>`.
///
/// Written on a discarded result so a closed stderr can never panic the hook.
fn diagnostic(action: &str, entity: &str, reason: &str, retryable: bool) {
    let _ = writeln!(
        io::stderr(),
        "{action} failed: entity={entity} reason={reason} retryable={retryable}"
    );
}

/// Parse the PostToolUse payload from raw stdin text.
///
/// Blank stdin is accepted as an empty payload (all fields default), which the
/// caller then treats as an ignored tool. Non-blank text that is not a JSON
/// object is a parse error the caller treats as malformed stdin.
fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    if raw.trim().is_empty() {
        return Ok(HookInput::default());
    }
    serde_json::from_str(raw)
}

/// The file an edit touched, or `None` when the tool is not a filesystem edit or
/// carries no file path.
///
/// Only [`EDIT_TOOLS`] are considered; a blank path is treated as absent so an
/// edit with an empty `file_path` is ignored rather than scanning nothing.
fn edited_file(hook_input: &HookInput) -> Option<String> {
    let tool_name = hook_input.tool_name.as_deref()?;
    if !EDIT_TOOLS.contains(&tool_name) {
        return None;
    }
    let file_path = hook_input
        .tool_input
        .as_ref()
        .and_then(|input| input.file_path.as_deref())?;
    if file_path.trim().is_empty() {
        None
    } else {
        Some(file_path.to_string())
    }
}

/// Resolve and canonicalize the repo root from the payload's `cwd`, falling back
/// to the process working directory.
///
/// The candidate (the payload `cwd`, or the process cwd when absent or blank) is
/// canonicalized and required to be an existing directory: the touched file is
/// resolved against this root and the evidence ledger is written under it, so a
/// nonexistent or non-directory root must fail safe rather than resolve paths
/// against a bogus base or scatter evidence into a stray location. Returns `None`
/// on any of those, which the caller maps to a silent success exit.
fn repo_root(cwd: Option<&str>) -> Option<PathBuf> {
    let candidate = match cwd {
        Some(cwd) if !cwd.trim().is_empty() => PathBuf::from(cwd),
        _ => std::env::current_dir().ok()?,
    };
    let canonical = std::fs::canonicalize(&candidate).ok()?;
    if canonical.is_dir() {
        Some(canonical)
    } else {
        None
    }
}

/// Append the result to the evidence ledger, failing safe on any error.
///
/// A persistence failure is diagnosed to stderr but never changes the hook's
/// outcome: evidence is best-effort and must not block a session.
fn persist(root: &Path, session_id: Option<&str>, result: &EnforcementResult) {
    if let Err(reason) = append_evidence(root, session_id, result) {
        diagnostic("persist", "evidence", &reason, true);
    }
}

/// Append one enforcement result as a JSONL record to
/// `.lgtm/evidence/current-task.results.jsonl` under `root`.
///
/// Each record wraps the result with the session id so the Stop gate can scope
/// results to a session. The whole read-modify-write is serialized by an
/// exclusive advisory lock (`flock(LOCK_EX)`) held on a sibling lock file for the
/// duration of both the rotation and the append, so two concurrent hooks cannot
/// interleave a rotation with an append and lose or corrupt records. When
/// rotation is required, it is committed via a staged temp file renamed over the
/// ledger (an atomic replace), so a reader — or a crash mid-rotation — never sees
/// a half-written ledger, and it preserves every `failed`/`unverified` record
/// from the current session (dropping oldest `passed` records first) so a burst
/// of clean edits can never evict a caught violation the Stop gate must still
/// see.
fn append_evidence(
    root: &Path,
    session_id: Option<&str>,
    result: &EnforcementResult,
) -> Result<(), String> {
    let dir = root.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).map_err(|error| format!("mkdir ({error})"))?;
    let path = dir.join("current-task.results.jsonl");

    let record = json!({
        "session_id": session_id,
        "result": result,
    });
    let mut line =
        serde_json::to_string(&record).map_err(|error| format!("serialize ({error})"))?;
    line.push('\n');

    // Hold an exclusive advisory lock across the rotate + append so concurrent
    // hooks serialize on the ledger. The lock lives on a sibling `.lock` file
    // (not the ledger itself) so a rotation that renames the ledger away does not
    // invalidate the lock every writer is coordinating on.
    let lock_path = dir.join("current-task.results.lock");
    let _lock = EvidenceLock::acquire(&lock_path)?;

    rotate_for_incoming(&path, session_id, line.len() as u64)?;

    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open ({error})"))?;
    file.write_all(line.as_bytes())
        .map_err(|error| format!("write ({error})"))?;
    Ok(())
}

/// An exclusive advisory lock (`flock(LOCK_EX)`) on a lock file, released on
/// drop.
///
/// Held for the whole evidence read-modify-write so two concurrent PostToolUse
/// hooks writing to the same repo cannot interleave a rotation and an append and
/// lose or corrupt records. The lock is advisory and process-scoped; every writer
/// of this ledger takes it, so mutual exclusion holds among lgtm hooks. On unix
/// this is a real `flock`; on non-unix (unsupported for hooks) the guard is a
/// no-op so the crate still builds.
struct EvidenceLock {
    #[cfg(unix)]
    file: std::fs::File,
}

/// The number of non-blocking lock attempts before the acquire gives up.
/// Combined with [`LOCK_RETRY_INTERVAL`] this bounds the total wait at roughly
/// two seconds so a wedged lock holder can never stall this hook indefinitely.
#[cfg(unix)]
const LOCK_RETRY_ATTEMPTS: u32 = 20;

/// The pause between non-blocking lock attempts. Short enough that the common
/// case (a brief overlap between two hooks) still acquires quickly, long enough
/// not to spin the CPU.
#[cfg(unix)]
const LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

impl EvidenceLock {
    /// Open (creating if needed) the lock file and take an exclusive `flock`,
    /// bounded so a wedged holder cannot block the hook forever.
    ///
    /// The lock is taken with `LOCK_EX | LOCK_NB` and retried up to
    /// [`LOCK_RETRY_ATTEMPTS`] times spaced [`LOCK_RETRY_INTERVAL`] apart (a ~2s
    /// deadline). A blocking `LOCK_EX` is deliberately avoided: if some other hook
    /// (or a stuck process) holds the lock and never releases it, a blocking
    /// acquire would wedge every subsequent hook. On the deadline the acquire
    /// returns an error; the caller (`persist`) writes a stderr diagnostic and
    /// skips the append, so this one result's evidence is lost but the hook still
    /// exits fail-safe rather than hanging the agent session.
    #[cfg(unix)]
    fn acquire(path: &Path) -> Result<Self, String> {
        use std::os::unix::io::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .map_err(|error| format!("lock open ({error})"))?;

        for attempt in 0..LOCK_RETRY_ATTEMPTS {
            // SAFETY: `flock` takes a valid open file descriptor and a flag; the
            // fd is owned by `file` and outlives the call. `LOCK_EX | LOCK_NB`
            // returns 0 with the lock held, or -1 with errno `EWOULDBLOCK` when
            // another holder has it, or -1 with another errno on a real error —
            // all three handled here.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            let contended = matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            );
            if !contended {
                return Err(format!("lock acquire ({error})"));
            }
            if attempt + 1 < LOCK_RETRY_ATTEMPTS {
                std::thread::sleep(LOCK_RETRY_INTERVAL);
            }
        }

        Err(format!(
            "lock contended for {LOCK_RETRY_ATTEMPTS} attempts (~{}ms); skipping evidence persistence this once",
            LOCK_RETRY_ATTEMPTS as u128 * LOCK_RETRY_INTERVAL.as_millis()
        ))
    }

    #[cfg(not(unix))]
    fn acquire(_path: &Path) -> Result<Self, String> {
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for EvidenceLock {
    /// Release the advisory lock. Closing the descriptor releases the `flock`;
    /// the explicit `LOCK_UN` makes the release eager rather than waiting for the
    /// close, and its result is ignored because the drop cannot fail meaningfully.
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: `self.file` is a valid, still-open descriptor for the lifetime
        // of this guard; LOCK_UN on it is always well-defined.
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// The read bound applied when loading the ledger to rotate it. It is larger
/// than [`MAX_EVIDENCE_BYTES`] so a ledger that has grown to or just past the cap
/// is still readable and trimmable: reading with exactly the cap would treat an
/// at-or-over-cap file as absent (per [`crate::fsutil::read_optional_bounded`])
/// and never rotate it. A file larger than even this bound is pathological (hand
/// written, not produced by this appender) and is treated as absent, which drops
/// it and starts the ledger fresh — still bounded, never unbounded.
const EVIDENCE_READ_BOUND: u64 = MAX_EVIDENCE_BYTES * 2;

/// Rotate the ledger if appending `incoming` bytes would push it past
/// [`MAX_EVIDENCE_BYTES`], preserving every must-keep record and committing the
/// result atomically.
///
/// Must be called with the evidence lock held. Reads the existing file bounded by
/// [`EVIDENCE_READ_BOUND`] (a runaway ledger cannot exhaust memory). When the
/// ledger plus the incoming record already fits, nothing is done. Otherwise it
/// partitions the existing records: every `failed` or `unverified` record from
/// the current `session_id` is a must-keep survivor that rotation may never
/// evict, and the remaining records (clean passes, skips, and records from other
/// sessions) are droppable oldest-first. It keeps all must-keep records plus as
/// many of the newest droppable records as fit the remaining budget, then writes
/// the survivors through a staged temp file renamed over the ledger so the
/// replace is atomic. A ledger larger than the read bound — or one that cannot be
/// classified — is treated as absent and reset the same atomic way, and even that
/// reset path preserves nothing only because nothing was readable; the caller's
/// fresh append then re-seeds the ledger.
fn rotate_for_incoming(path: &Path, session_id: Option<&str>, incoming: u64) -> Result<(), String> {
    let existing = crate::fsutil::read_optional_bounded(path, EVIDENCE_READ_BOUND);
    if existing.is_empty() {
        // Either the ledger is genuinely absent, or it exceeded the read bound
        // and is unreadable. Atomically reset any on-disk file so a
        // pathologically large ledger does not survive the append.
        if path.exists() {
            replace_ledger(path, "")?;
        }
        return Ok(());
    }
    if existing.len() as u64 + incoming <= MAX_EVIDENCE_BYTES {
        return Ok(());
    }

    let budget = MAX_EVIDENCE_BYTES.saturating_sub(incoming) as usize;
    let kept = trim_records(&existing, session_id, budget);
    replace_ledger(path, &kept)
}

/// Select the records to keep so the result fits `budget` bytes while never
/// dropping a must-keep record.
///
/// A must-keep record is a `failed` or `unverified` result belonging to
/// `session_id`: those are the caught violations and unverified concerns the Stop
/// gate must still see, so rotation preserves them unconditionally even if that
/// means the kept set exceeds `budget`. Every other record is droppable and is
/// kept newest-first only while the running total stays within the budget the
/// must-keep records leave. The returned string preserves the original relative
/// order of the kept records (must-keep and droppable interleaved as they
/// appeared), each newline-terminated.
fn trim_records(existing: &str, session_id: Option<&str>, budget: usize) -> String {
    let records: Vec<&str> = existing.lines().collect();

    // First pass: total the bytes the must-keep records consume so the droppable
    // budget is whatever remains.
    let mut must_keep_bytes = 0usize;
    let mut is_must_keep = Vec::with_capacity(records.len());
    for record in &records {
        let keep = is_must_keep_record(record, session_id);
        if keep {
            must_keep_bytes = must_keep_bytes.saturating_add(record.len() + 1);
        }
        is_must_keep.push(keep);
    }

    let droppable_budget = budget.saturating_sub(must_keep_bytes);

    // Second pass, newest-first over droppable records: admit each while it fits
    // the droppable budget, marking the rest for eviction. Must-keep records are
    // always admitted.
    let mut admitted = vec![false; records.len()];
    let mut used = 0usize;
    for index in (0..records.len()).rev() {
        if is_must_keep[index] {
            admitted[index] = true;
            continue;
        }
        let size = records[index].len() + 1;
        if used + size <= droppable_budget {
            used += size;
            admitted[index] = true;
        }
    }

    let mut kept = String::new();
    for (index, record) in records.iter().enumerate() {
        if admitted[index] {
            kept.push_str(record);
            kept.push('\n');
        }
    }
    kept
}

/// True when a serialized ledger line is a `failed` or `unverified` record
/// belonging to `session_id`, which rotation must never evict.
///
/// A line that does not parse, or whose session id does not match, is not
/// must-keep: only well-formed records of the current session that carry a caught
/// violation or an unverified concern are protected. A `None` `session_id` (the
/// hook received no session) protects records whose stored `session_id` is also
/// null, so an unsessioned run still cannot evict its own violations.
fn is_must_keep_record(line: &str, session_id: Option<&str>) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    let record_session = value.get("session_id").and_then(|value| value.as_str());
    if record_session != session_id {
        return false;
    }
    matches!(
        value
            .get("result")
            .and_then(|result| result.get("status"))
            .and_then(|status| status.as_str()),
        Some("failed") | Some("unverified")
    )
}

/// Atomically replace the ledger at `path` with `contents`.
///
/// Writes to a uniquely named sibling temp file, fsyncs it, then renames it over
/// the ledger so a concurrent reader (or a crash) sees either the old ledger or
/// the new one, never a half-written file. The temp lives in the ledger's own
/// directory so the rename is a same-filesystem atomic replace, and it is opened
/// `create_new` so a leftover or planted temp of the same name fails rather than
/// being clobbered.
fn replace_ledger(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp_path = dir.join(format!(
        ".current-task.results.jsonl.tmp-{}-{nanos}-{counter}",
        std::process::id()
    ));

    let write_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!("rotate stage ({error})"));
    }

    std::fs::rename(&temp_path, path).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        format!("rotate commit ({error})")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use serde_json::Value;

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
        append_evidence(&temp.path, Some("sess-1"), &result).expect("append must succeed");

        let ledger = temp
            .path
            .join(".lgtm")
            .join("evidence")
            .join("current-task.results.jsonl");
        let contents = std::fs::read_to_string(&ledger).expect("ledger readable");
        let line = contents.lines().next().expect("one record present");
        let value: Value = serde_json::from_str(line).expect("record must be valid JSON");
        assert_eq!(value["session_id"], json!("sess-1"));
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
        append_evidence(&temp.path, Some("sess-2"), &result).expect("append must succeed");

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
        let outcome = append_evidence(&temp.path, Some("sess-lock"), &result);
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
        serde_json::to_string(&json!({ "session_id": session, "result": result }))
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
        append_evidence(&temp.path, Some("sess-x"), &result).expect("append must succeed");

        let contents = std::fs::read_to_string(&path).expect("ledger readable");
        assert!(
            contents.contains("planted leak"),
            "rotation must preserve the failed record of the current session"
        );
        assert!(
            contents.contains("newest"),
            "the new record must be appended after rotation"
        );
    }
}
