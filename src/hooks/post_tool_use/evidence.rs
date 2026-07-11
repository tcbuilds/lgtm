use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::checks::EnforcementResult;

pub(super) const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;

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
pub(super) fn append_evidence(
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
pub(super) fn trim_records(existing: &str, session_id: Option<&str>, budget: usize) -> String {
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
pub(super) fn is_must_keep_record(line: &str, session_id: Option<&str>) -> bool {
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
