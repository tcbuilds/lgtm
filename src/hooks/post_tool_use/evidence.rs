use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::checks::EnforcementResult;

pub(super) const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;
pub(super) const MAX_EVIDENCE_RECORDS: usize = 16 * 1024;
pub(super) const MAX_MUST_KEEP_RECORDS: usize = 128;
const MAX_COMPACT_FIELD_CHARS: usize = 4 * 1024;

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
/// a half-written ledger, and it preserves a bounded set of recent
/// `failed`/`unverified` records from the current session (dropping older
/// records first) so a burst of clean edits cannot erase the actionable signal
/// the Stop gate must still see.
pub(super) fn append_evidence(
    root: &Path,
    session_id: Option<&str>,
    edited_file: Option<&str>,
    result: &EnforcementResult,
) -> Result<(), String> {
    let dir = root.join(".lgtm").join("evidence");
    std::fs::create_dir_all(&dir).map_err(|error| format!("mkdir ({error})"))?;
    let path = dir.join("current-task.results.jsonl");

    let line = serialize_record(session_id, edited_file, result)?;

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
/// [`MAX_EVIDENCE_BYTES`], preserving a bounded recent failure signal and
/// committing the result atomically.
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
    let record_cap_reached = existing
        .lines()
        .nth(MAX_EVIDENCE_RECORDS.saturating_sub(1))
        .is_some();
    if existing.len() as u64 + incoming <= MAX_EVIDENCE_BYTES && !record_cap_reached {
        return Ok(());
    }

    let budget = MAX_EVIDENCE_BYTES.saturating_sub(incoming) as usize;
    let kept = trim_records(&existing, session_id, budget);
    replace_ledger(path, &kept)
}

/// Select the records to keep so the result fits `budget` bytes while retaining
/// a bounded, recent failure signal.
///
/// A must-keep record is a `failed` or `unverified` result belonging to
/// `session_id`. The newest records are preferred, but both their byte budget and
/// [`MAX_MUST_KEEP_RECORDS`] cap apply. Every other record is droppable and is
/// kept newest-first only after the protected records have been selected. The
/// returned string preserves the original relative order of the survivors.
pub(super) fn trim_records(existing: &str, session_id: Option<&str>, budget: usize) -> String {
    let has_excess_records = existing
        .lines()
        .nth(MAX_EVIDENCE_RECORDS.saturating_sub(1))
        .is_some();
    let marker = has_excess_records.then(|| compact_truncation_record(session_id));
    let marker_present = marker.as_ref().is_some_and(|line| line.len() <= budget);
    let marker = marker.filter(|line| line.len() <= budget);
    let mut remaining = budget.saturating_sub(marker.as_ref().map_or(0, String::len));
    let marker_slots = if marker_present { 1 } else { 0 };
    let record_limit = MAX_EVIDENCE_RECORDS
        .saturating_sub(marker_slots)
        .saturating_sub(1);
    let mut recent: Vec<&str> = existing.lines().rev().take(record_limit).collect();
    recent.reverse();
    let mut selected: Vec<(usize, &str, Option<String>)> = Vec::new();
    let mut must_keep_count = 0;
    let must_keep_limit = MAX_MUST_KEEP_RECORDS.saturating_sub(marker_slots);

    // Process only the newest bounded window. A single large actionable record
    // is compacted before admission so its status, session, and path identity
    // remain available to Stop.
    for index in (0..recent.len()).rev() {
        if !is_must_keep_record(recent[index], session_id) || must_keep_count >= must_keep_limit {
            continue;
        }
        let size = recent[index].len() + 1;
        let compact = if size > remaining {
            compact_existing_record(recent[index])
        } else {
            None
        };
        let admitted_size = compact.as_ref().map_or(size, String::len);
        if admitted_size <= remaining {
            remaining -= admitted_size;
            selected.push((index, recent[index], compact));
            must_keep_count += 1;
        }
    }

    // Fill only the remaining bytes with recent clean or unrelated records.
    for index in (0..recent.len()).rev() {
        if is_must_keep_record(recent[index], session_id) {
            continue;
        }
        let size = recent[index].len() + 1;
        if size <= remaining {
            remaining -= size;
            selected.push((index, recent[index], None));
        }
    }

    selected.sort_unstable_by_key(|(index, _, _)| *index);
    let mut kept = String::with_capacity(budget.saturating_sub(remaining));
    if let Some(marker) = marker {
        kept.push_str(&marker);
    }
    for (_, record, compact) in selected {
        if let Some(compact) = compact {
            kept.push_str(&compact);
        } else {
            kept.push_str(record);
            kept.push('\n');
        }
    }
    kept
}

fn compact_truncation_record(session_id: Option<&str>) -> String {
    let mut marker = serde_json::to_string(&json!({
        "session_id": session_id,
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
    }))
    .unwrap_or_else(|_| "{}".to_string());
    marker.push('\n');
    marker
}

fn compact_existing_record(line: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let result = value.get("result")?;
    let locations = result
        .get("locations")
        .and_then(|value| value.as_array())
        .and_then(|locations| locations.first())
        .and_then(|location| {
            let file = location.get("file")?.as_str()?;
            Some(vec![json!({
                "file": compact_text(file),
                "line": location.get("line").cloned().unwrap_or(serde_json::Value::Null)
            })])
        })
        .unwrap_or_default();
    let compact = json!({
        "session_id": value.get("session_id").cloned().unwrap_or(serde_json::Value::Null),
        "edited_file": value
            .get("edited_file")
            .and_then(|value| value.as_str())
            .map(compact_text),
        "result": {
            "rule_id": result
                .get("rule_id")
                .and_then(|value| value.as_str())
                .map(compact_text)
                .unwrap_or_else(|| "unknown".to_string()),
            "status": result
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unverified"),
            "severity": result
                .get("severity")
                .and_then(|value| value.as_str())
                .unwrap_or("error"),
            "message": "Evidence record exceeded the rotation budget; details were truncated.",
            "locations": locations,
            "remediation": null,
            "evidence": {
                "check": result
                    .get("evidence")
                    .and_then(|evidence| evidence.get("check"))
                    .and_then(|value| value.as_str())
                    .map(compact_text)
                    .unwrap_or_else(|| "unknown".to_string()),
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true
    });
    let mut compact_line = serde_json::to_string(&compact).ok()?;
    compact_line.push('\n');
    Some(compact_line)
}

fn serialize_record(
    session_id: Option<&str>,
    edited_file: Option<&str>,
    result: &EnforcementResult,
) -> Result<String, String> {
    let record = json!({
        "session_id": session_id,
        "edited_file": edited_file,
        "result": result,
    });
    let mut line =
        serde_json::to_string(&record).map_err(|error| format!("serialize ({error})"))?;
    line.push('\n');
    if line.len() as u64 <= MAX_EVIDENCE_BYTES {
        return Ok(line);
    }

    // Preserve the session, status, rule, and edited path when a single result
    // is too large to fit. Stop needs that bounded identity and signal; it does
    // not need unbounded tool descriptions or locations to decide safely.
    let compact = json!({
        "session_id": session_id,
        "edited_file": edited_file.map(compact_text),
        "result": {
            "rule_id": compact_text(&result.rule_id),
            "status": result.status,
            "severity": result.severity,
            "message": "Evidence record exceeded the ledger bound; details were truncated.",
            "locations": [],
            "remediation": null,
            "evidence": {
                "check": compact_text(&result.evidence.check),
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true
    });
    let mut compact_line =
        serde_json::to_string(&compact).map_err(|error| format!("serialize compact ({error})"))?;
    compact_line.push('\n');
    Ok(compact_line)
}

fn compact_text(value: &str) -> String {
    if value.chars().count() <= MAX_COMPACT_FIELD_CHARS {
        return value.to_string();
    }
    let mut compact: String = value
        .chars()
        .take(MAX_COMPACT_FIELD_CHARS.saturating_sub(1))
        .collect();
    compact.push('…');
    compact
}

/// True when a serialized ledger line is a `failed` or `unverified` record
/// belonging to `session_id`, making it a candidate for bounded retention.
///
/// A line that does not parse, or whose session id does not match, is not
/// must-keep: only well-formed records of the current session that carry a caught
/// violation or an unverified concern are eligible for the bounded recent
/// signal. A `None` `session_id` (the hook received no session) matches records
/// whose stored `session_id` is also null, so an unsessioned run gets the same
/// bounded retention policy.
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
