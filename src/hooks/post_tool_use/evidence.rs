use std::io::{Read, Write};
use std::path::Path;

use serde_json::json;

use crate::checks::EnforcementResult;

pub(super) const MAX_EVIDENCE_BYTES: u64 = 5 * 1024 * 1024;
pub(super) const MAX_EVIDENCE_RECORDS: usize = 16 * 1024;
pub(super) const MAX_MUST_KEEP_RECORDS: usize = 128;
const MAX_COMPACT_FIELD_CHARS: usize = 4 * 1024;
const CURRENT_TASK_DETAIL_TRUNCATION_MESSAGE: &str =
    "Evidence record exceeded the ledger bound; details were truncated.";
const CURRENT_TASK_PERSISTENCE_MESSAGE: &str =
    "Current-task evidence could not be persisted within the bounded ledger limit.";
// Only a bounded number of marker-shaped lines may reach JSON parsing while
// searching records outside the retained window. The canonical serialization
// is checked separately so marker-like noise cannot hide a real older marker.
const MAX_PERSISTENCE_MARKER_CANDIDATES: usize = 8;
const PERSISTENCE_MARKER_MESSAGE_SIGNATURE: &str =
    "\"message\":\"Current-task evidence could not be persisted within the bounded ledger limit.\"";
const PERSISTENCE_MARKER_FLAG_SIGNATURE: &str = "\"persistence_failed\":true";
pub(super) const MAX_RECORDED_PATHS: usize = 512;

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

    let (line, rotation_session) = match serialize_record(session_id, edited_file, result) {
        Ok(line) => (line, session_id),
        Err(_) => (compact_persistence_failure_record(), None),
    };

    // Hold an exclusive advisory lock across the rotate + append so concurrent
    // hooks serialize on the ledger. The lock lives on a sibling `.lock` file
    // (not the ledger itself) so a rotation that renames the ledger away does not
    // invalidate the lock every writer is coordinating on.
    let lock_path = dir.join("current-task.results.lock");
    let _lock = EvidenceLock::acquire(&lock_path)?;

    let needs_delimiter = rotate_for_incoming(&path, rotation_session, line.len() as u64)?;

    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open ({error})"))?;
    // Coalesce the delimiter and record so an interrupted append cannot leave a
    // second write to interleave between the JSONL framing bytes and the record.
    let mut append = Vec::with_capacity(line.len() + (if needs_delimiter { 1 } else { 0 }));
    if needs_delimiter {
        append.push(b'\n');
    }
    append.extend_from_slice(line.as_bytes());
    file.write_all(&append)
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
/// is still readable and trimmable without allowing an unbounded allocation.
const EVIDENCE_READ_BOUND: u64 = MAX_EVIDENCE_BYTES * 2;

enum ExistingLedger {
    Missing,
    Empty,
    Readable(String),
}

#[derive(serde::Deserialize)]
struct StoredEvidenceRecord {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    edited_file: Option<String>,
    result: EnforcementResult,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    persistence_failed: bool,
}

fn validate_object_shape(
    value: &serde_json::Value,
    allowed: &[&str],
    required: &[&str],
    context: &str,
) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{context} is not an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("{context} contains unknown field `{field}`"));
    }
    if let Some(field) = required
        .iter()
        .find(|field| !object.keys().any(|key| key == *field))
    {
        return Err(format!("{context} is missing required field `{field}`"));
    }
    Ok(())
}

fn marker_shape(record: &StoredEvidenceRecord) -> bool {
    record.edited_file.is_none()
        && record.result.rule_id == "current-task-evidence"
        && record.result.status == crate::checks::Status::Unverified
        && record.result.severity == crate::policy::Severity::Error
        && record.result.locations.is_empty()
        && record.result.remediation.is_none()
        && record.result.evidence.check == "evidence.current-task"
        && record.result.evidence.tool_version.is_none()
        && record.result.evidence.finding_descriptions.is_empty()
}

fn persistence_marker(record: &StoredEvidenceRecord) -> bool {
    record.truncated
        && marker_shape(record)
        && record.session_id.is_none()
        && record.persistence_failed
        && record.result.message
            == "Current-task evidence could not be persisted within the bounded ledger limit."
}

fn validate_record_shape(value: &serde_json::Value) -> Result<(), String> {
    validate_object_shape(
        value,
        &[
            "session_id",
            "edited_file",
            "result",
            "truncated",
            "persistence_failed",
        ],
        &["session_id", "result"],
        "existing ledger record",
    )?;
    let session_id = value
        .get("session_id")
        .ok_or_else(|| "existing ledger record is missing a session id".to_string())?;
    if !session_id.is_null()
        && session_id
            .as_str()
            .is_none_or(|session_id| session_id.is_empty())
    {
        return Err("existing ledger session id is empty or invalid".to_string());
    }
    let result = value
        .get("result")
        .ok_or_else(|| "existing ledger record is missing a result".to_string())?;
    validate_object_shape(
        result,
        &[
            "rule_id",
            "status",
            "severity",
            "message",
            "locations",
            "remediation",
            "evidence",
        ],
        &[
            "rule_id",
            "status",
            "severity",
            "message",
            "locations",
            "evidence",
        ],
        "existing ledger result",
    )?;
    let result_object = result
        .as_object()
        .ok_or_else(|| "existing ledger result is not an object".to_string())?;
    if result_object
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|rule_id| rule_id.is_empty())
    {
        return Err("existing ledger result rule id is empty".to_string());
    }
    let locations = result
        .get("locations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "existing ledger result locations is not an array".to_string())?;
    if locations.len() > MAX_RECORDED_PATHS {
        return Err("existing ledger result has too many locations".to_string());
    }
    for location in locations {
        validate_object_shape(
            location,
            &["file", "line"],
            &["file"],
            "existing ledger result location",
        )?;
        let location = location
            .as_object()
            .ok_or_else(|| "existing ledger result location is not an object".to_string())?;
        if !location["file"].is_string()
            || location
                .get("line")
                .is_some_and(|line| !line.is_null() && line.as_u64().is_none_or(|line| line == 0))
        {
            return Err("existing ledger result location has invalid fields".to_string());
        }
    }
    let evidence = result
        .get("evidence")
        .ok_or_else(|| "existing ledger result is missing evidence".to_string())?;
    validate_object_shape(
        evidence,
        &["check", "tool_version", "finding_descriptions"],
        &["check"],
        "existing ledger result evidence",
    )?;
    let evidence = evidence
        .as_object()
        .ok_or_else(|| "existing ledger result evidence is not an object".to_string())?;
    if evidence
        .get("check")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|check| check.is_empty())
    {
        return Err("existing ledger result evidence check is empty".to_string());
    }
    Ok(())
}

fn parse_stored_record(value: serde_json::Value) -> Result<StoredEvidenceRecord, String> {
    validate_record_shape(&value)?;
    let has_persistence_metadata = value.get("persistence_failed").is_some();
    let record = serde_json::from_value::<StoredEvidenceRecord>(value)
        .map_err(|error| format!("existing ledger has invalid evidence schema ({error})"))?;
    if marker_shape(&record) && !record.truncated && !record.persistence_failed {
        return Err("existing ledger marker is missing truncation metadata".to_string());
    }
    if marker_shape(&record)
        && record.truncated
        && !record.persistence_failed
        && record.result.message
            == "Older current-task evidence records were dropped at the bounded retention limit."
        && has_persistence_metadata
    {
        return Err(
            "existing ledger retention marker has unexpected persistence metadata".to_string(),
        );
    }
    if (record.persistence_failed
        || record.result.message
            == "Current-task evidence could not be persisted within the bounded ledger limit.")
        && !persistence_marker(&record)
    {
        return Err("existing ledger has invalid persistence marker metadata".to_string());
    }
    Ok(record)
}

fn read_existing_ledger(path: &Path) -> Result<ExistingLedger, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExistingLedger::Missing);
        }
        Err(error) => return Err(format!("inspect existing ledger ({error})")),
    };
    if !metadata.file_type().is_file() {
        return Err("existing ledger is not a regular file".to_string());
    }
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open existing ledger ({error})"))?
    else {
        return Err("existing ledger became unavailable".to_string());
    };
    let mut bytes = Vec::new();
    file.take(EVIDENCE_READ_BOUND.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read existing ledger ({error})"))?;
    if bytes.len() as u64 > EVIDENCE_READ_BOUND {
        return Err("existing ledger exceeds the readable size bound".to_string());
    }
    let raw =
        String::from_utf8(bytes).map_err(|_| "existing ledger is not valid UTF-8".to_string())?;
    if raw.is_empty() {
        Ok(ExistingLedger::Empty)
    } else {
        Ok(ExistingLedger::Readable(raw))
    }
}

/// Validate the bounded recent record window before append or rotation so a
/// malformed present ledger is preserved and surfaced rather than silently
/// treated as usable evidence. Older records are outside the retained window
/// and are surfaced by the retention marker when the record cap forces rotation.
fn validate_recent_records(existing: &str) -> Result<(), String> {
    for line in existing.lines().rev().take(MAX_EVIDENCE_RECORDS) {
        let value = serde_json::from_str::<serde_json::Value>(line)
            .map_err(|error| format!("existing ledger contains malformed JSON ({error})"))?;
        let _ = parse_stored_record(value)?;
    }
    Ok(())
}

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
/// replace is atomic. A present ledger that is oversized, malformed, unreadable,
/// or otherwise unavailable is preserved and reported as an error rather than
/// silently reset and reseeded.
fn rotate_for_incoming(
    path: &Path,
    session_id: Option<&str>,
    incoming: u64,
) -> Result<bool, String> {
    let existing = match read_existing_ledger(path)? {
        ExistingLedger::Missing => return Ok(false),
        ExistingLedger::Empty => return Err("existing ledger is empty".to_string()),
        ExistingLedger::Readable(existing) => existing,
    };
    validate_recent_records(&existing)?;
    let record_cap_reached = existing
        .lines()
        .nth(MAX_EVIDENCE_RECORDS.saturating_sub(1))
        .is_some();
    let needs_delimiter = !existing.ends_with('\n');
    let delimiter_bytes = u64::from(needs_delimiter);
    if existing
        .len()
        .saturating_add(incoming as usize)
        .saturating_add(delimiter_bytes as usize) as u64
        <= MAX_EVIDENCE_BYTES
        && !record_cap_reached
    {
        return Ok(needs_delimiter);
    }

    if incoming > MAX_EVIDENCE_BYTES {
        return Err("incoming evidence record exceeds the maximum size".to_string());
    }
    let budget = MAX_EVIDENCE_BYTES.saturating_sub(incoming) as usize;
    let kept = trim_records(&existing, session_id, budget)?;
    replace_ledger(path, &kept)?;
    Ok(false)
}

/// Select records that fit `budget` bytes while retaining a bounded, recent
/// failure signal. Any omitted record causes a compact marker to be reserved;
/// if that marker cannot fit, the caller must preserve the old ledger.
pub(super) fn trim_records(
    existing: &str,
    session_id: Option<&str>,
    budget: usize,
) -> Result<String, String> {
    let record_limit = MAX_EVIDENCE_RECORDS.saturating_sub(1);
    let mut recent: Vec<&str> = existing.lines().rev().take(record_limit).collect();
    recent.reverse();
    let global_persistence_marker = find_global_persistence_marker(existing)?;
    if let Some(marker) = global_persistence_marker
        && !recent.contains(&marker)
    {
        recent.insert(0, marker);
    }
    let window_omitted = existing.lines().count() > recent.len();
    let first = select_records(&recent, session_id, budget, 0);
    if !window_omitted && !first.omitted {
        if global_persistence_marker.is_some()
            && !contains_persistence_failure_marker(&first.contents)
        {
            return Err(
                "persistence failure marker cannot fit without losing its typed signal".to_string(),
            );
        }
        return Ok(first.contents);
    }

    let marker = compact_truncation_record(session_id);
    if marker.len() > budget {
        return Err(
            "truncation marker cannot fit without exceeding the evidence bound".to_string(),
        );
    }
    let remaining = budget - marker.len();
    let selected = select_records(&recent, session_id, remaining, 1);
    if global_persistence_marker.is_some()
        && !contains_persistence_failure_marker(&selected.contents)
    {
        return Err(
            "persistence failure marker cannot fit without losing its typed signal".to_string(),
        );
    }
    let mut kept = String::with_capacity(marker.len() + selected.contents.len());
    kept.push_str(&marker);
    kept.push_str(&selected.contents);
    if kept.len() > budget {
        return Err("trimmed evidence exceeds the reserved evidence bound".to_string());
    }
    Ok(kept)
}

/// Find the newest valid global persistence marker without deserializing every
/// older record. The cheap signatures reject ordinary lines before parsing; a
/// small candidate budget bounds hostile marker-like input. A marker emitted by
/// this producer is also compared with its canonical serialization, so an older
/// valid marker remains discoverable even if newer noise consumes the candidate
/// budget. Every parsed candidate still passes the existing typed validation.
fn find_global_persistence_marker(existing: &str) -> Result<Option<&str>, String> {
    let canonical = compact_persistence_failure_record();
    let canonical = canonical.strip_suffix('\n').unwrap_or(canonical.as_str());
    let mut parsed_candidates = 0;
    let mut canonical_checked = false;
    let mut over_budget = false;

    for line in existing.lines().rev() {
        let is_canonical = line == canonical;
        let has_signature = line.contains(PERSISTENCE_MARKER_MESSAGE_SIGNATURE)
            && line.contains(PERSISTENCE_MARKER_FLAG_SIGNATURE);
        if !is_canonical && !has_signature {
            continue;
        }
        if is_canonical {
            if canonical_checked {
                continue;
            }
            canonical_checked = true;
        }

        // Keep scanning cheaply after the small candidate budget is spent so a
        // canonical older marker cannot be hidden by marker-like noise. There
        // are at most MAX_PERSISTENCE_MARKER_CANDIDATES non-canonical parses,
        // plus the first canonical line (which is itself bounded).
        if !is_canonical {
            if parsed_candidates >= MAX_PERSISTENCE_MARKER_CANDIDATES {
                over_budget = true;
                continue;
            }
            parsed_candidates += 1;
        }

        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if is_valid_persistence_failure_marker(value) {
            return Ok(Some(line));
        }
    }
    if over_budget {
        Err("persistence marker search exceeded the bounded candidate budget".to_string())
    } else {
        Ok(None)
    }
}

fn contains_persistence_failure_marker(contents: &str) -> bool {
    contents.lines().any(|line| {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .is_some_and(|value| is_persistence_failure_record(&value))
    })
}

struct RecordSelection {
    contents: String,
    omitted: bool,
}

fn select_records(
    recent: &[&str],
    session_id: Option<&str>,
    budget: usize,
    marker_slots: usize,
) -> RecordSelection {
    let record_limit = MAX_EVIDENCE_RECORDS
        .saturating_sub(marker_slots)
        .saturating_sub(1);
    let must_keep_limit = MAX_MUST_KEEP_RECORDS.saturating_sub(marker_slots);
    let mut remaining = budget;
    let mut selected: Vec<(usize, &str, Option<String>)> = Vec::new();
    let mut selected_indices = vec![false; recent.len()];
    let mut must_keep_count = 0;
    let mut omitted = recent.len() > record_limit;

    // Preserve the newest global persistence marker before applying the bounded
    // per-session failure budget. A later burst of failures must not erase the
    // distinct signal that an earlier record could not be persisted.
    let mut persistence_marker_selected = false;
    for index in (0..recent.len()).rev() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(recent[index]) else {
            continue;
        };
        if !is_persistence_failure_record(&value) {
            continue;
        }
        if persistence_marker_selected {
            omitted = true;
            continue;
        }
        let size = recent[index].len() + 1;
        let compact = if size > remaining || record_has_excess_paths(recent[index]) {
            compact_existing_record(recent[index])
        } else {
            None
        };
        let admitted_size = compact.as_ref().map_or(size, String::len);
        if admitted_size > remaining {
            omitted = true;
            continue;
        }
        remaining -= admitted_size;
        selected_indices[index] = true;
        selected.push((index, recent[index], compact));
        persistence_marker_selected = true;
    }

    for index in (0..recent.len()).rev() {
        if !is_must_keep_record(recent[index], session_id)
            || serde_json::from_str::<serde_json::Value>(recent[index])
                .ok()
                .is_some_and(|value| is_persistence_failure_record(&value))
        {
            continue;
        }
        if must_keep_count >= must_keep_limit {
            omitted = true;
            continue;
        }
        let size = recent[index].len() + 1;
        let compact = if size > remaining || record_has_excess_paths(recent[index]) {
            compact_existing_record(recent[index])
        } else {
            None
        };
        let admitted_size = compact.as_ref().map_or(size, String::len);
        if admitted_size > remaining {
            omitted = true;
            continue;
        }
        remaining -= admitted_size;
        selected_indices[index] = true;
        selected.push((index, recent[index], compact));
        must_keep_count += 1;
    }

    for index in (0..recent.len()).rev() {
        if is_must_keep_record(recent[index], session_id) {
            continue;
        }
        let size = recent[index].len() + 1;
        let compact = record_has_excess_paths(recent[index])
            .then(|| compact_existing_record(recent[index]))
            .flatten();
        let admitted_size = compact.as_ref().map_or(size, String::len);
        if selected.len() >= record_limit || admitted_size > remaining {
            omitted = true;
            continue;
        }
        remaining -= admitted_size;
        selected_indices[index] = true;
        selected.push((index, recent[index], compact));
    }

    if selected.len() < recent.len() || selected_indices.iter().any(|selected| !selected) {
        omitted = true;
    }
    selected.sort_unstable_by_key(|(index, _, _)| *index);
    let mut contents = String::with_capacity(budget.saturating_sub(remaining));
    for (_, record, compact) in selected {
        if let Some(compact) = compact {
            contents.push_str(&compact);
        } else {
            contents.push_str(record);
            contents.push('\n');
        }
    }
    RecordSelection { contents, omitted }
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

fn compact_persistence_failure_record() -> String {
    let mut marker = serde_json::to_string(&json!({
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
    }))
    .unwrap_or_else(|_| "{}".to_string());
    marker.push('\n');
    marker
}

fn record_has_excess_paths(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|value| value.get("result").cloned())
        .and_then(|result| result.get("locations").cloned())
        .and_then(|locations| locations.as_array().map(Vec::len))
        .is_some_and(|count| count > MAX_RECORDED_PATHS)
}

pub(super) fn compact_existing_record(line: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    let record = parse_stored_record(value).ok()?;
    let retention_marker = marker_shape(&record)
        && record.result.message
            == "Older current-task evidence records were dropped at the bounded retention limit."
        && !record.persistence_failed;
    let is_persistence_marker = persistence_marker(&record);
    let locations = record
        .result
        .locations
        .first()
        .map(|location| {
            let mut compacted = json!({"file": compact_text(&location.file)});
            if let Some(line) = location.line {
                compacted["line"] = json!(line);
            }
            vec![compacted]
        })
        .unwrap_or_default();
    let message = if is_persistence_marker {
        "Current-task evidence could not be persisted within the bounded ledger limit."
    } else if retention_marker {
        "Older current-task evidence records were dropped at the bounded retention limit."
    } else {
        CURRENT_TASK_DETAIL_TRUNCATION_MESSAGE
    };
    let mut compact = json!({
        "session_id": record.session_id,
        "edited_file": record.edited_file.as_deref().map(compact_text),
        "result": {
            "rule_id": compact_text(&record.result.rule_id),
            "status": record.result.status,
            "severity": record.result.severity,
            "message": message,
            "locations": locations,
            "remediation": null,
            "evidence": {
                "check": compact_text(&record.result.evidence.check),
                "tool_version": null,
                "finding_descriptions": []
            }
        },
        "truncated": true
    });
    if is_persistence_marker {
        compact["persistence_failed"] = json!(true);
    }
    // Keep this helper honest if the ledger shape changes: never return a
    // compacted line that Stop could not deserialize as an EditRecord.
    parse_stored_record(compact.clone()).ok()?;
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
    let marker_len = compact_truncation_record(session_id).len();
    if line.len() as u64 <= MAX_EVIDENCE_BYTES
        && line.len().saturating_add(marker_len) <= MAX_EVIDENCE_BYTES as usize
        && result.locations.len() <= MAX_RECORDED_PATHS
    {
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
            "message": CURRENT_TASK_DETAIL_TRUNCATION_MESSAGE,
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
    if compact_line.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err("compact evidence record exceeds the maximum size".to_string());
    }
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
fn is_persistence_failure_record(value: &serde_json::Value) -> bool {
    let result = value.get("result").and_then(serde_json::Value::as_object);
    let evidence = result
        .and_then(|result| result.get("evidence"))
        .and_then(serde_json::Value::as_object);
    value
        .get("session_id")
        .is_some_and(serde_json::Value::is_null)
        && value
            .get("edited_file")
            .is_some_and(serde_json::Value::is_null)
        && value.get("truncated").and_then(serde_json::Value::as_bool) == Some(true)
        && value
            .get("persistence_failed")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        && result
            .and_then(|result| result.get("rule_id"))
            .and_then(serde_json::Value::as_str)
            == Some("current-task-evidence")
        && result
            .and_then(|result| result.get("status"))
            .and_then(serde_json::Value::as_str)
            == Some("unverified")
        && result
            .and_then(|result| result.get("severity"))
            .and_then(serde_json::Value::as_str)
            == Some("error")
        && result
            .and_then(|result| result.get("message"))
            .and_then(serde_json::Value::as_str)
            == Some(CURRENT_TASK_PERSISTENCE_MESSAGE)
        && result
            .and_then(|result| result.get("locations"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
        && result
            .and_then(|result| result.get("remediation"))
            .is_some_and(serde_json::Value::is_null)
        && evidence
            .and_then(|evidence| evidence.get("check"))
            .and_then(serde_json::Value::as_str)
            == Some("evidence.current-task")
        && evidence
            .and_then(|evidence| evidence.get("tool_version"))
            .is_some_and(serde_json::Value::is_null)
        && evidence
            .and_then(|evidence| evidence.get("finding_descriptions"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
}

fn is_valid_persistence_failure_marker(value: serde_json::Value) -> bool {
    parse_stored_record(value)
        .ok()
        .is_some_and(|record| persistence_marker(&record))
}

pub(super) fn is_must_keep_record(line: &str, session_id: Option<&str>) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    if is_persistence_failure_record(&value) {
        return true;
    }
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
