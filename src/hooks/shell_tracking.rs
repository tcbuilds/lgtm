//! Correlate shell hooks without treating every dirty file as an agent edit.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::checks::{EnforcementResult, ResultEvidence, Status};
use crate::policy::Severity;

mod snapshot;

const STATE_BYTES: u64 = 1024 * 1024;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const RULE: &str = "shell-change-tracking";
pub(super) const TOUCH_CHECK: &str = "shell.observed-change";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    root: PathBuf,
    session: String,
    call: String,
    command_hash: String,
    outstanding: Vec<(String, String, String)>,
    overflowed: bool,
    invalid: bool,
    before: Option<snapshot::Snapshot>,
}

pub(super) fn begin(root: &Path, session: Option<&str>, call: Option<&str>, command: &str) {
    if let Err(reason) = begin_inner(root, session, call, command) {
        record_issue(root, session, &reason);
    }
}

fn begin_inner(
    root: &Path,
    session: Option<&str>,
    call: Option<&str>,
    command: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + SNAPSHOT_TIMEOUT;
    let directory = directory(root)?;
    let _lock = super::evidence_lock::EvidenceLock::acquire_until(
        &directory.join("shell-tracking.lock"),
        Some(deadline),
    )?;
    let (session, call) = match (identity(session), identity(call)) {
        (Ok(session), Ok(call)) => (session, call),
        _ => {
            let mut state = read_state(&directory)?.unwrap_or(State {
                version: 1,
                root: root.to_path_buf(),
                session: String::new(),
                call: String::new(),
                command_hash: String::new(),
                outstanding: Vec::new(),
                overflowed: true,
                invalid: true,
                before: None,
            });
            if !state.session.is_empty() {
                record_issue(
                    root,
                    Some(&state.session),
                    "an uncorrelated shell call overlapped tracking",
                );
            }
            // An executing call with no usable identity cannot be safely drained.
            state.overflowed = true;
            state.invalid = true;
            state.before = None;
            write_state(&directory, &state)?;
            return Err("shell tracking requires bounded session and tool-use identities; review and reset tracking after all calls finish".to_string());
        }
    };
    let command_hash = format!("{:x}", Sha256::digest(command.as_bytes()));
    let key = (session.to_string(), call.to_string(), command_hash.clone());
    let previous = read_state(&directory)?;
    let new_session = previous
        .as_ref()
        .is_none_or(|state| state.session != session);
    if let Some(mut state) = previous {
        if !state.outstanding.is_empty()
            || state.overflowed
            || (state.session == session && state.invalid)
        {
            record_issue(
                root,
                Some(&state.session),
                "shell tracking window overlapped or remained incomplete",
            );
            state.invalid = true;
            if state.outstanding.len() < 64 && !state.outstanding.contains(&key) {
                state.outstanding.push(key);
            } else {
                state.overflowed = true;
            }
            state.before = None;
            write_state(&directory, &state)?;
            return Err("shell tracking window overlapped or remained incomplete; start a new session after shell calls finish".to_string());
        }
        if state.session == session && state.call == call {
            return Err("shell tool-use identity was reused".to_string());
        }
    }
    let mut state = State {
        version: 1,
        root: root.to_path_buf(),
        session: session.to_string(),
        call: call.to_string(),
        command_hash,
        outstanding: vec![key],
        overflowed: false,
        invalid: true,
        before: None,
    };
    // Persist uncertainty first so a failed snapshot cannot establish a clean pair.
    write_state(&directory, &state)?;
    let before = snapshot::capture(root, deadline)?;
    capture_baseline(
        root,
        session,
        before.files.keys().cloned().collect(),
        new_session,
    )?;
    state.before = Some(before);
    state.invalid = false;
    write_state(&directory, &state)
}

pub(super) fn finish(
    root: &Path,
    session: Option<&str>,
    call: Option<&str>,
    command: &str,
) -> Result<Vec<String>, String> {
    let result = finish_inner(root, session, call, command);
    if let Err(reason) = &result {
        record_issue(root, session, reason);
    }
    result
}

fn finish_inner(
    root: &Path,
    session: Option<&str>,
    call: Option<&str>,
    command: &str,
) -> Result<Vec<String>, String> {
    let deadline = Instant::now() + SNAPSHOT_TIMEOUT;
    let directory = directory(root)?;
    let _lock = super::evidence_lock::EvidenceLock::acquire_until(
        &directory.join("shell-tracking.lock"),
        Some(deadline),
    )?;
    let mut state =
        read_state(&directory)?.ok_or("shell result has no matching pre-tool snapshot")?;
    let key = (
        session.unwrap_or_default().to_string(),
        call.unwrap_or_default().to_string(),
        format!("{:x}", Sha256::digest(command.as_bytes())),
    );
    let matches = state.root == root
        && Some(state.session.as_str()) == session
        && Some(state.call.as_str()) == call
        && state.command_hash == format!("{:x}", Sha256::digest(command.as_bytes()))
        && state.outstanding == [key.clone()]
        && !state.overflowed
        && !state.invalid;
    if !matches {
        record_issue(
            root,
            Some(&state.session),
            "shell result did not match the pending tool call",
        );
        state.invalid = true;
        state.outstanding.retain(|outstanding| outstanding != &key);
        state.before = None;
        write_state(&directory, &state)?;
        return Err("shell result did not match the pending tool call".to_string());
    }
    state.invalid = true;
    write_state(&directory, &state)?;
    let before = state.before.as_ref().ok_or("shell snapshot is missing")?;
    let after = snapshot::capture(root, deadline)?;
    let changed = snapshot::changed(root, before, &after, deadline)?;
    for path in &changed {
        let result = tracking_result(
            Status::Passed,
            "File state changed during the matched shell call.",
            TOUCH_CHECK,
        );
        super::post_tool_use::append_tracking_evidence(root, session, Some(path), &result)?;
    }
    // Attribution is committed only after every touch record was persisted.
    state.outstanding.clear();
    state.invalid = false;
    state.before = None;
    write_state(&directory, &state)?;
    Ok(changed)
}

pub(super) fn observe_edit(root: &Path, session: Option<&str>) {
    let result = (|| -> Result<(), String> {
        let directory = directory(root)?;
        let _lock =
            super::evidence_lock::EvidenceLock::acquire(&directory.join("shell-tracking.lock"))?;
        if let Some(mut state) = read_state(&directory)?
            && !state.outstanding.is_empty()
        {
            record_issue(
                root,
                Some(&state.session),
                "an edit hook overlapped the shell tracking window",
            );
            state.invalid = true;
            write_state(&directory, &state)?;
        }
        Ok(())
    })();
    if let Err(reason) = result {
        record_issue(root, session, &reason);
    }
}

pub(super) fn issue(root: &Path, session: Option<&str>) -> Result<Option<String>, String> {
    let path = root.join(".lgtm/evidence");
    if !path.exists() {
        return Ok(None);
    }
    let directory = directory(root)?;
    let _lock =
        super::evidence_lock::EvidenceLock::acquire(&directory.join("shell-tracking.lock"))?;
    let Some(state) = read_state(&directory)? else {
        return Ok(None);
    };
    Ok((state.overflowed || !state.outstanding.is_empty() || (Some(state.session.as_str()) == session && state.invalid))
        .then(|| "Shell change tracking is incomplete or ambiguous; finish outstanding calls and start a new session.".to_string()))
}

pub(super) fn record_issue(root: &Path, session: Option<&str>, reason: &str) {
    let session = session.filter(|value| identity(Some(value)).is_ok());
    let result = tracking_result(Status::Unverified, reason, "shell.tracking");
    if let Err(error) = super::post_tool_use::append_tracking_evidence(root, session, None, &result)
    {
        eprintln!("shell tracking evidence failed: {error}");
    }
    eprintln!("shell change tracking unverified: {reason}");
}

fn tracking_result(status: Status, message: &str, check: &str) -> EnforcementResult {
    EnforcementResult {
        rule_id: RULE.to_string(),
        status,
        severity: Severity::Error,
        message: message.to_string(),
        locations: Vec::new(),
        remediation: None,
        evidence: ResultEvidence {
            check: check.to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

pub(super) fn is_deleted_path(root: &Path, path: &str) -> bool {
    let relative = Path::new(path);
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return false;
    }
    let candidate = root.join(relative);
    if !matches!(std::fs::symlink_metadata(&candidate), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return false;
    }
    for ancestor in candidate
        .ancestors()
        .skip(1)
        .take_while(|path| *path != root)
    {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return false,
        }
    }
    true
}

fn identity(value: Option<&str>) -> Result<&str, String> {
    value
        .filter(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            "shell tracking requires bounded session and tool-use identities".to_string()
        })
}

fn directory(root: &Path) -> Result<PathBuf, String> {
    if !cfg!(unix) {
        return Err("shell tracking requires supported evidence locking".to_string());
    }
    let parent = root.join(".lgtm");
    crate::fsutil::ensure_directory(&parent).map_err(|error| error.to_string())?;
    let directory = parent.join("evidence");
    crate::fsutil::ensure_directory(&directory).map_err(|error| error.to_string())?;
    Ok(directory)
}

fn read_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
        Ok(metadata) if !metadata.is_file() => {
            return Err("tracking state is not a regular file".to_string());
        }
        Ok(_) => {}
    }
    let file = crate::fsutil::open_regular_file(path)
        .map_err(|error| error.to_string())?
        .ok_or("tracking state became unavailable")?;
    let mut bytes = Vec::new();
    file.take(STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > STATE_BYTES {
        return Err("tracking state exceeds its size bound".to_string());
    }
    Ok(Some(bytes))
}

fn read_state(directory: &Path) -> Result<Option<State>, String> {
    read_bytes(&directory.join("shell-tracking.json"))?
        .map(|bytes| {
            let state: State = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            if state.version != 1 {
                return Err("unsupported shell tracking version".to_string());
            }
            Ok(state)
        })
        .transpose()
}

fn write_state(directory: &Path, state: &State) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    write_atomic(&directory.join("shell-tracking.json"), &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > STATE_BYTES {
        return Err("tracking state exceeds its size bound".to_string());
    }
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|error| error.to_string())?;
    let result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err()
        && let Err(error) = std::fs::remove_file(&temp)
    {
        eprintln!("shell tracking temporary cleanup failed: {error}");
    }
    result.map_err(|error| error.to_string())
}

fn capture_baseline(
    root: &Path,
    session: &str,
    files: BTreeSet<String>,
    new_session: bool,
) -> Result<(), String> {
    let path = root.join(".lgtm/evidence/current-task.baseline.json");
    if let Some(bytes) = read_bytes(&path)? {
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if value.get("session_id").and_then(serde_json::Value::as_str) == Some(session) {
            let previous = value
                .get("diff_files_before")
                .and_then(serde_json::Value::as_array)
                .ok_or("existing session diff baseline is unverified")?;
            if previous.iter().all(serde_json::Value::is_string) {
                return Ok(());
            }
            return Err("existing session diff baseline is malformed".to_string());
        }
    }
    if !new_session {
        return Err(
            "existing shell session baseline is missing or belongs to another session".to_string(),
        );
    }
    let bytes =
        serde_json::to_vec(&serde_json::json!({"session_id":session,"diff_files_before":files}))
            .map_err(|error| error.to_string())?;
    write_atomic(&path, &bytes)
}
