use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::compile::CompiledInstructions;
use crate::fsutil::read_optional_bounded;

const MAX_BASELINE_FILE_BYTES: u64 = 256 * 1_024;

pub(super) fn capture(
    root: &Path,
    target: &Path,
    session_id: Option<&str>,
    compiled: &CompiledInstructions,
) -> Result<(), String> {
    let directory = root.join(".lgtm/evidence");
    reject_symlink(&directory)?;
    std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let name = sanitize_session(session_id);
    let final_path = directory.join("current-task.baseline.json");
    let temp = directory.join(format!(".{name}.baseline.{}.tmp", std::process::id()));
    let content = read_optional_bounded(target, MAX_BASELINE_FILE_BYTES);
    let value = json!({
        "session_id": session_id,
        "target": target.strip_prefix(root).unwrap_or(target),
        "existed": target.is_file(),
        "content_bytes": content.len(),
        "content_identity": content_identity(content.as_bytes()),
        "context_identity": compiled.plan.context_identity,
        "rule_ids": compiled.plan.rule_ids,
        "checks": compiled.plan.checks,
    });
    write_atomic(
        &temp,
        &final_path,
        &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    )
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors().take(2) {
        if std::fs::symlink_metadata(ancestor)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err("evidence path contains symlink".to_string());
        }
    }
    Ok(())
}

fn write_atomic(temp: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    std::fs::rename(temp, final_path).map_err(|error| error.to_string())
}

fn sanitize_session(session_id: Option<&str>) -> String {
    let value: String = session_id
        .unwrap_or("unknown")
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(64)
        .collect();
    if value.is_empty() {
        "unknown".to_string()
    } else {
        value
    }
}

fn content_identity(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64-{hash:016x}")
}
