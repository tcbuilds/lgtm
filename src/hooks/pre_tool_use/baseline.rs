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
    let diff_files_before = initial_diff_files(&final_path, root, session_id);
    let value = json!({
        "session_id": session_id,
        "target": target.strip_prefix(root).unwrap_or(target),
        "existed": target.is_file(),
        "content_bytes": content.len(),
        "content_identity": content_identity(content.as_bytes()),
        "context_identity": compiled.plan.context_identity,
        "rule_ids": compiled.plan.rule_ids,
        "checks": compiled.plan.checks,
        "diff_files_before": diff_files_before,
    });
    write_atomic(
        &temp,
        &final_path,
        &serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    )
}

fn initial_diff_files(path: &Path, root: &Path, session_id: Option<&str>) -> Option<Vec<String>> {
    let raw = read_optional_bounded(path, MAX_BASELINE_FILE_BYTES);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
        let recorded = value.get("session_id").and_then(|value| value.as_str());
        if recorded == session_id
            && let Some(files) = value
                .get("diff_files_before")
                .and_then(|value| value.as_array())
        {
            return files
                .iter()
                .map(|file| {
                    file.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| "baseline diff file is not a string".to_string())
                })
                .collect::<Result<Vec<_>, _>>()
                .ok();
        }
    }
    crate::checks::diff::changed_files(root)
        .ok()
        .map(|files| files.into_iter().collect())
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::compile::{CompiledInstructions, EnforcementPlan};

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("lgtm-pre-baseline-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        root
    }

    fn compiled() -> CompiledInstructions {
        CompiledInstructions {
            packet: "packet".to_string(),
            plan: EnforcementPlan {
                context_identity: "context".to_string(),
                rule_ids: vec!["rule".to_string()],
                checks: vec!["check".to_string()],
                evidence_required: vec!["evidence".to_string()],
            },
        }
    }

    #[test]
    fn capture_records_content_and_compiled_plan() {
        let root = temp_root("capture");
        let target = root.join("src/file.py");
        std::fs::create_dir_all(target.parent().expect("target parent")).expect("parent");
        std::fs::write(&target, "value = 1\n").expect("target");
        capture(&root, &target, Some("session-1"), &compiled()).expect("capture");
        let raw = std::fs::read_to_string(root.join(".lgtm/evidence/current-task.baseline.json"))
            .expect("baseline");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON baseline");
        assert_eq!(value["session_id"], "session-1");
        assert_eq!(value["target"], "src/file.py");
        assert_eq!(value["existed"], true);
        assert_eq!(value["content_bytes"], 10);
        assert_eq!(value["content_identity"], content_identity(b"value = 1\n"));
        assert_eq!(value["context_identity"], "context");
        assert_eq!(value["rule_ids"], serde_json::json!(["rule"]));
        assert_eq!(value["checks"], serde_json::json!(["check"]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn capture_records_missing_target_and_sanitizes_session() {
        let root = temp_root("missing");
        let target = root.join("new.py");
        capture(&root, &target, Some("../bad session"), &compiled()).expect("capture");
        let raw = std::fs::read_to_string(root.join(".lgtm/evidence/current-task.baseline.json"))
            .expect("baseline");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON baseline");
        assert_eq!(value["session_id"], "../bad session");
        assert_eq!(value["existed"], false);
        assert_eq!(value["content_bytes"], 0);
        assert_eq!(value["content_identity"], content_identity(&[]));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn capture_keeps_content_at_the_baseline_limit() {
        let root = temp_root("limit");
        let target = root.join("large.py");
        let content = "a".repeat(256 * 1_024);
        std::fs::write(&target, &content).expect("target");
        capture(&root, &target, None, &compiled()).expect("capture");
        let raw = std::fs::read_to_string(root.join(".lgtm/evidence/current-task.baseline.json"))
            .expect("baseline");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("JSON baseline");
        assert_eq!(value["content_bytes"], content.len());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn initial_diff_files_reuses_matching_session_baseline() {
        let root = temp_root("diff");
        let path = root.join("baseline.json");
        std::fs::write(
            &path,
            r#"{"session_id":"session","diff_files_before":["before.py"]}"#,
        )
        .expect("baseline");
        assert_eq!(
            initial_diff_files(&path, &root, Some("session")),
            Some(vec!["before.py".to_string()])
        );
        assert_eq!(initial_diff_files(&path, &root, Some("other")), None);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn session_sanitization_has_bounded_fallbacks() {
        assert_eq!(sanitize_session(None), "unknown");
        assert_eq!(sanitize_session(Some("../")), "unknown");
        assert_eq!(sanitize_session(Some("a-b_c1")), "a-b_c1");
        assert_eq!(sanitize_session(Some(&"a".repeat(65))).len(), 64);
    }

    #[test]
    fn content_identity_is_deterministic_for_empty_and_nonempty_content() {
        assert_eq!(content_identity(&[]), "fnv1a64-cbf29ce484222325");
        assert_eq!(content_identity(b"a"), "fnv1a64-af63dc4c8601ec8c");
        assert_ne!(content_identity(b"a"), content_identity(b"b"));
    }

    #[cfg(unix)]
    #[test]
    fn capture_rejects_a_symlinked_evidence_ancestor() {
        let root = temp_root("symlink");
        let outside = temp_root("symlink-outside");
        std::os::unix::fs::symlink(&outside, root.join(".lgtm")).expect("symlink fixture");
        let result = reject_symlink(&root.join(".lgtm/evidence"));
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }
}
