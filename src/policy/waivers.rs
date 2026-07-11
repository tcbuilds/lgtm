use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::{Category, Rule};
use crate::checks::{EnforcementResult, Status};

const MAX_BYTES: u64 = 256 * 1024;
const MAX_TEXT: usize = 512;
const MAX_WAIVERS: usize = 64;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    pub rule_id: String,
    pub reason: String,
    pub owner: String,
    pub expires: String,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Store {
    waivers: Vec<Waiver>,
}

pub fn create(
    root: &Path,
    rule_id: &str,
    reason: &str,
    owner: &str,
    expires: &str,
) -> Result<(), String> {
    let rules = super::load_embedded_registry().map_err(|error| error.to_string())?;
    let rule = find_rule(&rules, rule_id)?;
    ensure_waivable(rule)?;
    let waiver = Waiver {
        rule_id: validate_text("rule", rule_id)?,
        reason: validate_text("reason", reason)?,
        owner: validate_text("owner", owner)?,
        expires: validate_future_date(expires)?,
    };
    let path = root.join(".lgtm/waivers.json");
    let mut store = load_store(&path)?;
    store.waivers.retain(|item| item.rule_id != waiver.rule_id);
    store.waivers.push(waiver);
    store
        .waivers
        .sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    validate_store(&store, &rules)?;
    persist(&path, &store)
}

pub fn load_active(root: &Path, rules: &[Rule]) -> Result<Vec<Waiver>, String> {
    let path = root.join(".lgtm/waivers.json");
    let store = load_store(&path)?;
    validate_store(&store, rules)?;
    Ok(store.waivers)
}

pub fn apply(waivers: &[Waiver], results: &mut [EnforcementResult]) {
    for result in results {
        if result.status == Status::Failed
            && waivers
                .iter()
                .any(|waiver| waiver.rule_id == result.rule_id)
        {
            result.status = Status::Waived;
            result.message = format!("{} waived by active repository waiver.", result.rule_id);
            result.remediation = None;
        }
    }
}

fn validate_store(store: &Store, rules: &[Rule]) -> Result<(), String> {
    if store.waivers.len() > MAX_WAIVERS {
        return Err(format!("waivers exceed {MAX_WAIVERS} entries"));
    }
    let mut seen = BTreeSet::new();
    for waiver in &store.waivers {
        if !seen.insert(&waiver.rule_id) {
            return Err(format!("duplicate waiver for rule `{}`", waiver.rule_id));
        }
        ensure_waivable(find_rule(rules, &waiver.rule_id)?)?;
        validate_stored_text("rule", &waiver.rule_id)?;
        validate_stored_text("reason", &waiver.reason)?;
        validate_stored_text("owner", &waiver.owner)?;
        validate_future_date(&waiver.expires)?;
    }
    Ok(())
}

fn validate_stored_text(field: &str, value: &str) -> Result<(), String> {
    if validate_text(field, value)? != value {
        return Err(format!("stored waiver {field} is not normalized"));
    }
    Ok(())
}

fn find_rule<'a>(rules: &'a [Rule], id: &str) -> Result<&'a Rule, String> {
    rules
        .iter()
        .find(|rule| rule.id == id)
        .ok_or_else(|| format!("unknown rule `{}`", sanitize(id)))
}

fn ensure_waivable(rule: &Rule) -> Result<(), String> {
    let protected = rule.category == Category::Security
        || matches!(
            rule.id.as_str(),
            "no-committed-secrets"
                | "sql-parameterization"
                | "destructive-operation-safeguards"
                | "auth-change-security-review"
        );
    if protected {
        Err(format!(
            "rule `{}` is security-critical and cannot be waived",
            rule.id
        ))
    } else {
        Ok(())
    }
}

fn load_store(path: &Path) -> Result<Store, String> {
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open waivers ({error})"))?
    else {
        if path.exists() {
            return Err("waivers path is not a regular file".to_string());
        }
        return Ok(Store::default());
    };
    let mut raw = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read waivers ({error})"))?;
    if raw.len() as u64 > MAX_BYTES {
        return Err("waivers file exceeds maximum size".to_string());
    }
    serde_json::from_str(&raw).map_err(|error| format!("malformed waivers file ({error})"))
}

fn persist(path: &Path, store: &Store) -> Result<(), String> {
    let parent = path.parent().ok_or("waivers path has no parent")?;
    ensure_safe_parent(parent)?;
    let (mut file, temp) = create_temp(path)?;
    let mut cleanup = TempCleanup::new(temp.clone());
    let mut bytes =
        serde_json::to_vec_pretty(store).map_err(|error| format!("serialize waivers ({error})"))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("write waivers ({error})"))?;
    std::fs::rename(&temp, path).map_err(|error| format!("commit waivers ({error})"))?;
    cleanup.committed = true;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync waiver directory ({error})"))
}

fn ensure_safe_parent(parent: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err("waiver directory is not a regular directory".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(parent)
            .map_err(|error| format!("create waiver directory ({error})")),
        Err(error) => Err(format!("inspect waiver directory ({error})")),
    }
}

fn create_temp(path: &Path) -> Result<(std::fs::File, PathBuf), String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let temp = path.with_extension(format!("tmp-{}-{id}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&temp) {
            Ok(file) => return Ok((file, temp)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("create waiver temp ({error})")),
        }
    }
    Err("create waiver temp (too many collisions)".to_string())
}

struct TempCleanup {
    path: PathBuf,
    committed: bool,
}

impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn validate_text(field: &str, value: &str) -> Result<String, String> {
    let clean = sanitize(value.trim());
    if clean.is_empty() || clean.len() > MAX_TEXT {
        return Err(format!("{field} must be 1..={MAX_TEXT} safe characters"));
    }
    Ok(clean)
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

fn validate_future_date(value: &str) -> Result<String, String> {
    let days = parse_date(value)?;
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock predates Unix epoch".to_string())?
        .as_secs()
        / 86_400;
    if days <= today as i64 {
        return Err("waiver expiry must be a future UTC date".to_string());
    }
    Ok(value.to_string())
}

fn parse_date(value: &str) -> Result<i64, String> {
    let parts: Vec<_> = value.split('-').collect();
    if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err("expiry must use YYYY-MM-DD".to_string());
    }
    let year: i64 = parts[0].parse().map_err(|_| "invalid expiry year")?;
    let month: u32 = parts[1].parse().map_err(|_| "invalid expiry month")?;
    let day: u32 = parts[2].parse().map_err(|_| "invalid expiry day")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month) || day == 0 || day > lengths[(month - 1) as usize] {
        return Err("expiry is not a real calendar date".to_string());
    }
    let adjusted = year - i64::from(month <= 2);
    let era = adjusted.div_euclid(400);
    let yoe = adjusted - era * 400;
    let mp = i64::from(month) + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    Ok(era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468)
}

#[cfg(test)]
#[path = "waivers/tests.rs"]
mod tests;
