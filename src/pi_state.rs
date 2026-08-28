//! Bounded, runtime-backed Pi installation and enforcement state.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PI_VERSION: &str = "0.84.3";
const MAX_EXTENSION_BYTES: u64 = 1024 * 1024;
const MAX_ATTESTATION_BYTES: u64 = 64 * 1024;
const MAX_SESSION_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SESSION_LINE_BYTES: u64 = 256 * 1024;
#[cfg(test)]
const MAX_SESSION_TAIL_BYTES: u64 = 256 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const FRESHNESS_WINDOW_MS: u128 = 10 * 60 * 1000;
const ATTESTATION_FILE: &str = ".lgtm/evidence/pi-attestation.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PiEnforcementState {
    NotInstalled,
    InstalledUnloadable,
    ProjectUntrusted,
    ToolContractUnverified,
    #[serde(rename = "stale/unverified")]
    StaleUnverified,
    Active,
}

impl PiEnforcementState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not-installed",
            Self::InstalledUnloadable => "installed-unloadable",
            Self::ProjectUntrusted => "project-untrusted",
            Self::ToolContractUnverified => "tool-contract-unverified",
            Self::StaleUnverified => "stale/unverified",
            Self::Active => "active",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiStateReport {
    pub state: PiEnforcementState,
    pub scope: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiAttestation {
    pub schema_version: u32,
    pub scope: String,
    pub extension_digest: String,
    pub lgtm_version: String,
    pub pi_version: String,
    pub trusted: bool,
    pub tool_contracts_verified: bool,
    pub session_file: Option<String>,
    pub session_id: String,
    pub session_entry_id: Option<String>,
    pub runtime_marker_position: u64,
    pub runtime_nonce: String,
    pub binary_digest: String,
    pub recorded_at_ms: u128,
}

#[derive(Debug)]
struct StaticExtension {
    scope: String,
    digest: String,
    binary: PathBuf,
    binary_digest: String,
    pi_version: String,
}

pub fn assess(root: &Path) -> PiStateReport {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let resolved = resolve_initialized_root(root)
        .unwrap_or_else(|| root.canonicalize().unwrap_or_else(|_| root.to_path_buf()));
    assess_at(&resolved, home.as_deref(), now_ms())
}

pub fn assess_at(root: &Path, home: Option<&Path>, now: u128) -> PiStateReport {
    assess_at_for_session(root, home, now, None)
}

pub fn assess_for_session(root: &Path, session_id: &str) -> PiStateReport {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let resolved = resolve_initialized_root(root)
        .unwrap_or_else(|| root.canonicalize().unwrap_or_else(|_| root.to_path_buf()));
    assess_at_for_session(&resolved, home.as_deref(), now_ms(), Some(session_id))
}

pub fn assess_at_for_session(
    root: &Path,
    home: Option<&Path>,
    now: u128,
    requested_session_id: Option<&str>,
) -> PiStateReport {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let attestation_result = read_attestation(&root);
    let preferred_scope = attestation_result
        .as_ref()
        .ok()
        .and_then(|attestation| attestation.as_ref())
        .map(|attestation| attestation.scope.as_str());
    let Some((path, expected_scope)) = select_extension(&root, home, preferred_scope) else {
        return report(
            PiEnforcementState::NotInstalled,
            None,
            "no Pi extension installed",
        );
    };
    let scope = expected_scope.to_string();
    let extension = match inspect_extension(&path, expected_scope) {
        Ok(extension) => extension,
        Err(reason) => {
            return report(
                PiEnforcementState::InstalledUnloadable,
                Some(scope),
                &reason,
            );
        }
    };
    let attestation = match attestation_result {
        Ok(Some(attestation)) => attestation,
        Ok(None) => {
            return report(
                PiEnforcementState::StaleUnverified,
                Some(scope),
                "runtime attestation is missing",
            );
        }
        Err(reason) => {
            return report(PiEnforcementState::StaleUnverified, Some(scope), &reason);
        }
    };
    if attestation.schema_version != 1
        || attestation.scope != extension.scope
        || attestation.extension_digest != extension.digest
        || attestation.binary_digest != extension.binary_digest
        || attestation.lgtm_version != env!("CARGO_PKG_VERSION")
        || attestation.pi_version != PI_VERSION
        || extension.pi_version != PI_VERSION
    {
        return report(
            PiEnforcementState::StaleUnverified,
            Some(scope),
            "runtime versions, extension bytes, or executable bytes changed",
        );
    }
    if attestation.recorded_at_ms > now
        || now.saturating_sub(attestation.recorded_at_ms) > FRESHNESS_WINDOW_MS
    {
        return report(
            PiEnforcementState::StaleUnverified,
            Some(scope),
            "runtime attestation is stale",
        );
    }
    if let Err(reason) = validate_policy_files(&root) {
        return report(PiEnforcementState::StaleUnverified, Some(scope), &reason);
    }
    if !attestation.trusted {
        return report(
            PiEnforcementState::ProjectUntrusted,
            Some(scope),
            "Pi runtime trust is not confirmed",
        );
    }
    if !attestation.tool_contracts_verified {
        return report(
            PiEnforcementState::ToolContractUnverified,
            Some(scope),
            "Pi built-in tool contracts are unverified",
        );
    }
    if requested_session_id.is_some_and(|session_id| attestation.session_id != session_id) {
        return report(
            PiEnforcementState::StaleUnverified,
            Some(scope),
            "Pi runtime attestation belongs to another session",
        );
    }
    if !session_proves_current_runtime(&attestation) {
        return report(
            PiEnforcementState::StaleUnverified,
            Some(scope),
            "Pi session evidence is missing or unverified",
        );
    }
    if !extension.binary.is_file() {
        return report(
            PiEnforcementState::InstalledUnloadable,
            Some(scope),
            "embedded LGTM binary is missing",
        );
    }
    report(
        PiEnforcementState::Active,
        Some(scope),
        "fresh trusted Pi runtime attestation is current",
    )
}

pub fn record_attestation(root: &Path, payload: &Value) -> Result<(), String> {
    let scope = string_field(payload, "scope")?;
    let trusted = bool_field(payload, "trusted")?;
    let tool_contracts_verified = bool_field(payload, "toolContractsVerified")?;
    let pi_version = string_field(payload, "piVersion")?;
    let session_id = string_field(payload, "sessionId")?;
    if session_id.is_empty() || session_id.len() > 256 {
        return Err("Pi session id is missing or invalid".to_string());
    }
    let session_file = optional_string_field(payload, "sessionFile")?;
    if session_file
        .as_deref()
        .is_some_and(|path| !Path::new(path).is_absolute())
    {
        return Err("attested Pi session path must be absolute".to_string());
    }
    let session_entry_id = optional_string_field(payload, "sessionEntryId")?;
    if session_entry_id.as_deref().is_some_and(str::is_empty) {
        return Err("attested Pi session entry id must not be empty".to_string());
    }
    let runtime_marker_position = payload
        .get("runtimeMarkerPosition")
        .and_then(Value::as_u64)
        .ok_or_else(|| "attestation runtime marker position is missing or invalid".to_string())?;
    let runtime_nonce = string_field(payload, "runtimeNonce")?;
    if runtime_nonce.is_empty() || runtime_nonce.len() > 128 {
        return Err("runtime attestation nonce is missing or invalid".to_string());
    }
    let loaded_binary_digest = string_field(payload, "binaryDigest")?;
    if loaded_binary_digest.len() != 64
        || !loaded_binary_digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("loaded LGTM binary digest is missing or invalid".to_string());
    }
    if !matches!(scope.as_str(), "project" | "global") {
        return Err("attestation scope is unsupported".to_string());
    }
    if pi_version != PI_VERSION {
        return Err("Pi runtime version is unsupported".to_string());
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let root =
        resolve_initialized_root(root).ok_or_else(|| "resolve initialized Pi root".to_string())?;
    validate_policy_files(&root)?;
    let expected_scope = scope.as_str();
    let path = extension_for_scope(&root, home.as_deref(), expected_scope)?;
    let extension = inspect_extension(&path, expected_scope)?;
    if loaded_binary_digest != extension.binary_digest {
        return Err("loaded LGTM binary differs from the installed extension".to_string());
    }
    let attestation = PiAttestation {
        schema_version: 1,
        scope,
        extension_digest: extension.digest,
        lgtm_version: env!("CARGO_PKG_VERSION").to_string(),
        pi_version,
        trusted,
        tool_contracts_verified,
        session_file,
        session_id,
        session_entry_id,
        runtime_marker_position,
        runtime_nonce,
        binary_digest: loaded_binary_digest,
        recorded_at_ms: now_ms(),
    };
    if !session_proves_current_runtime(&attestation) {
        return Err("Pi session evidence is missing or unverified".to_string());
    }
    let bytes = serde_json::to_vec_pretty(&attestation)
        .map_err(|error| format!("serialize Pi attestation ({error})"))?;
    if bytes.len() as u64 > MAX_ATTESTATION_BYTES {
        return Err("Pi attestation exceeds maximum size".to_string());
    }
    write_attestation(&root, &bytes)
}

fn extension_for_scope(root: &Path, home: Option<&Path>, scope: &str) -> Result<PathBuf, String> {
    let path = match scope {
        "project" => root.join(".pi/extensions/lgtm.ts"),
        "global" => home
            .ok_or_else(|| "HOME is unavailable for global Pi attestation".to_string())?
            .join(".pi/agent/extensions/lgtm.ts"),
        _ => return Err("attestation scope is unsupported".to_string()),
    };
    if path_exists(&path) {
        Ok(path)
    } else {
        Err("Pi extension is not installed".to_string())
    }
}

fn select_extension(
    root: &Path,
    home: Option<&Path>,
    preferred_scope: Option<&str>,
) -> Option<(PathBuf, &'static str)> {
    let project = root.join(".pi/extensions/lgtm.ts");
    let global = home.map(|home| home.join(".pi/agent/extensions/lgtm.ts"));
    if preferred_scope == Some("global") && global.as_deref().is_some_and(path_exists) {
        return global.map(|path| (path, "global"));
    }
    if preferred_scope == Some("project") && path_exists(&project) {
        return Some((project.clone(), "project"));
    }
    if path_exists(&project)
        && extension_claims_lgtm(&project)
        && (inspect_extension(&project, "project").is_ok()
            || global.as_deref().is_none_or(|path| !path_exists(path)))
    {
        return Some((project, "project"));
    }
    global.and_then(|path| {
        (path_exists(&path) && extension_claims_lgtm(&path)).then_some((path, "global"))
    })
}

fn extension_claims_lgtm(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return true;
    }
    if !metadata.is_file() || metadata.len() > MAX_EXTENSION_BYTES {
        return false;
    }
    fs::read_to_string(path)
        .map(|contents| contents.contains("lgtm-pi-extension:"))
        .unwrap_or(false)
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn inspect_extension(path: &Path, expected_scope: &str) -> Result<StaticExtension, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("inspect Pi extension ({error})"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Pi extension is not a regular file".to_string());
    }
    if metadata.len() > MAX_EXTENSION_BYTES {
        return Err("Pi extension exceeds maximum size".to_string());
    }
    let contents =
        fs::read_to_string(path).map_err(|error| format!("read Pi extension ({error})"))?;
    if !contents.contains("// lgtm-pi-extension: v1")
        || !contents.contains("// lgtm-pi-extension: end")
        || !contents.contains(&format!("// lgtm-pi-scope: {expected_scope}"))
    {
        return Err("Pi extension ownership or scope markers are invalid".to_string());
    }
    let template_scope = match expected_scope {
        "project" => crate::init::pi::ExtensionScope::Project,
        "global" => crate::init::pi::ExtensionScope::Global,
        _ => return Err("Pi extension scope is unsupported".to_string()),
    };
    let expected_digest = crate::init::pi::expected_template_digest(template_scope);
    if digest(&crate::init::pi::normalize_for_attestation(&contents)) != expected_digest
        || parse_const_path(&contents, "const TEMPLATE_DIGEST = ")? != expected_digest
        || parse_const_path(&contents, "const PROJECT_TEMPLATE_DIGEST = ")?
            != crate::init::pi::expected_template_digest(crate::init::pi::ExtensionScope::Project)
    {
        return Err("Pi extension does not match the canonical LGTM template".to_string());
    }
    let binary = parse_const_path(&contents, "const LGTM_BINARY = ")?;
    let binary = PathBuf::from(binary);
    if !binary.is_absolute() {
        return Err("Pi extension embeds a non-absolute LGTM binary".to_string());
    }
    let pi_version = parse_const_path(&contents, "const PI_VERSION = ")?;
    let binary_metadata =
        fs::symlink_metadata(&binary).map_err(|_| "embedded LGTM binary is missing".to_string())?;
    if binary_metadata.file_type().is_symlink() || !binary_metadata.is_file() {
        return Err("embedded LGTM binary is not a regular file".to_string());
    }
    #[cfg(unix)]
    if binary_metadata.permissions().mode() & 0o111 == 0 {
        return Err("embedded LGTM binary is not executable".to_string());
    }
    let binary_digest = digest_file(&binary)?;
    parse_const_path(&contents, "const BINARY_DIGEST = ")?;
    Ok(StaticExtension {
        scope: expected_scope.to_string(),
        digest: digest(&contents),
        binary,
        binary_digest,
        pi_version,
    })
}

fn parse_const_path(contents: &str, prefix: &str) -> Result<String, String> {
    let line = contents
        .lines()
        .find(|line| line.trim_start().starts_with(prefix))
        .ok_or_else(|| format!("Pi extension is missing {prefix}"))?;
    let value = line
        .trim_start()
        .strip_prefix(prefix)
        .and_then(|value| value.trim().strip_suffix(';'))
        .ok_or_else(|| format!("Pi extension has malformed {prefix}"))?;
    serde_json::from_str(value).map_err(|_| format!("Pi extension has malformed {prefix}"))
}

fn digest_file(path: &Path) -> Result<String, String> {
    let Some(mut file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open executable ({error})"))?
    else {
        return Err("embedded LGTM binary is missing".to_string());
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect executable ({error})"))?;
    if metadata.len() > MAX_BINARY_BYTES {
        return Err("embedded LGTM binary exceeds maximum size".to_string());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read executable ({error})"))?;
    Ok(digest_bytes(&bytes))
}

pub(crate) fn validate_policy_files(root: &Path) -> Result<(), String> {
    crate::hooks::pre_tool_use::validate_policy_files(root)
}

fn read_attestation(root: &Path) -> Result<Option<PiAttestation>, String> {
    let path = root.join(ATTESTATION_FILE);
    let Some(file) = crate::fsutil::open_regular_file(&path)
        .map_err(|error| format!("open Pi attestation ({error})"))?
    else {
        return Ok(None);
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect Pi attestation ({error})"))?;
    if metadata.len() > MAX_ATTESTATION_BYTES {
        return Err("Pi attestation exceeds maximum size".to_string());
    }
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|error| format!("parse Pi attestation ({error})"))
}

fn write_attestation(root: &Path, bytes: &[u8]) -> Result<(), String> {
    let lgtm_directory = root.join(".lgtm");
    ensure_directory(&lgtm_directory)?;
    let directory = lgtm_directory.join("evidence");
    ensure_directory(&directory)?;
    let path = directory.join("pi-attestation.json");
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err("Pi attestation path is not a regular file".to_string());
    }
    let temporary = directory.join(format!("pi-attestation.json.tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("stage Pi attestation ({error})"))?;
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
    {
        let _ = fs::remove_file(&temporary);
        return Err(format!("write Pi attestation ({error})"));
    }
    if let Err(error) = fs::rename(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("commit Pi attestation ({error})"));
    }
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(format!("{} is not a regular directory", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| format!("create {} ({error})", path.display()))
        }
        Err(error) => Err(format!("inspect {} ({error})", path.display())),
    }
}

// The marker proves extension execution, not cryptographic authenticity; a local user
// who can rewrite Pi's session log can still forge runtime evidence.
fn session_proves_current_runtime(attestation: &PiAttestation) -> bool {
    let Some(path) = attestation.session_file.as_deref() else {
        return false;
    };
    let Some(entry_id) = attestation.session_entry_id.as_deref() else {
        return false;
    };
    let path = Path::new(path);
    let Ok(Some(mut file)) = crate::fsutil::open_regular_file(path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if attestation.runtime_marker_position > MAX_SESSION_SCAN_BYTES
        || attestation.runtime_marker_position >= metadata.len()
        || metadata
            .len()
            .saturating_sub(attestation.runtime_marker_position)
            > MAX_SESSION_SCAN_BYTES
        || file
            .seek(SeekFrom::Start(attestation.runtime_marker_position))
            .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(file);
    let mut marker_line = Vec::new();
    if reader
        .by_ref()
        .take(MAX_SESSION_LINE_BYTES + 1)
        .read_until(b'\n', &mut marker_line)
        .is_err()
    {
        return false;
    }
    let Some(newline) = marker_line
        .last()
        .is_some_and(|byte| *byte == b'\n')
        .then_some(marker_line.len() - 1)
    else {
        return false;
    };
    if newline as u64 > MAX_SESSION_LINE_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&marker_line[..newline]) else {
        return false;
    };
    let marker_valid = value.get("id").and_then(Value::as_str) == Some(entry_id)
        && value.get("customType").and_then(Value::as_str) == Some("lgtm-runtime")
        && value
            .get("data")
            .and_then(|data| data.get("nonce"))
            .and_then(Value::as_str)
            == Some(attestation.runtime_nonce.as_str())
        && value
            .get("data")
            .and_then(|data| data.get("sessionId"))
            .and_then(Value::as_str)
            == Some(attestation.session_id.as_str())
        && value
            .get("data")
            .and_then(|data| data.get("extensionDigest"))
            .and_then(Value::as_str)
            == Some(
                crate::init::pi::expected_template_digest(match attestation.scope.as_str() {
                    "project" => crate::init::pi::ExtensionScope::Project,
                    "global" => crate::init::pi::ExtensionScope::Global,
                    _ => return false,
                })
                .as_str(),
            )
        && value
            .get("data")
            .and_then(|data| data.get("scope"))
            .and_then(Value::as_str)
            == Some(attestation.scope.as_str())
        && value
            .get("data")
            .and_then(|data| data.get("binaryDigest"))
            .and_then(Value::as_str)
            == Some(attestation.binary_digest.as_str());
    if !marker_valid {
        return false;
    }
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_SESSION_LINE_BYTES + 1)
            .read_until(b'\n', &mut line);
        let Ok(read) = read else {
            return false;
        };
        if read == 0 {
            return true;
        }
        let Some(newline) = line
            .last()
            .is_some_and(|byte| *byte == b'\n')
            .then_some(line.len() - 1)
        else {
            return false;
        };
        if newline == 0 {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&line[..newline]) else {
            return false;
        };
        if value.get("customType").and_then(Value::as_str) == Some("lgtm")
            && value
                .get("data")
                .and_then(|data| data.get("reason"))
                .is_some()
        {
            return false;
        }
    }
}

fn report(state: PiEnforcementState, scope: Option<String>, reason: &str) -> PiStateReport {
    PiStateReport {
        state,
        scope,
        reason: reason.to_string(),
    }
}

fn string_field(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("attestation field {key} is missing or not a string"))
}

fn optional_string_field(value: &Value, key: &str) -> Result<Option<String>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| format!("attestation field {key} is not a string")),
    }
}

fn bool_field(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("attestation field {key} is missing or not a boolean"))
}

fn resolve_initialized_root(path: &Path) -> Option<PathBuf> {
    let mut current = path.canonicalize().ok()?;
    loop {
        if let Ok(metadata) = fs::symlink_metadata(current.join(".lgtm/config.json"))
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
        {
            return Some(current);
        }
        let parent = current.parent()?.to_path_buf();
        if parent == current {
            return None;
        }
        current = parent;
    }
}

fn digest(contents: &str) -> String {
    digest_bytes(contents.as_bytes())
}

fn digest_bytes(contents: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contents);
    format!("{:x}", hasher.finalize())
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lgtm-pi-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("temp root");
        path
    }

    fn extension(root: &Path) {
        let path = root.join(".pi/extensions/lgtm.ts");
        fs::create_dir_all(path.parent().expect("extension parent")).expect("extension parent");
        let binary = std::env::current_exe().expect("test binary path");
        let contents = crate::init::pi::render(
            &binary.to_string_lossy(),
            crate::init::pi::ExtensionScope::Project,
        )
        .expect("render extension");
        fs::write(path, contents).expect("extension");
    }

    #[test]
    fn global_attestation_scope_uses_global_extension_with_project_present() {
        let root = temp_root();
        let home = temp_root();
        let project = root.join(".pi/extensions/lgtm.ts");
        let global = home.join(".pi/agent/extensions/lgtm.ts");
        fs::create_dir_all(project.parent().expect("project parent")).expect("project parent");
        fs::create_dir_all(global.parent().expect("global parent")).expect("global parent");
        fs::write(
            &project,
            crate::init::pi::render("/bin/sh", crate::init::pi::ExtensionScope::Project)
                .expect("project extension"),
        )
        .expect("project extension writes");
        fs::write(
            &global,
            crate::init::pi::render("/bin/sh", crate::init::pi::ExtensionScope::Global)
                .expect("global extension"),
        )
        .expect("global extension writes");
        assert_eq!(
            extension_for_scope(&root, Some(&home), "global").expect("global extension"),
            global
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn presence_without_runtime_proof_is_stale() {
        let root = temp_root();
        extension(&root);
        assert_eq!(
            assess_at(&root, None, now_ms()).state,
            PiEnforcementState::StaleUnverified
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn session_tail_skips_initial_partial_jsonl_line() {
        let root = temp_root();
        let session = root.join("session.jsonl");
        let template_digest =
            crate::init::pi::expected_template_digest(crate::init::pi::ExtensionScope::Project);
        let marker = serde_json::json!({
            "id": "leaf",
            "customType": "lgtm-runtime",
            "data": {
                "nonce": "nonce",
                "extensionDigest": template_digest,
                "binaryDigest": "binary",
                "scope": "project",
                "sessionId": "session"
            }
        });
        let mut bytes = vec![b'x'; (MAX_SESSION_TAIL_BYTES + 32) as usize];
        bytes.extend_from_slice(b"\n");
        bytes.extend_from_slice(marker.to_string().as_bytes());
        bytes.push(b'\n');
        fs::write(&session, bytes).expect("session");
        let attestation = PiAttestation {
            schema_version: 1,
            scope: "project".to_string(),
            extension_digest: "digest".to_string(),
            lgtm_version: env!("CARGO_PKG_VERSION").to_string(),
            pi_version: PI_VERSION.to_string(),
            trusted: true,
            tool_contracts_verified: true,
            session_file: Some(session.to_string_lossy().into_owned()),
            session_id: "session".to_string(),
            session_entry_id: Some("leaf".to_string()),
            runtime_marker_position: MAX_SESSION_TAIL_BYTES + 33,
            runtime_nonce: "nonce".to_string(),
            binary_digest: "binary".to_string(),
            recorded_at_ms: 0,
        };
        assert!(session_proves_current_runtime(&attestation));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn session_marker_remains_provable_after_large_valid_suffix() {
        let root = temp_root();
        let session = root.join("long-session.jsonl");
        let template_digest =
            crate::init::pi::expected_template_digest(crate::init::pi::ExtensionScope::Project);
        let marker = serde_json::json!({
            "id": "leaf",
            "customType": "lgtm-runtime",
            "data": {
                "nonce": "nonce",
                "extensionDigest": template_digest,
                "binaryDigest": "binary",
                "scope": "project",
                "sessionId": "session"
            }
        });
        let mut contents = format!("{marker}\n");
        while contents.len() <= (MAX_SESSION_TAIL_BYTES + 32) as usize {
            contents.push_str("{\"type\":\"message\"}\n");
        }
        fs::write(&session, contents).expect("long session");
        let attestation = PiAttestation {
            schema_version: 1,
            scope: "project".to_string(),
            extension_digest: "digest".to_string(),
            lgtm_version: env!("CARGO_PKG_VERSION").to_string(),
            pi_version: PI_VERSION.to_string(),
            trusted: true,
            tool_contracts_verified: true,
            session_file: Some(session.to_string_lossy().into_owned()),
            session_id: "session".to_string(),
            session_entry_id: Some("leaf".to_string()),
            runtime_marker_position: 0,
            runtime_nonce: "nonce".to_string(),
            binary_digest: "binary".to_string(),
            recorded_at_ms: 0,
        };
        assert!(session_proves_current_runtime(&attestation));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_unverified_round_trips_through_evidence_schema_name() {
        let state = PiEnforcementState::StaleUnverified;
        let encoded = serde_json::to_string(&state).expect("state serializes");
        assert_eq!(encoded, "\"stale/unverified\"");
        assert_eq!(
            serde_json::from_str::<PiEnforcementState>(&encoded).expect("state deserializes"),
            state
        );
    }

    #[test]
    fn malformed_or_symlinked_extension_never_becomes_active() {
        let root = temp_root();
        let path = root.join(".pi/extensions/lgtm.ts");
        fs::create_dir_all(path.parent().expect("extension parent")).expect("extension parent");
        fs::write(&path, "// lgtm-pi-extension: v1\n").expect("malformed extension");
        assert_eq!(
            assess_at(&root, None, now_ms()).state,
            PiEnforcementState::InstalledUnloadable
        );
        let _ = fs::remove_dir_all(root);
    }
}
