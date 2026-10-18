//! Track and refresh managed installations without searching unrelated repositories.
//! The registry keeps its original Pi directory name for compatibility.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fs::{
    commit_write, create_private_dir_all, preflight_file_targets, preflight_targets,
    stage_private_write, stage_write,
};
use super::pi::{self, ExtensionScope};
use super::{InitError, read_if_exists};

const MAX_INSTALLATIONS: usize = 4096;
const REFRESH_BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    version: u8,
    target: PathBuf,
    binary: PathBuf,
    global: bool,
    #[serde(default)]
    managed: Option<ManagedInstallation>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedInstallation {
    root: PathBuf,
    agent: String,
    rules_only: bool,
    guidance: Vec<PathBuf>,
    #[serde(default)]
    codex_digest: Option<String>,
}

fn registry(home: &Path) -> PathBuf {
    home.join(".local/state/lgtm/pi-installations")
}

pub(crate) fn register(
    home: &Path,
    target: &Path,
    binary: &str,
    scope: ExtensionScope,
) -> Result<(), InitError> {
    if !home.is_absolute() || !Path::new(binary).is_absolute() {
        return Err(InitError::UnwritableTarget {
            path: target.to_path_buf(),
            reason: "Pi installation HOME and executable must be absolute paths".to_string(),
        });
    }
    preflight_file_targets(&[target])?;
    let target = std::fs::canonicalize(target).map_err(|source| InitError::Read {
        path: target.to_path_buf(),
        source,
    })?;
    let global = scope == ExtensionScope::Global;
    let root = target
        .ancestors()
        .nth(if global { 4 } else { 3 })
        .ok_or_else(|| InitError::UnwritableTarget {
            path: target.clone(),
            reason: "Pi installation has no root".to_string(),
        })?;
    let managed = managed_record(root, super::InitAgent::Pi, global, false);
    persist(
        home,
        Installation {
            version: 1,
            target,
            binary: PathBuf::from(binary),
            global,
            managed: Some(managed),
        },
    )
}

fn managed_record(
    root: &Path,
    agent: super::InitAgent,
    global: bool,
    rules_only: bool,
) -> ManagedInstallation {
    ManagedInstallation {
        root: root.to_path_buf(),
        agent: format!("{agent:?}").to_lowercase(),
        rules_only,
        guidance: super::managed_refresh::guidance_paths(root, agent, global),
        codex_digest: (agent == super::InitAgent::Codex && !global).then(|| {
            format!(
                "{:x}",
                Sha256::digest(super::rules::agents_document().as_bytes())
            )
        }),
    }
}

fn persist(home: &Path, installation: Installation) -> Result<(), InitError> {
    if !home.is_absolute() {
        return Err(InitError::UnwritableTarget {
            path: home.to_path_buf(),
            reason: "installation HOME must be absolute".to_string(),
        });
    }
    let directory = registry(home);
    preflight_targets(home, &[&directory.join("installation.json")])?;
    create_private_dir_all(&directory)?;
    let mut key = Sha256::new();
    key.update(installation.target.as_os_str().as_encoded_bytes());
    if let Some(managed) = &installation.managed {
        key.update(b"\0");
        key.update(managed.agent.as_bytes());
    }
    let path = directory.join(format!("{:x}.json", key.finalize()));
    let bytes = serde_json::to_vec(&installation).map_err(|error| InitError::UnwritableTarget {
        path: path.clone(),
        reason: format!("serialize Pi installation ({error})"),
    })?;
    let existing = read_if_exists(&path)?;
    if existing.as_deref().map(str::as_bytes) == Some(bytes.as_slice()) {
        return Ok(());
    }
    if existing.is_none() {
        require_registry_capacity(&directory)?;
    }
    commit_write(stage_private_write(&path, &bytes)?)
}

/// A full registry needs stale-record cleanup; a stalled scan needs a retry.
fn registry_full_reason(directory: &Path) -> String {
    format!(
        "installation registry limit reached ({MAX_INSTALLATIONS}); move confirmed stale registration files from {} to a backup directory, then retry",
        directory.display()
    )
}

fn registry_timeout_reason(directory: &Path, stage: &str) -> String {
    format!(
        "installation registry {stage} timed out ({}s); retry, then inspect {} for stale registrations if it stays slow",
        REFRESH_BUDGET.as_secs(),
        directory.display()
    )
}

fn require_registry_capacity(directory: &Path) -> Result<(), InitError> {
    let entries = std::fs::read_dir(directory).map_err(|source| InitError::Read {
        path: directory.to_path_buf(),
        source,
    })?;
    let deadline = Instant::now() + REFRESH_BUDGET;
    for (index, entry) in entries.enumerate() {
        entry.map_err(|source| InitError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        if index >= MAX_INSTALLATIONS - 1 {
            return Err(InitError::UnwritableTarget {
                path: directory.to_path_buf(),
                reason: registry_full_reason(directory),
            });
        }
        if Instant::now() >= deadline {
            return Err(InitError::UnwritableTarget {
                path: directory.to_path_buf(),
                reason: registry_timeout_reason(directory, "traversal"),
            });
        }
    }
    Ok(())
}

pub(crate) fn register_adapter(
    root: &Path,
    agent: super::InitAgent,
    rules_only: bool,
) -> Result<(), InitError> {
    let home = std::env::var_os("HOME").ok_or_else(|| InitError::UnwritableTarget {
        path: root.to_path_buf(),
        reason: "HOME is required to track installations".to_string(),
    })?;
    let root = std::fs::canonicalize(root).map_err(|source| InitError::Read {
        path: root.to_path_buf(),
        source,
    })?;
    let target = root.join(match agent {
        super::InitAgent::Claude => {
            if rules_only {
                ".claude/rules"
            } else {
                ".claude/settings.json"
            }
        }
        super::InitAgent::Codex => {
            if rules_only {
                "AGENTS.md"
            } else {
                ".codex/hooks.json"
            }
        }
        super::InitAgent::Pi => {
            if rules_only {
                "AGENTS.md"
            } else {
                ".pi/extensions/lgtm.ts"
            }
        }
    });
    let managed = managed_record(&root, agent, false, rules_only);
    persist(
        Path::new(&home),
        Installation {
            version: 1,
            target,
            binary: PathBuf::from(pi::hook_binary()?),
            global: false,
            managed: Some(managed),
        },
    )
}

pub fn register_rules(root: &Path, agent: super::InitAgent) -> Result<(), String> {
    register_adapter(root, agent, true).map_err(|error| error.to_string())
}

pub(crate) fn register_project(target: &Path, binary: &str) -> Result<(), InitError> {
    let home = std::env::var_os("HOME").ok_or_else(|| InitError::UnwritableTarget {
        path: target.to_path_buf(),
        reason: "HOME is required to track Pi installations".to_string(),
    })?;
    register(Path::new(&home), target, binary, ExtensionScope::Project)
}

/// Refresh registered managed output without redetecting repository policy.
/// Never reinstall removed hooks or files: absence may mean deliberate disablement.
pub fn refresh() -> Result<String, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is required to refresh Pi installations")?;
    let binary =
        std::env::current_exe().map_err(|error| format!("resolve executable ({error})"))?;
    refresh_at(Path::new(&home), &binary)
}

fn refresh_at(home: &Path, binary: &Path) -> Result<String, String> {
    if !home.is_absolute() {
        return Err("Pi installation HOME must be an absolute path".to_string());
    }
    let directory = registry(home);
    preflight_targets(home, &[&directory.join("installation.json")])
        .map_err(|error| error.to_string())?;
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("read Pi installation registry ({error})")),
    };
    let deadline = Instant::now() + REFRESH_BUDGET;
    let mut refreshed = 0;
    let mut preserved = 0;
    let mut stale = 0;
    let mut file_writes = 0;
    // Registration stores canonical targets; HOME may use macOS /var aliases.
    let global_root = std::fs::canonicalize(home)
        .map_err(|error| format!("resolve installation HOME ({error})"))?;
    let global_target = global_root.join(".pi/agent/extensions/lgtm.ts");
    let mut global_registered = false;
    for (index, entry) in entries.into_iter().flatten().enumerate() {
        if index >= MAX_INSTALLATIONS {
            return Err(registry_full_reason(&directory));
        }
        if Instant::now() >= deadline {
            return Err(registry_timeout_reason(&directory, "refresh"));
        }
        let path = entry
            .map_err(|error| format!("read Pi installation entry ({error})"))?
            .path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let mut installation = read_installation(&path)?;
        global_registered |= installation.target == global_target;
        if std::fs::canonicalize(&installation.binary).ok().as_deref() != Some(binary) {
            preserved += 1;
            continue;
        }
        let Some(managed) = refresh_managed(&mut installation)? else {
            if installation
                .managed
                .as_ref()
                .is_some_and(|managed| managed.agent == "pi" && !managed.rules_only)
            {
                extension_root(&installation)?;
            }
            stale += 1;
            continue;
        };
        file_writes += managed;
        // Migration metadata must survive even when managed files already match.
        // persist avoids writing when the complete registration is unchanged.
        persist(home, installation.clone()).map_err(|error| error.to_string())?;
        let pi_result = if installation
            .managed
            .as_ref()
            .is_none_or(|managed| managed.agent == "pi" && !managed.rules_only)
        {
            refresh_one(&installation)
        } else {
            Ok(0)
        };
        match pi_result {
            Ok(count) if count > 0 || managed > 0 => {
                refreshed += 1;
                file_writes += count;
            }
            Ok(_) => preserved += 1,
            Err(error) => {
                return Err(format!(
                    "refresh Pi extension {} ({error}); binary is installed, repair and run lgtm refresh-pi",
                    installation.target.display()
                ));
            }
        }
    }
    if !global_registered {
        let migrated = refresh_legacy_global(&global_root, binary)?;
        if migrated > 0 {
            refreshed += 1;
            file_writes += migrated;
        }
    }
    Ok(format!(
        "LGTM installations: {refreshed} refreshed, {preserved} unchanged or preserved, {stale} stale registrations skipped (missing project root; records kept for manual cleanup); {file_writes} managed file writes. Reload running agent sessions. Register untracked project installations once with the appropriate lgtm init command."
    ))
}

// Discover only the canonical global hook, never scan unrelated repositories.
fn refresh_legacy_global(home: &Path, binary: &Path) -> Result<usize, String> {
    let target = home.join(".pi/agent/extensions/lgtm.ts");
    preflight_targets(home, &[&target]).map_err(|error| error.to_string())?;
    let Some(existing) = read_if_exists(&target).map_err(|error| error.to_string())? else {
        return Ok(0);
    };
    let binary_text = binary.to_str().ok_or("Pi executable path is not UTF-8")?;
    let generated =
        pi::render(binary_text, ExtensionScope::Global).map_err(|error| error.to_string())?;
    let binding = format!("const LGTM_BINARY = {};", serde_json::json!(binary_text));
    if !existing.lines().any(|line| line == binding)
        || !pi::owned_template(&existing, &generated, ExtensionScope::Global)
    {
        return Ok(0);
    }
    let mut managed = managed_record(home, super::InitAgent::Pi, true, false);
    managed
        .guidance
        .retain(|path| path != &home.join(".pi/agent/AGENTS.md"));
    let mut installation = Installation {
        version: 1,
        target,
        binary: binary.to_path_buf(),
        global: true,
        managed: Some(managed),
    };
    // The canonical HOME exists here, so this legacy root is never stale.
    let count = refresh_one(&installation)? + refresh_managed(&mut installation)?.unwrap_or(0);
    persist(home, installation).map_err(|error| error.to_string())?;
    Ok(count)
}

/// Refresh the managed files of one registration. `Ok(None)` reports a stale
/// registration whose managed root no longer exists.
fn refresh_managed(installation: &mut Installation) -> Result<Option<usize>, String> {
    let Some(managed) = installation.managed.as_mut() else {
        return Ok(Some(0));
    };
    let agent = match managed.agent.as_str() {
        "claude" => super::InitAgent::Claude,
        "codex" => super::InitAgent::Codex,
        "pi" => super::InitAgent::Pi,
        _ => return Err("registered adapter is unsupported".to_string()),
    };
    if !managed.root.is_absolute() || !installation.target.starts_with(&managed.root) {
        return Err("registered installation root is invalid".to_string());
    }
    let metadata = match std::fs::symlink_metadata(&managed.root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect registered installation root ({error})")),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("registered installation root is not a regular directory".to_string());
    }
    if !installation.global
        && !managed.rules_only
        && !managed.root.join(".lgtm/config.json").is_file()
    {
        return Ok(Some(0));
    }
    let count = super::managed_refresh::refresh(
        &managed.root,
        agent,
        installation.global,
        managed.rules_only,
        &managed.guidance,
        managed.codex_digest.as_deref(),
    )
    .map_err(|error| {
        format!(
            "refresh managed files in {} ({error})",
            managed.root.display()
        )
    })?;
    managed.guidance =
        super::managed_refresh::guidance_paths(&managed.root, agent, installation.global);
    if agent == super::InitAgent::Codex && !installation.global {
        managed.codex_digest = Some(format!(
            "{:x}",
            Sha256::digest(super::rules::agents_document().as_bytes())
        ));
    }
    Ok(Some(count))
}

fn read_installation(path: &Path) -> Result<Installation, String> {
    let raw = read_if_exists(path)
        .map_err(|error| error.to_string())?
        .ok_or("Pi installation disappeared during refresh")?;
    let installation: Installation = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid Pi installation {} ({error})", path.display()))?;
    if installation.version != 1
        || !installation.target.is_absolute()
        || !installation.binary.is_absolute()
    {
        return Err(format!(
            "invalid Pi installation identity: {}",
            path.display()
        ));
    }
    Ok(installation)
}

fn extension_root(installation: &Installation) -> Result<&Path, String> {
    let target = &installation.target;
    let suffix = if installation.global {
        ".pi/agent/extensions/lgtm.ts"
    } else {
        ".pi/extensions/lgtm.ts"
    };
    if !target.ends_with(suffix) {
        return Err("registered path is not a Pi extension location".to_string());
    }
    target
        .ancestors()
        .nth(if installation.global { 4 } else { 3 })
        .ok_or_else(|| "registered extension has no installation root".to_string())
}

fn refresh_one(installation: &Installation) -> Result<usize, String> {
    let target = &installation.target;
    let root = extension_root(installation)?;
    preflight_targets(root, &[target]).map_err(|error| error.to_string())?;
    preflight_file_targets(&[target]).map_err(|error| error.to_string())?;
    let binary = &installation.binary;
    let Some(existing) = read_if_exists(target).map_err(|error| error.to_string())? else {
        return Ok(0);
    };
    // A tracked path must still reference the same executable. Do not repoint
    // extensions that the owner deliberately moved to a different installation.
    let declared_binary = existing.lines().find_map(|line| {
        line.strip_prefix("const LGTM_BINARY = ")
            .and_then(|value| value.strip_suffix(';'))
            .and_then(|value| serde_json::from_str::<String>(value).ok())
    });
    if declared_binary.as_deref().map(Path::new) != Some(binary) {
        return Ok(0);
    }
    let scope = if installation.global {
        ExtensionScope::Global
    } else {
        ExtensionScope::Project
    };
    let binary = binary.to_str().ok_or("Pi executable path is not UTF-8")?;
    let generated = pi::render(binary, scope).map_err(|error| error.to_string())?;
    if !pi::owned_template(&existing, &generated, scope) {
        return Ok(0);
    }
    let backup = target.with_file_name("lgtm.ts.bak");
    preflight_file_targets(&[&backup]).map_err(|error| error.to_string())?;
    let plan = pi::plan(target, &backup, binary, scope).map_err(|error| error.to_string())?;
    let mut writes = 0;
    if let Some(bytes) = plan.backup_contents {
        commit_write(stage_private_write(&backup, &bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        writes += 1;
    }
    if let Some(bytes) = plan.target_contents {
        commit_write(stage_write(target, &bytes).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        writes += 1;
    }
    Ok(writes)
}
