//! Refresh installed managed output without rerunning repository detection.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::fs::{
    commit_write, create_dir_all, preflight_file_targets, preflight_targets, stage_private_write,
};
use super::{
    InitAgent, InitError, codex, config, global, pi_config, read_if_exists, rules, settings,
};

pub(super) fn guidance_paths(root: &Path, agent: InitAgent, is_global: bool) -> Vec<PathBuf> {
    let mut paths = rules::target_paths(root, if is_global { InitAgent::Claude } else { agent });
    if is_global {
        paths.push(root.join(".codex/AGENTS.md"));
    }
    paths
}

pub(super) fn refresh(
    root: &Path,
    agent: InitAgent,
    is_global: bool,
    rules_only: bool,
    known_guidance: &[PathBuf],
    codex_digest: Option<&str>,
) -> Result<usize, InitError> {
    let mut writes = Vec::new();
    let guidance_agent = if is_global { InitAgent::Claude } else { agent };
    plan_guidance(root, guidance_agent, known_guidance, &mut writes)?;
    if agent == InitAgent::Codex && !is_global {
        plan_codex_guidance(root, codex_digest, &mut writes)?;
    }
    if is_global {
        let target = root.join(".codex/AGENTS.md");
        if read_if_exists(&target)?
            .is_some_and(|text| text.contains("<!-- lgtm-global-guidance:start -->"))
            && let Some(bytes) = global::render_agents(&target)?
        {
            writes.push((target, bytes));
        }
    }
    if !rules_only {
        if is_global || agent == InitAgent::Claude {
            plan_hooks(
                &root.join(".claude/settings.json"),
                InitAgent::Claude,
                &mut writes,
            )?;
        }
        if is_global || agent == InitAgent::Codex {
            plan_hooks(
                &root.join(".codex/hooks.json"),
                InitAgent::Codex,
                &mut writes,
            )?;
        }
        if !is_global && agent == InitAgent::Codex {
            plan_execpolicy(root, &mut writes)?;
        }
        if !is_global && agent == InitAgent::Pi && root.join(".pi/extensions/lgtm.ts").is_file() {
            plan_pi_settings(root, &mut writes)?;
        }
    }
    write_batch(root, writes)
}

fn plan_guidance(
    root: &Path,
    agent: InitAgent,
    known: &[PathBuf],
    writes: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), InitError> {
    let (planned, _) = rules::plan(root, agent)?;
    for write in planned {
        let existing = read_if_exists(&write.path)?;
        if write.path.starts_with(root.join(".claude/rules"))
            && !root.join(".claude/rules").is_dir()
        {
            continue;
        }
        if existing.is_none() && (known.is_empty() || known.contains(&write.path)) {
            continue;
        }
        // Removing the owned marker is an explicit opt-out, not an invitation
        // for the updater to insert it again.
        if agent == InitAgent::Pi
            && write.path == root.join("AGENTS.md")
            && existing
                .as_deref()
                .is_none_or(|text| !text.contains("<!-- lgtm-pi-guidance:start -->"))
        {
            continue;
        }
        if let Some(backup) = write.backup {
            writes.push((backup.path, backup.contents));
        }
        writes.push((write.path, write.contents));
    }
    Ok(())
}

fn plan_codex_guidance(
    root: &Path,
    expected_digest: Option<&str>,
    writes: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), InitError> {
    let target = root.join("AGENTS.md");
    if writes.iter().any(|(path, _)| path == &target) {
        return Ok(());
    }
    if let Some(existing) = read_if_exists(&target)? {
        let digest = format!("{:x}", Sha256::digest(existing.as_bytes()));
        let desired = rules::agents_document();
        if expected_digest == Some(digest.as_str()) && existing != desired {
            writes.push((target, desired.into_bytes()));
        }
    }
    Ok(())
}

fn plan_hooks(
    path: &Path,
    agent: InitAgent,
    writes: &mut Vec<(PathBuf, Vec<u8>)>,
) -> Result<(), InitError> {
    if read_if_exists(path)?.is_none() {
        return Ok(());
    }
    let validated = if agent == InitAgent::Claude {
        config::validate_claude_settings(path)?
    } else {
        config::validate_settings(path)?
    };
    let Some(original) = validated else {
        return Ok(());
    };
    let updated = if agent == InitAgent::Claude {
        settings::refresh_existing_hooks(&original)
    } else {
        codex::refresh_existing_hooks(&original)
    };
    if updated != original {
        writes.push((path.to_path_buf(), render_json(path, updated)?));
    }
    Ok(())
}

fn render_json(path: &Path, value: Map<String, Value>) -> Result<Vec<u8>, InitError> {
    serde_json::to_vec_pretty(&Value::Object(value)).map_err(|error| InitError::UnwritableTarget {
        path: path.to_path_buf(),
        reason: format!("serialize refreshed settings ({error})"),
    })
}

fn plan_execpolicy(root: &Path, writes: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<(), InitError> {
    let source = root.join(".lgtm/execpolicy.json");
    let target = root.join(".codex/rules/lgtm.rules");
    if read_if_exists(&target)?.is_none() {
        return Ok(());
    }
    if let Some(contents) = read_if_exists(&source)? {
        let (rendered, _) = codex::render_execpolicy(&source, &contents, &target)?;
        if let Some(bytes) = rendered {
            writes.push((target, bytes));
        }
    }
    Ok(())
}

fn plan_pi_settings(root: &Path, writes: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<(), InitError> {
    let settings = root.join(".pi/settings.json");
    if read_if_exists(&settings)?.is_some()
        && let Some(bytes) = pi_config::render_settings(pi_config::validate_settings(&settings)?)
    {
        writes.push((settings, bytes));
    }
    let lsp = root.join(".pi/pi-lsp.json");
    if read_if_exists(&lsp)?.is_some()
        && let Some(bytes) = pi_config::render_lsp(pi_config::validate_lsp(&lsp)?)
    {
        writes.push((lsp, bytes));
    }
    Ok(())
}

fn write_batch(root: &Path, writes: Vec<(PathBuf, Vec<u8>)>) -> Result<usize, InitError> {
    let targets: Vec<&Path> = writes.iter().map(|(path, _)| path.as_path()).collect();
    preflight_targets(root, &targets)?;
    preflight_file_targets(&targets)?;
    let mut staged = Vec::new();
    for (path, bytes) in writes {
        if read_if_exists(&path)?.as_deref().map(str::as_bytes) == Some(bytes.as_slice()) {
            continue;
        }
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        staged.push(stage_private_write(&path, &bytes)?);
    }
    let count = staged.len();
    for write in staged {
        commit_write(write)?;
    }
    Ok(count)
}
