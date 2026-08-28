//! Global harness installation under the current user's home directory.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::*;

const MANAGED_START: &str = "<!-- lgtm-global-guidance:start -->";
const MANAGED_END: &str = "<!-- lgtm-global-guidance:end -->";

/// Result of installing every harness LGTM currently supports globally.
#[derive(Debug)]
pub struct GlobalInitSummary {
    pub files_written: Vec<String>,
    pub notes: Vec<String>,
    pub rules: rules::Installed,
}

/// Install global Claude and Codex configuration below `home`.
pub fn run(home: &Path, dry_run: bool) -> Result<GlobalInitSummary, InitError> {
    if !home.is_absolute() {
        return Err(InitError::UnwritableTarget {
            path: home.to_path_buf(),
            reason: "HOME must be an absolute path".to_string(),
        });
    }

    let claude_settings = home.join(".claude/settings.json");
    let codex_hooks = home.join(".codex/hooks.json");
    let codex_agents = home.join(".codex/AGENTS.md");
    let pi_extension = home.join(".pi/agent/extensions/lgtm.ts");
    let pi_backup = pi_extension.with_file_name("lgtm.ts.bak");
    let binary = codex::hook_binary();
    let claude_render =
        render_claude_hooks(config::validate_claude_settings(&claude_settings)?, &binary);
    let codex_render = codex::render_hooks(config::validate_settings(&codex_hooks)?);
    let agents_render = render_agents(&codex_agents)?;
    let (guidance_plan, rules) = rules::plan(home, InitAgent::Claude)?;

    let mut targets = vec![
        claude_settings.clone(),
        codex_hooks.clone(),
        codex_agents.clone(),
        pi_extension.clone(),
        pi_backup.clone(),
    ];
    targets.extend(rules::target_paths(home, InitAgent::Claude));
    let target_refs: Vec<&Path> = targets.iter().map(PathBuf::as_path).collect();
    preflight_targets(home, &target_refs)?;
    preflight_file_targets(&target_refs)?;

    let pi_plan = pi::plan(
        &pi_extension,
        &pi_backup,
        &pi::hook_binary()?,
        pi::ExtensionScope::Global,
    )?;

    let mut planned = vec![
        (
            claude_settings,
            ".claude/settings.json".to_string(),
            claude_render,
        ),
        (codex_hooks, ".codex/hooks.json".to_string(), codex_render),
        (codex_agents, ".codex/AGENTS.md".to_string(), agents_render),
    ];
    if let Some(contents) = pi_plan.backup_contents.as_ref() {
        planned.push((
            pi_plan.backup.clone(),
            ".pi/agent/extensions/lgtm.ts.bak".to_string(),
            Some(contents.clone()),
        ));
    }
    planned.push((
        pi_plan.target.clone(),
        ".pi/agent/extensions/lgtm.ts".to_string(),
        pi_plan.target_contents.clone(),
    ));
    planned.extend(guidance_plan.iter().map(|write| {
        (
            write.path.clone(),
            format!(".claude/rules/{}", write.label),
            Some(write.contents.clone()),
        )
    }));

    let files_written: Vec<String> = planned
        .iter()
        .filter(|(_, _, render)| render.is_some())
        .map(|(_, label, _)| label.clone())
        .collect();
    let mut notes = vec![
        "global install targets $HOME; no repository .lgtm config was written".to_string(),
        "Pi global extension handles initialized repositories, including nested cwd launches"
            .to_string(),
        "Codex global hooks require review in `/hooks` after changes".to_string(),
    ];
    if home.join(".codex/AGENTS.override.md").is_file() {
        notes.push(
            "Codex AGENTS.override.md is active; it hides .codex/AGENTS.md until removed"
                .to_string(),
        );
    }
    if pi_plan.preserved_collision {
        notes.push(
            "preserved existing .pi/agent/extensions/lgtm.ts; Pi enforcement is not installed globally"
                .to_string(),
        );
    }
    if dry_run {
        notes.insert(0, "dry-run: no files changed".to_string());
        return Ok(GlobalInitSummary {
            files_written,
            notes,
            rules,
        });
    }

    for (path, _, render) in &planned {
        if render.is_some()
            && let Some(parent) = path.parent()
        {
            create_dir_all(parent)?;
        }
    }
    let mut staged = Vec::new();
    for (path, label, render) in planned {
        if let Some(bytes) = render {
            staged.push((stage_write(&path, &bytes)?, label));
        }
    }
    for (handle, _) in staged {
        commit_write(handle)?;
    }

    Ok(GlobalInitSummary {
        files_written,
        notes,
        rules,
    })
}

fn render_claude_hooks(validated: config::ValidatedSettings, binary: &str) -> Option<Vec<u8>> {
    let existing = validated.unwrap_or_default();
    let merged = settings::merge_settings_with_binary(&existing, binary);
    if merged == existing {
        return None;
    }
    let mut serialized = serde_json::to_string_pretty(&Value::Object(merged))
        .expect("Claude hooks map serializes as a JSON object");
    serialized.push('\n');
    Some(serialized.into_bytes())
}

fn render_agents(path: &Path) -> Result<Option<Vec<u8>>, InitError> {
    let existing = read_if_exists(path)?.unwrap_or_default();
    let managed = format!(
        "{MANAGED_START}\n{}\n{MANAGED_END}\n",
        rules::entry_document()
    );
    let merged = merge_managed_block(path, &existing, &managed)?;
    (merged != existing)
        .then(|| Ok(merged.into_bytes()))
        .transpose()
}

fn merge_managed_block(path: &Path, existing: &str, managed: &str) -> Result<String, InitError> {
    let start_count = existing.matches(MANAGED_START).count();
    let end_count = existing.matches(MANAGED_END).count();
    if start_count > 1 || end_count > 1 {
        return Err(InitError::MalformedGuidance {
            path: path.to_path_buf(),
            reason: "found duplicate LGTM managed-block markers".to_string(),
        });
    }

    let start = existing.find(MANAGED_START);
    let end = existing.find(MANAGED_END);
    match (start, end) {
        (Some(start), Some(end)) if start <= end => {
            let after = end + MANAGED_END.len();
            let mut merged = String::with_capacity(existing.len() + managed.len());
            merged.push_str(&existing[..start]);
            merged.push_str(managed.trim_end_matches('\n'));
            merged.push_str(&existing[after..]);
            Ok(merged)
        }
        (None, None) if existing.is_empty() => Ok(managed.to_string()),
        (None, None) => {
            let separator = if existing.ends_with("\n\n") {
                ""
            } else if existing.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            Ok(format!("{existing}{separator}{managed}"))
        }
        _ => Err(InitError::MalformedGuidance {
            path: path.to_path_buf(),
            reason: "found only one LGTM managed-block marker".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_block_preserves_existing_guidance_and_is_idempotent() {
        let path = Path::new("AGENTS.md");
        let existing = "# Personal defaults\n\n- Keep this exact.\n";
        let managed = format!("{MANAGED_START}\nLGTM\n{MANAGED_END}\n");
        let once = merge_managed_block(path, existing, &managed).expect("first merge");
        let twice = merge_managed_block(path, &once, &managed).expect("second merge");
        assert!(once.starts_with(existing));
        assert_eq!(once, twice);
    }

    #[test]
    fn incomplete_managed_block_is_rejected() {
        let error = merge_managed_block(Path::new("AGENTS.md"), MANAGED_START, "replacement")
            .expect_err("incomplete marker must fail");
        assert!(error.to_string().contains("managed-block marker"));
    }

    #[test]
    fn duplicate_managed_block_markers_are_rejected() {
        let existing = format!("{MANAGED_START}\n{MANAGED_END}\n{MANAGED_START}\n{MANAGED_END}\n");
        let error = merge_managed_block(Path::new("AGENTS.md"), &existing, "replacement")
            .expect_err("duplicate markers must fail");
        assert!(error.to_string().contains("duplicate"));
    }
}
