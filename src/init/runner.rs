use super::*;

/// Migrate `.lgtm/config.json` from V1 shell strings to validated V2 argv.
pub fn migrate_config(root: &Path, dry_run: bool) -> Result<InitSummary, InitError> {
    let detection = detect(root);
    let workspaces = crate::discovery::discover(root)?;
    let config_path = root.join(".lgtm").join("config.json");
    let backup_path = root.join(".lgtm").join("config.v1.bak.json");
    let contents = read_if_exists(&config_path)?.ok_or_else(|| InitError::MalformedConfig {
        path: config_path.clone(),
        reason: "no config exists to migrate".to_string(),
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedConfig {
            path: config_path.clone(),
            reason: error.to_string(),
        })?;
    if value.get("version").and_then(serde_json::Value::as_str) == Some(crate::config_v2::VERSION) {
        crate::config_v2::parse(&value).map_err(|error| InitError::MalformedConfig {
            path: config_path,
            reason: error.to_string(),
        })?;
        return Ok(InitSummary {
            detection,
            workspaces,
            files_written: Vec::new(),
            notes: vec!["config is already V2; no migration needed".to_string()],
        });
    }
    let config =
        crate::config_v2::migrate_v1(&value).map_err(|error| InitError::MalformedConfig {
            path: config_path.clone(),
            reason: error.to_string(),
        })?;
    let rendered =
        crate::config_v2::render(&config).map_err(|error| InitError::MalformedConfig {
            path: config_path.clone(),
            reason: error.to_string(),
        })?;
    let labels = vec![".lgtm/config.v1.bak.json", ".lgtm/config.json"];
    if dry_run {
        return Ok(InitSummary {
            detection,
            workspaces,
            files_written: labels.into_iter().map(str::to_string).collect(),
            notes: vec![
                "dry-run: no files changed".to_string(),
                "V1 config will be backed up before V2 replacement".to_string(),
            ],
        });
    }
    preflight_targets(&[&config_path, &backup_path])?;
    let backup = stage_write(&backup_path, contents.as_bytes())?;
    let replacement = stage_write(&config_path, &rendered)?;
    commit_write(backup)?;
    commit_write(replacement)?;
    Ok(InitSummary {
        detection,
        workspaces,
        files_written: labels.into_iter().map(str::to_string).collect(),
        notes: vec!["migrated V1 shell commands to structured V2 argv".to_string()],
    })
}

/// Inspect the repository and report planned writes without mutating it.
pub fn preview(root: &Path) -> Result<InitSummary, InitError> {
    let detection = detect(root);
    let workspaces = crate::discovery::discover(root)?;
    let settings_path = root.join(".claude").join("settings.json");
    let config_path = root.join(".lgtm").join("config.json");
    let _ = validate_settings(&settings_path)?;
    let _ = validate_config(&config_path)?;
    let mut notes = vec!["dry-run: no files changed".to_string()];
    note_unsupported_repo(&detection, &mut notes);
    for workspace in &workspaces {
        if workspace.commands.is_empty() {
            notes.push(format!(
                "missing gates: workspace `{}` has no recognized quality commands",
                workspace.id
            ));
        }
    }
    Ok(InitSummary {
        detection,
        workspaces,
        files_written: vec![
            ".lgtm/config.json".to_string(),
            ".gitignore".to_string(),
            ".claude/settings.json".to_string(),
        ],
        notes,
    })
}

/// Scaffold repo-local configuration and merge Claude Code hooks.
pub fn run(root: &Path) -> Result<InitSummary, InitError> {
    let detection = detect(root);
    let workspaces = crate::discovery::discover(root)?;

    let settings_path = root.join(".claude").join("settings.json");
    let validated_settings = validate_settings(&settings_path)?;

    let config_path = root.join(".lgtm").join("config.json");
    let existing_config = validate_config(&config_path)?;
    let existing_config_contents = existing_config
        .as_ref()
        .map(|(_, contents)| contents.clone())
        .unwrap_or_default();
    let existing_config = existing_config.map(|(object, _)| object);

    let evidence_dir = root.join(".lgtm").join("evidence");
    let gitignore_path = root.join(".gitignore");
    preflight_targets(&[&evidence_dir, &config_path, &gitignore_path, &settings_path])?;

    let mut files_written = Vec::new();
    let mut notes = Vec::new();

    note_unsupported_repo(&detection, &mut notes);

    let config_render = render_config(
        &detection,
        existing_config,
        &existing_config_contents,
        &mut notes,
    );
    let gitignore_render = render_gitignore(&gitignore_path, &mut notes)?;
    let settings_render = render_settings(validated_settings);

    create_output_directories(&evidence_dir, &settings_path)?;

    let planned: [PlannedWrite<'_>; 3] = [
        (&config_path, ".lgtm/config.json", config_render),
        (&gitignore_path, ".gitignore", gitignore_render),
        (&settings_path, ".claude/settings.json", settings_render),
    ];

    stage_and_commit(planned, &mut files_written)?;

    Ok(InitSummary {
        detection,
        workspaces,
        files_written,
        notes,
    })
}

type PlannedWrite<'a> = (&'a Path, &'static str, Option<Vec<u8>>);

fn note_unsupported_repo(detection: &Detection, notes: &mut Vec<String>) {
    if detection.languages.is_empty() {
        notes.push("no MVP-supported languages detected (python only in MVP)".to_string());
    }
}

fn create_output_directories(evidence_dir: &Path, settings_path: &Path) -> Result<(), InitError> {
    create_dir_all(evidence_dir)?;
    if let Some(parent) = settings_path.parent() {
        create_dir_all(parent)?;
    }
    Ok(())
}

fn stage_and_commit(
    planned: [PlannedWrite<'_>; 3],
    files_written: &mut Vec<String>,
) -> Result<(), InitError> {
    let mut staged = Vec::new();
    for (path, label, render) in planned {
        if let Some(bytes) = render {
            staged.push((stage_write(path, &bytes)?, label));
        }
    }
    for (handle, label) in staged {
        commit_write(handle)?;
        files_written.push(label.to_string());
    }
    Ok(())
}
