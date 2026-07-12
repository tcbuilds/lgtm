use super::*;

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
