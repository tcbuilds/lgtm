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
            rules: None,
        });
    }
    let config =
        crate::config_v2::migrate_v1_with_workspaces(&value, &workspaces).map_err(|error| {
            InitError::MalformedConfig {
                path: config_path.clone(),
                reason: error.to_string(),
            }
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
            rules: None,
        });
    }
    preflight_targets(root, &[&config_path, &backup_path])?;
    let backup = stage_write(&backup_path, contents.as_bytes())?;
    let replacement = stage_write(&config_path, &rendered)?;
    commit_write(backup)?;
    commit_write(replacement)?;
    Ok(InitSummary {
        detection,
        workspaces,
        files_written: labels.into_iter().map(str::to_string).collect(),
        notes: vec!["migrated V1 shell commands to structured V2 argv".to_string()],
        rules: None,
    })
}

/// Inspect the repository and report planned writes without mutating it.
pub fn preview(root: &Path) -> Result<InitSummary, InitError> {
    preview_with_agent(root, InitAgent::Claude)
}

/// Inspect the repository and report planned writes for one agent.
pub fn preview_with_agent(root: &Path, agent: InitAgent) -> Result<InitSummary, InitError> {
    let detection = detect(root);
    let workspaces = crate::discovery::discover(root)?;
    let settings_path = hooks_path(root, agent);
    let config_path = root.join(".lgtm").join("config.json");
    let _ = validate_settings(&settings_path)?;
    let _ = validate_config(&config_path)?;
    let mut notes = vec!["dry-run: no files changed".to_string()];
    note_unsupported_repo(&detection, &mut notes);
    notes.push(track_note(agent));
    if agent == InitAgent::Codex {
        notes.push(codex::trust_note(&settings_path));
    }
    for workspace in &workspaces {
        if workspace.commands.is_empty() {
            notes.push(format!(
                "missing gates: workspace `{}` has no recognized quality commands",
                workspace.id
            ));
        }
    }
    let (_, guidance_summary) = rules::plan(root, agent)?;
    Ok(InitSummary {
        detection,
        workspaces,
        files_written: vec![
            ".lgtm/config.json".to_string(),
            ".lgtm/execpolicy.json".to_string(),
            ".gitignore".to_string(),
            hooks_label(agent).to_string(),
        ],
        notes,
        rules: Some(guidance_summary),
    })
}

/// Scaffold repo-local configuration and merge Claude Code hooks.
pub fn run(root: &Path) -> Result<InitSummary, InitError> {
    run_with_options(root, true)
}

/// Scaffold configuration, optionally requiring explicit acceptance of
/// medium-confidence fallback commands.
pub fn run_with_options(root: &Path, accept_guesses: bool) -> Result<InitSummary, InitError> {
    run_with_agent(root, accept_guesses, InitAgent::Claude)
}

/// Scaffold configuration and merge hooks for the selected agent.
pub fn run_with_agent(
    root: &Path,
    accept_guesses: bool,
    agent: InitAgent,
) -> Result<InitSummary, InitError> {
    let detection = detect(root);
    let workspaces = crate::discovery::discover(root)?;
    if !accept_guesses {
        let guesses: Vec<_> = workspaces
            .iter()
            .flat_map(|workspace| {
                workspace
                    .commands
                    .iter()
                    .filter(|command| command.confidence == "medium")
                    .map(|command| format!("{}:{}", workspace.id, command.argv.join(" ")))
            })
            .collect();
        if !guesses.is_empty() {
            return Err(InitError::LowConfidence {
                details: guesses.join(", "),
            });
        }
    }

    let settings_path = hooks_path(root, agent);
    let rules_path = root.join(".codex/rules/lgtm.rules");
    let validated_settings = validate_settings(&settings_path)?;

    let config_path = root.join(".lgtm").join("config.json");
    let existing_config = validate_config(&config_path)?;
    let existing_config_contents = existing_config
        .as_ref()
        .map(|config| config.contents.clone())
        .unwrap_or_default();
    let needs_repair = existing_config
        .as_ref()
        .is_some_and(|config| config.needs_repair);
    let existing_config = existing_config.map(|config| config.object);

    let evidence_dir = root.join(".lgtm").join("evidence");
    let execpolicy_path = root.join(".lgtm").join("execpolicy.json");
    let gitignore_path = root.join(".gitignore");
    let mut targets: Vec<&Path> = vec![
        evidence_dir.as_path(),
        config_path.as_path(),
        execpolicy_path.as_path(),
        gitignore_path.as_path(),
        settings_path.as_path(),
    ];
    let guidance_targets = rules::target_paths(root, agent);
    targets.extend(guidance_targets.iter().map(PathBuf::as_path));
    if agent == InitAgent::Codex {
        targets.push(rules_path.as_path());
    }
    preflight_targets(root, &targets)?;
    let file_targets: Vec<&Path> = targets
        .iter()
        .copied()
        .filter(|path| *path != evidence_dir.as_path())
        .collect();
    preflight_file_targets(&file_targets)?;

    let mut files_written = Vec::new();
    let mut notes = Vec::new();

    note_unsupported_repo(&detection, &mut notes);
    notes.push(track_note(agent));
    if agent == InitAgent::Codex {
        notes.push(codex::trust_note(&settings_path));
    }

    let config_render = render_config(
        &workspaces,
        existing_config,
        &existing_config_contents,
        needs_repair,
        &mut notes,
    )?;
    let (execpolicy_default_render, execpolicy_contents) =
        execpolicy::render_defaults(&execpolicy_path, &mut notes)?;
    let gitignore_render = render_gitignore(&gitignore_path, &mut notes)?;
    let settings_render = match agent {
        InitAgent::Claude => render_settings(validated_settings),
        InitAgent::Codex => codex::render_hooks(validated_settings),
    };
    let (rules_render, rules_notes) = match agent {
        InitAgent::Claude => (None, Vec::new()),
        InitAgent::Codex => {
            codex::render_execpolicy(&execpolicy_path, &execpolicy_contents, &rules_path)?
        }
    };
    notes.extend(rules_notes);

    let (guidance_plan, guidance_summary) = rules::plan(root, agent)?;

    create_output_directories(
        &evidence_dir,
        &settings_path,
        rules_render.is_some(),
        &rules_path,
        &guidance_plan,
    )?;

    let mut planned: Vec<PlannedWrite<'_>> = vec![
        (&config_path, ".lgtm/config.json".to_string(), config_render),
        (
            &execpolicy_path,
            ".lgtm/execpolicy.json".to_string(),
            execpolicy_default_render,
        ),
        (&gitignore_path, ".gitignore".to_string(), gitignore_render),
        (
            &settings_path,
            hooks_label(agent).to_string(),
            settings_render,
        ),
        (
            &rules_path,
            ".codex/rules/lgtm.rules".to_string(),
            rules_render,
        ),
    ];
    planned.extend(guidance_plan.iter().map(|write| {
        (
            write.path.as_path(),
            guidance_label(agent, &write.label),
            Some(write.contents.clone()),
        )
    }));

    stage_and_commit(planned, &mut files_written)?;

    Ok(InitSummary {
        detection,
        workspaces,
        files_written,
        notes,
        rules: Some(guidance_summary),
    })
}

fn hooks_path(root: &Path, agent: InitAgent) -> PathBuf {
    match agent {
        InitAgent::Claude => root.join(".claude").join("settings.json"),
        InitAgent::Codex => root.join(".codex").join("hooks.json"),
    }
}

fn hooks_label(agent: InitAgent) -> &'static str {
    match agent {
        InitAgent::Claude => ".claude/settings.json",
        InitAgent::Codex => ".codex/hooks.json",
    }
}

fn track_note(agent: InitAgent) -> String {
    format!(
        "track .lgtm/config.json, .lgtm/execpolicy.json, and {}; **/.lgtm/evidence/ is transient",
        hooks_label(agent)
    )
}

/// Convert a rules-relative label into the repo-relative path reported by init.
fn guidance_label(agent: InitAgent, label: &str) -> String {
    match agent {
        InitAgent::Claude => format!(".claude/rules/{label}"),
        InitAgent::Codex => label.to_string(),
    }
}

type PlannedWrite<'a> = (&'a Path, String, Option<Vec<u8>>);

fn note_unsupported_repo(detection: &Detection, notes: &mut Vec<String>) {
    if detection.languages.is_empty() {
        notes.push("no MVP-supported languages detected (python only in MVP)".to_string());
    }
}

fn create_output_directories(
    evidence_dir: &Path,
    settings_path: &Path,
    create_rules: bool,
    rules_path: &Path,
    guidance_plan: &[rules::PlannedRuleWrite],
) -> Result<(), InitError> {
    create_dir_all(evidence_dir)?;
    if let Some(parent) = settings_path.parent() {
        create_dir_all(parent)?;
    }
    if create_rules && let Some(parent) = rules_path.parent() {
        create_dir_all(parent)?;
    }
    for write in guidance_plan {
        if let Some(parent) = write.path.parent() {
            create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn stage_and_commit<'a>(
    planned: impl IntoIterator<Item = PlannedWrite<'a>>,
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
        files_written.push(label);
    }
    Ok(())
}
