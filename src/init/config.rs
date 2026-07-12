use super::*;

pub(super) type ValidatedSettings = Option<Map<String, Value>>;

/// Read and validate `.claude/settings.json` without writing anything.
///
/// Returns `Ok(None)` when the file is absent or blank, `Ok(Some(object))` when
/// it parses to a well-shaped settings object, and an error when it is
/// malformed, not an object, or carries a `hooks` value whose shape would be
/// discarded by a merge (non-object `hooks`, or a non-array event value).
pub(super) fn validate_settings(path: &Path) -> Result<ValidatedSettings, InitError> {
    let contents = match read_if_exists(path)? {
        None => return Ok(None),
        Some(contents) if contents.trim().is_empty() => return Ok(None),
        Some(contents) => contents,
    };

    let value: Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedSettings {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;

    let Value::Object(object) = value else {
        return Err(InitError::SettingsNotObject {
            path: path.to_path_buf(),
        });
    };

    if let Some(hooks) = object.get("hooks") {
        let Value::Object(hooks) = hooks else {
            return Err(InitError::SettingsHooksNotObject {
                path: path.to_path_buf(),
            });
        };
        for (event, entries) in hooks {
            if !entries.is_array() {
                return Err(InitError::SettingsEventNotArray {
                    path: path.to_path_buf(),
                    event: event.clone(),
                });
            }
        }
    }

    Ok(Some(object))
}

/// The validated, parsed `.lgtm/config.json` object paired with the exact bytes
/// read from disk, or `None` when the file is absent or blank. The raw bytes are
/// threaded to [`render_config`] for its skip-if-identical comparison so the file
/// is never re-read after validation.
pub(super) type ValidatedConfig = Option<(Map<String, Value>, String)>;

/// Read and validate an existing `.lgtm/config.json` without writing anything.
///
/// Returns `Ok(None)` when the file is absent or blank, `Ok(Some((object,
/// contents)))` when it parses to a well-typed JSON object (a user-edited config
/// to preserve) paired with the exact bytes read from disk, and an error when it
/// is malformed, not an object, or carries a preserved field whose JSON type is
/// wrong. The raw contents are returned so [`render_config`] can perform its
/// skip-if-identical comparison against the bytes validated here rather than
/// re-reading the file, which both avoids a second unbounded read and closes the
/// swap-between-validate-and-render race. The type check exists because
/// [`merge_config`] preserves fields it does not overwrite: a preserved field
/// whose type is wrong would otherwise be silently discarded and overwritten,
/// violating preservation. Every preserved field is checked to the depth the
/// runtime relies on: `profile` must be a string, `languages` an array of
/// strings, `disabled_rules`
/// an array of strings, `severity_overrides` an object of string values, and
/// `required_commands` an object whose every value is an array of strings.
/// Refusing here keeps that consistent with the malformed-config handling above.
pub(super) fn validate_config(path: &Path) -> Result<ValidatedConfig, InitError> {
    let contents = match read_if_exists(path)? {
        None => return Ok(None),
        Some(contents) if contents.trim().is_empty() => return Ok(None),
        Some(contents) => contents,
    };

    let value: Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedConfig {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;

    let Value::Object(object) = value else {
        return Err(InitError::ConfigNotObject {
            path: path.to_path_buf(),
        });
    };

    validate_optional_field(path, &object, "profile", Value::is_string)?;
    validate_optional_field(path, &object, "version", Value::is_string)?;
    crate::policy::config_version::validate(&object).map_err(|reason| {
        InitError::MalformedConfig {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    validate_optional_field(path, &object, "languages", is_string_array)?;
    validate_optional_field(path, &object, "disabled_rules", is_string_array)?;
    validate_optional_field(path, &object, "severity_overrides", is_string_valued_object)?;
    if let Some(value) = object.get("command_timeout_seconds")
        && !value
            .as_u64()
            .is_some_and(|seconds| (1..=3600).contains(&seconds))
    {
        return Err(InitError::ConfigFieldWrongType {
            path: path.to_path_buf(),
            field: "command_timeout_seconds".to_string(),
        });
    }
    if let Some(required) = object.get("required_commands") {
        let Value::Object(commands) = required else {
            return Err(InitError::ConfigFieldWrongType {
                path: path.to_path_buf(),
                field: "required_commands".to_string(),
            });
        };
        if !commands.values().all(is_string_array) {
            return Err(InitError::ConfigFieldWrongType {
                path: path.to_path_buf(),
                field: "required_commands".to_string(),
            });
        }
    }

    Ok(Some((object, contents)))
}

fn validate_optional_field(
    path: &Path,
    object: &Map<String, Value>,
    field: &str,
    predicate: fn(&Value) -> bool,
) -> Result<(), InitError> {
    if object.get(field).is_none_or(predicate) {
        return Ok(());
    }
    Err(InitError::ConfigFieldWrongType {
        path: path.to_path_buf(),
        field: field.to_string(),
    })
}

/// True when `value` is a JSON array whose every element is a string.
///
/// Used to validate preserved `disabled_rules` and each `required_commands`
/// entry, both of which [`merge_config`] carries forward verbatim and therefore
/// must be well-typed to avoid silently preserving a nonsense value.
fn is_string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

/// True when `value` is a JSON object whose every value is a string.
///
/// Used to validate a preserved `severity_overrides` map, which maps rule ids to
/// string severities; a non-object map or a non-string severity is a
/// preservation hazard and is refused.
fn is_string_valued_object(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.values().all(Value::is_string))
}

/// Render the desired `.lgtm/config.json` bytes, preserving any existing
/// user-edited config, or `None` when the file is already up to date.
///
/// On a fresh repo (`existing_config` is `None`) the detected config is
/// produced. When a valid config already exists it is preserved verbatim:
/// user-edited `disabled_rules` and `severity_overrides` are never overwritten.
/// Newly detected languages and their commands are merged only into fields that
/// are still empty in the existing config, so re-init can enrich a bare config
/// without clobbering deliberate edits. Returns `None` when the serialized
/// contents already match `existing_contents` (the exact bytes
/// [`validate_config`] read from disk) so no write is staged; reusing those
/// already-validated bytes avoids a second unbounded read and closes the
/// swap-between-validate-and-render race.
pub(super) fn render_config(
    detection: &Detection,
    workspaces: &[Workspace],
    existing_config: Option<Map<String, Value>>,
    existing_contents: &str,
    notes: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, InitError> {
    let desired = match existing_config {
        None => settings::build_v2_config(workspaces),
        Some(existing) if existing.get("version").and_then(Value::as_str) != Some("2") => {
            notes.push("migrated legacy config using detected workspace gates".to_string());
            let migrated =
                crate::config_v2::migrate_v1_with_workspaces(&Value::Object(existing), workspaces)
                    .map_err(|error| InitError::MalformedConfig {
                        path: PathBuf::from(".lgtm/config.json"),
                        reason: error.to_string(),
                    })?;
            serde_json::to_value(migrated).expect("V2 config model serializes")
        }
        Some(existing) => {
            notes.push("preserved existing .lgtm/config.json".to_string());
            Value::Object(merge_config(existing, detection))
        }
    };

    let mut serialized = serde_json::to_string_pretty(&desired)
        .expect("config value is a plain JSON object and always serializes");
    serialized.push('\n');

    if existing_contents == serialized {
        return Ok(None);
    }

    Ok(Some(serialized.into_bytes()))
}

/// Merge newly detected languages and commands into an existing config object,
/// filling only empty fields.
///
/// User-set keys are preserved. `languages` is populated from detection only
/// when the existing list is missing or empty; each detected language's commands
/// are added under `required_commands` only when that language has no entry yet.
/// Everything else in the existing object is left exactly as authored.
fn merge_config(mut existing: Map<String, Value>, detection: &Detection) -> Map<String, Value> {
    existing
        .entry("version".to_string())
        .or_insert_with(|| json!(crate::policy::config_version::CONFIG_COMPATIBILITY_VERSION));
    let languages_empty = existing
        .get("languages")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty);
    if languages_empty {
        existing.insert("languages".to_string(), json!(detection.languages));
    }

    let required = existing
        .entry("required_commands".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(required) = required {
        for (language, commands) in &detection.required_commands {
            if !required.contains_key(language) {
                required.insert(language.clone(), json!(commands));
            }
        }
    }

    existing
}
