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

/// Validated `.lgtm/config.json` data plus whether init should rewrite it.
pub(super) struct ValidatedConfig {
    pub(super) object: Map<String, Value>,
    pub(super) contents: String,
    pub(super) needs_repair: bool,
}

pub(super) type OptionalValidatedConfig = Option<ValidatedConfig>;

/// Read and validate an existing `.lgtm/config.json` without writing anything.
///
/// Returns `Ok(None)` when the file is absent or blank, or validated data paired
/// with the exact bytes read from disk. The raw contents are returned so
/// [`render_config`] can avoid a second read. Strict V2 parsing rejects unknown
/// fields, except obsolete V1 gate fields are removed when the remaining V2
/// config validates; `needs_repair` then makes init rewrite that file.
pub(super) fn validate_config(path: &Path) -> Result<OptionalValidatedConfig, InitError> {
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

    let Value::Object(ref object) = value else {
        return Err(InitError::ConfigNotObject {
            path: path.to_path_buf(),
        });
    };

    validate_optional_field(path, object, "profile", Value::is_string)?;
    validate_optional_field(path, object, "version", Value::is_string)?;
    crate::policy::config_version::validate(object).map_err(|reason| {
        InitError::MalformedConfig {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    let is_v2 = object.get("version").and_then(Value::as_str) == Some("2");
    let (object, needs_repair) = if is_v2 {
        match crate::config_v2::parse(&value) {
            Ok(_) => (object.clone(), false),
            Err(error) => {
                let mut repaired = object.clone();
                let removed_languages = repaired.remove("languages").is_some();
                let removed_commands = repaired.remove("required_commands").is_some();
                let repaired_value = Value::Object(repaired.clone());
                if (removed_languages || removed_commands)
                    && crate::config_v2::parse(&repaired_value).is_ok()
                {
                    (repaired, true)
                } else {
                    return Err(InitError::MalformedConfig {
                        path: path.to_path_buf(),
                        reason: error.to_string(),
                    });
                }
            }
        }
    } else {
        validate_optional_field(path, object, "languages", is_string_array)?;
        validate_optional_field(path, object, "disabled_rules", is_string_array)?;
        validate_optional_field(path, object, "severity_overrides", is_string_valued_object)?;
        (object.clone(), false)
    };
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

    Ok(Some(ValidatedConfig {
        object,
        contents,
        needs_repair,
    }))
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
/// Used to validate legacy `disabled_rules` and each `required_commands` entry
/// before V1 migration, avoiding silent preservation of malformed values.
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
/// user-edited fields are never overwritten. Existing V2 config is preserved
/// byte-for-byte; legacy config is migrated to detected workspace commands.
/// Returns `None` when no write is needed.
pub(super) fn render_config(
    workspaces: &[Workspace],
    existing_config: Option<Map<String, Value>>,
    existing_contents: &str,
    needs_repair: bool,
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
        Some(existing) if needs_repair => {
            notes.push(
                "removed obsolete V1 languages and required_commands from V2 config".to_string(),
            );
            Value::Object(existing)
        }
        Some(_existing) => {
            notes.push("preserved existing .lgtm/config.json".to_string());
            return Ok(None);
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
