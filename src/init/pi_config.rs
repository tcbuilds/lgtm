//! Merge-safe project configuration installed with the Pi adapter.

use super::*;

const PI_LSP_TEMPLATE: &str = include_str!("../../templates/pi/pi-lsp.json");
const PI_SETTINGS_TEMPLATE: &str = include_str!("../../templates/pi/settings.json");

type ValidatedPiObject = Option<Map<String, Value>>;

pub(super) fn validate_settings(path: &Path) -> Result<ValidatedPiObject, InitError> {
    let object = read_object(path)?;
    if let Some(packages) = object.as_ref().and_then(|value| value.get("packages")) {
        let Some(packages) = packages.as_array() else {
            return malformed(path, "packages must be an array");
        };
        if packages
            .iter()
            .any(|package| package_source(package).is_none())
        {
            return malformed(
                path,
                "packages entries must be strings or objects with a string source",
            );
        }
    }
    Ok(object)
}

pub(super) fn validate_lsp(path: &Path) -> Result<ValidatedPiObject, InitError> {
    let object = read_object(path)?;
    if let Some(object) = object.as_ref() {
        validate_timeout(path, object.get("timeout"))?;
        if let Some(servers) = object.get("servers") {
            let Some(servers) = servers.as_object() else {
                return malformed(path, "servers must be an object");
            };
            validate_servers(path, servers)?;
        } else {
            if object.contains_key("timeout") {
                return malformed(
                    path,
                    "timeout requires the wrapper shape with a servers object",
                );
            }
            validate_servers(path, object)?;
        }
    }
    Ok(object)
}

pub(super) fn render_settings(existing: ValidatedPiObject) -> Option<Vec<u8>> {
    let original = existing.unwrap_or_default();
    let mut merged = original.clone();
    let required = template_object(PI_SETTINGS_TEMPLATE);
    let required_packages = required["packages"]
        .as_array()
        .expect("Pi settings template packages are an array");
    let packages = merged
        .entry("packages")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("validated Pi settings packages are an array");

    for package in required_packages {
        let required_source = package_source(package).expect("template package has a source");
        let required_identity = package_identity(required_source);
        let already_present = packages.iter().any(|entry| {
            package_source(entry)
                .is_some_and(|source| package_identity(source) == required_identity)
        });
        if !already_present {
            packages.push(package.clone());
        }
    }
    render_changed(original, merged)
}

pub(super) fn render_lsp(existing: ValidatedPiObject) -> Option<Vec<u8>> {
    let original = existing.unwrap_or_default();
    let mut merged = if original.is_empty() || original.contains_key("servers") {
        original.clone()
    } else {
        let mut wrapper = Map::new();
        wrapper.insert("servers".to_string(), Value::Object(original.clone()));
        wrapper
    };
    let required = template_object(PI_LSP_TEMPLATE);
    let required_servers = required["servers"]
        .as_object()
        .expect("Pi LSP template servers are an object");
    let servers = merged
        .entry("servers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .expect("validated Pi LSP servers are an object");

    for (name, server) in required_servers {
        servers
            .entry(name.clone())
            .or_insert_with(|| server.clone());
    }
    if !merged.contains_key("timeout") {
        merged.insert("timeout".to_string(), required["timeout"].clone());
    }
    render_changed(original, merged)
}

fn read_object(path: &Path) -> Result<ValidatedPiObject, InitError> {
    let contents = match read_if_exists(path)? {
        None => return Ok(None),
        Some(contents) if contents.trim().is_empty() => return Ok(None),
        Some(contents) => contents,
    };
    let value: Value =
        serde_json::from_str(&contents).map_err(|error| InitError::MalformedPiConfig {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    let Value::Object(object) = value else {
        return malformed(path, "root must be a JSON object");
    };
    Ok(Some(object))
}

fn validate_timeout(path: &Path, timeout: Option<&Value>) -> Result<(), InitError> {
    if timeout.is_none_or(|value| {
        value
            .as_f64()
            .is_some_and(|value| value.is_finite() && value > 0.0)
    }) {
        Ok(())
    } else {
        malformed(path, "timeout must be a positive number")
    }
}

fn validate_servers(path: &Path, servers: &Map<String, Value>) -> Result<(), InitError> {
    for (name, server) in servers {
        let Some(server) = server.as_object() else {
            return malformed(path, &format!("server {name} must be an object"));
        };
        let valid_command = server
            .get("command")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty() && items.iter().all(Value::is_string));
        if !valid_command {
            return malformed(
                path,
                &format!("server {name}.command must be a non-empty string array"),
            );
        }
        let valid_extensions = server
            .get("extensions")
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().all(Value::is_string));
        if !valid_extensions {
            return malformed(
                path,
                &format!("server {name}.extensions must be a string array"),
            );
        }
    }
    Ok(())
}

fn package_source(value: &Value) -> Option<&str> {
    match value {
        Value::String(source) => Some(source),
        Value::Object(object) => object.get("source").and_then(Value::as_str),
        _ => None,
    }
}

fn package_identity(source: &str) -> String {
    let (prefix, spec) = source
        .strip_prefix("npm:")
        .map_or(("", source), |spec| ("npm:", spec));
    if prefix.is_empty() && (spec.starts_with('.') || spec.starts_with('/') || spec.contains(':')) {
        return source.to_string();
    }
    let version_start = if spec.starts_with('@') {
        spec.find('/')
            .and_then(|slash| spec[slash + 1..].rfind('@').map(|index| slash + 1 + index))
    } else {
        spec.rfind('@')
    };
    let name = version_start.map_or(spec, |index| &spec[..index]);
    format!("npm:{name}")
}

fn template_object(template: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(template)
        .expect("embedded Pi config template is valid JSON")
        .as_object()
        .expect("embedded Pi config template is an object")
        .clone()
}

fn render_changed(original: Map<String, Value>, merged: Map<String, Value>) -> Option<Vec<u8>> {
    if original == merged {
        return None;
    }
    let mut serialized = serde_json::to_string_pretty(&Value::Object(merged))
        .expect("validated Pi config serializes");
    serialized.push('\n');
    Some(serialized.into_bytes())
}

fn malformed<T>(path: &Path, reason: &str) -> Result<T, InitError> {
    Err(InitError::MalformedPiConfig {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    })
}
