//! Deterministic local policy authoring and fixture validation.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_INPUT_BYTES: u64 = 512 * 1024;

pub fn validate_file(path: &Path) -> Result<usize, String> {
    let value = read_json(path)?;
    let registry = normalize_registry(value)?;
    super::load_and_validate(&serde_json::to_string(&registry).map_err(|error| error.to_string())?)
        .map(|rules| rules.len())
        .map_err(|error| error.to_string())
}

pub fn add_rule(registry_path: &Path, rule_path: &Path) -> Result<usize, String> {
    let registry = normalize_registry(read_json(registry_path)?)?;
    let rule = read_json(rule_path)?;
    if !rule.is_object() {
        return Err("rule input must be a JSON object".to_string());
    }
    let mut updated = registry;
    updated.push(rule.clone());
    let rules = super::load_and_validate(
        &serde_json::to_string(&updated).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let id = rules
        .last()
        .map(|rule| rule.id.as_str())
        .unwrap_or_default();
    if rules.iter().filter(|rule| rule.id == id).count() != 1 {
        return Err(format!("rule id `{id}` already exists"));
    }
    write_atomic(
        registry_path,
        &serde_json::to_string_pretty(&updated).map_err(|error| error.to_string())?,
    )?;
    Ok(rules.len())
}

pub fn test_fixtures(directory: &Path) -> Result<(usize, usize), String> {
    let mut paths = fs::read_dir(directory)
        .map_err(|error| format!("read fixture directory ({}): {error}", directory.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read fixture entry: {error}"))?;
    paths.retain(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    });
    paths.sort();
    if paths.is_empty() {
        return Err("fixture directory contains no .json files".to_string());
    }
    let mut passed = 0;
    for path in &paths {
        let expected_invalid = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains(".invalid."));
        let result = validate_file(path);
        let valid = result.is_ok();
        if valid == expected_invalid {
            return Err(format!(
                "fixture expectation failed for {}: expected {}",
                path.display(),
                if expected_invalid { "invalid" } else { "valid" }
            ));
        }
        passed += 1;
    }
    Ok((passed, paths.len()))
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let Some(file) = crate::fsutil::open_regular_file(path)
        .map_err(|error| format!("open {} ({error})", path.display()))?
    else {
        return Err(format!(
            "{} is absent or not a regular file",
            path.display()
        ));
    };
    let mut raw = String::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("read {} ({error})", path.display()))?;
    if raw.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!(
            "{} exceeds {MAX_INPUT_BYTES} bytes",
            path.display()
        ));
    }
    serde_json::from_str(&raw).map_err(|error| format!("parse {} ({error})", path.display()))
}

fn normalize_registry(value: serde_json::Value) -> Result<Vec<serde_json::Value>, String> {
    match value {
        serde_json::Value::Array(rules) => Ok(rules),
        serde_json::Value::Object(_) => Ok(vec![value]),
        _ => Err("policy input must be a rule object or registry array".to_string()),
    }
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("create parent ({error})"))?;
    let temp = PathBuf::from(format!("{}.tmp-{}", path.display(), std::process::id()));
    fs::write(&temp, format!("{contents}\n"))
        .map_err(|error| format!("write staging file ({error})"))?;
    fs::rename(&temp, path).map_err(|error| format!("publish policy registry ({error})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_names_define_expected_validity() {
        let root =
            std::env::temp_dir().join(format!("lgtm-policy-fixtures-{}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture dir");
        fs::write(root.join("valid.json"), super::super::RULES_JSON).expect("valid fixture");
        fs::write(root.join("bad.invalid.json"), "{\"nope\":true}").expect("invalid fixture");
        assert_eq!(test_fixtures(&root).expect("fixtures pass"), (2, 2));
        fs::remove_dir_all(root).ok();
    }
}
