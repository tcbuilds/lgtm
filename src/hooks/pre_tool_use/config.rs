use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::fsutil::open_regular_file;

const MAX_CONFIG_BYTES: u64 = 256 * 1_024;

#[derive(Debug, Default, Deserialize)]
struct Config {
    #[serde(default)]
    prohibited_paths: Vec<String>,
}

pub(super) fn prohibited_patterns(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join(".lgtm/config.json");
    if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
        return Err("config is not a regular file".to_string());
    }
    let Some(file) = open_regular_file(&path).map_err(|error| error.to_string())? else {
        return Ok(Vec::new());
    };
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_CONFIG_BYTES {
        return Err("config exceeds maximum size".to_string());
    }
    let config: Config = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    if config.prohibited_paths.len() > 1_024 {
        return Err("prohibited_paths exceeds bounds".to_string());
    }
    config
        .prohibited_paths
        .into_iter()
        .map(normalize_pattern)
        .collect()
}

pub(super) fn is_prohibited(relative: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| {
        if matches!(pattern.as_str(), "*" | "**") {
            return true;
        }
        let Some(prefix) = pattern.strip_suffix("/**") else {
            return relative == pattern;
        };
        relative == prefix || relative.starts_with(&format!("{prefix}/"))
    })
}

fn normalize_pattern(pattern: String) -> Result<String, String> {
    let pattern = pattern.replace('\\', "/");
    let core = pattern.strip_suffix("/**").unwrap_or(&pattern);
    let is_all = matches!(pattern.as_str(), "*" | "**");
    if pattern.is_empty()
        || pattern.len() > 4_096
        || core.starts_with('/')
        || core.split('/').any(|part| matches!(part, "" | "." | ".."))
        || (!is_all && core.contains('*'))
    {
        return Err("prohibited_paths contains an invalid pattern".to_string());
    }
    Ok(pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_prefix_and_all_patterns_match_explicitly() {
        assert!(is_prohibited("secrets/key.py", &["secrets/**".to_string()]));
        assert!(is_prohibited("config.json", &["config.json".to_string()]));
        assert!(is_prohibited("any/path", &["*".to_string()]));
        assert!(!is_prohibited("config.toml", &["config.json".to_string()]));
    }

    #[test]
    fn unsupported_or_traversing_patterns_are_rejected() {
        for pattern in ["*.env", "../secret", "/etc", ""] {
            assert!(normalize_pattern(pattern.to_string()).is_err(), "{pattern}");
        }
    }
}
