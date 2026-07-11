use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::fsutil::open_regular_file;

pub(super) const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Deserialize)]
pub(super) struct Config {
    #[serde(default = "default_profile")]
    pub(super) profile: String,
    #[serde(default)]
    pub(super) languages: Vec<String>,
    #[serde(skip)]
    pub(super) is_legacy_version: bool,
}

fn default_profile() -> String {
    "default".to_string()
}

pub(super) enum ConfigState {
    Present(Config),
    NotInitialized,
    Malformed(String),
}

pub(super) fn load_config(root: &Path) -> ConfigState {
    let path = root.join(".lgtm").join("config.json");
    let file = match open_regular_file(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return classify_missing_config(&path),
        Err(error) => return ConfigState::Malformed(format!("unreadable ({error})")),
    };
    parse_config(file)
}

fn classify_missing_config(path: &Path) -> ConfigState {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ConfigState::NotInitialized,
        Err(_) | Ok(_) => ConfigState::Malformed("not a regular file".to_string()),
    }
}

fn parse_config(mut file: std::fs::File) -> ConfigState {
    let mut contents = String::new();
    if let Err(error) = file
        .by_ref()
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut contents)
    {
        return ConfigState::Malformed(format!("unreadable ({error})"));
    }
    if contents.len() as u64 > MAX_CONFIG_BYTES {
        return ConfigState::Malformed("oversized".to_string());
    }
    if contents.trim().is_empty() {
        return ConfigState::NotInitialized;
    }
    let value: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(value) => value,
        Err(error) => return ConfigState::Malformed(format!("invalid JSON ({error})")),
    };
    let Some(object) = value.as_object() else {
        return ConfigState::Malformed("root must be an object".to_string());
    };
    let compatibility = match crate::policy::config_version::validate(object) {
        Ok(compatibility) => compatibility,
        Err(error) => return ConfigState::Malformed(error),
    };
    match serde_json::from_value::<Config>(value) {
        Ok(mut config) => match crate::policy::profile::validate_name(&config.profile) {
            Ok(()) => {
                config.is_legacy_version =
                    compatibility == crate::policy::config_version::Compatibility::LegacyMissing;
                ConfigState::Present(config)
            }
            Err(error) => ConfigState::Malformed(error),
        },
        Err(error) => ConfigState::Malformed(format!("invalid config ({error})")),
    }
}
