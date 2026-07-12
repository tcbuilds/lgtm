use serde_json::Map;

pub const CONFIG_COMPATIBILITY_VERSION: &str = "1";
pub const CONFIG_V2_VERSION: &str = "2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compatibility {
    Current,
    CurrentV2,
    LegacyMissing,
}

pub fn validate(object: &Map<String, serde_json::Value>) -> Result<Compatibility, String> {
    match object.get("version") {
        None => Ok(Compatibility::LegacyMissing),
        Some(value) if value.as_str() == Some(CONFIG_COMPATIBILITY_VERSION) => {
            Ok(Compatibility::Current)
        }
        Some(value) if value.as_str() == Some(CONFIG_V2_VERSION) => Ok(Compatibility::CurrentV2),
        Some(value) if value.is_string() => Err(format!(
            "config version mismatch: expected `{CONFIG_COMPATIBILITY_VERSION}`, found `{}`",
            sanitize(value.as_str().unwrap_or_default())
        )),
        Some(_) => Err("config version must be a string".to_string()),
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn matching_missing_mismatched_and_malformed_versions_are_distinct() {
        let current = json!({"version":"1"}).as_object().expect("object").clone();
        assert_eq!(validate(&current), Ok(Compatibility::Current));
        let current_v2 = json!({"version":"2"}).as_object().expect("object").clone();
        assert_eq!(validate(&current_v2), Ok(Compatibility::CurrentV2));
        assert_eq!(validate(&Map::new()), Ok(Compatibility::LegacyMissing));
        let mismatch = json!({"version":"2\nInjected"})
            .as_object()
            .expect("object")
            .clone();
        let error = validate(&mismatch).expect_err("mismatch rejected");
        assert!(error.contains("expected `1`, found `2Injected`"));
        let malformed = json!({"version":1}).as_object().expect("object").clone();
        assert_eq!(
            validate(&malformed).expect_err("type rejected"),
            "config version must be a string"
        );
    }
}
