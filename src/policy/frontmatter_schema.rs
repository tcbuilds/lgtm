use serde_json::Value;

use super::{RULE_SCHEMA_JSON, frontmatter::FrontmatterError};

/// Validate one parsed frontmatter object against its declared schema definition.
pub(super) fn validate(path: &str, value: &Value) -> Result<(), FrontmatterError> {
    let schema: Value = serde_json::from_str(RULE_SCHEMA_JSON)
        .map_err(|error| FrontmatterError::Schema(error.to_string()))?;
    let validators = jsonschema::validator_map_for(&schema)
        .map_err(|error| FrontmatterError::Schema(error.to_string()))?;
    let validator = validators
        .get("#/$defs/frontmatter")
        .ok_or_else(|| FrontmatterError::Schema("missing #/$defs/frontmatter".to_string()))?;
    if let Some(error) = validator.iter_errors(value).next() {
        return Err(FrontmatterError::Malformed {
            path: path.to_string(),
            reason: format!("schema violation at {}: {error}", error.instance_path()),
        });
    }
    Ok(())
}
