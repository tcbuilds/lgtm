use serde::Deserialize;

pub(super) const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Default, Deserialize)]
pub(super) struct HookInput {
    #[serde(default)]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    pub(super) source: Option<String>,
}

pub(super) fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    if raw.trim().is_empty() {
        return Ok(HookInput::default());
    }
    serde_json::from_str(raw)
}
