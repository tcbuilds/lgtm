use serde::Deserialize;

pub(super) const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const EDIT_TOOLS: [&str; 3] = ["Edit", "Write", "MultiEdit"];

#[derive(Debug, Default, Deserialize)]
pub(super) struct HookInput {
    #[serde(default)]
    pub(super) session_id: Option<String>,
    #[serde(default)]
    pub(super) cwd: Option<String>,
    #[serde(default)]
    pub(super) tool_name: Option<String>,
    #[serde(default)]
    pub(super) tool_input: Option<ToolInput>,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ToolInput {
    #[serde(default)]
    pub(super) file_path: Option<String>,
}

pub(super) fn parse_input(raw: &str) -> Result<HookInput, serde_json::Error> {
    if raw.trim().is_empty() {
        return Ok(HookInput::default());
    }
    serde_json::from_str(raw)
}

pub(super) fn edited_file(input: &HookInput) -> Option<String> {
    let tool_name = input.tool_name.as_deref()?;
    if !EDIT_TOOLS.contains(&tool_name) {
        return None;
    }
    let path = input.tool_input.as_ref()?.file_path.as_deref()?;
    (!path.trim().is_empty()).then(|| path.to_string())
}
