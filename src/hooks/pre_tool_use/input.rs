use serde::Deserialize;

pub(super) const MAX_PAYLOAD_BYTES: u64 = 256 * 1_024;

#[derive(Debug, Deserialize)]
pub(super) struct HookInput {
    pub cwd: Option<String>,
    pub session_id: Option<String>,
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: ToolInput,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ToolInput {
    pub file_path: Option<String>,
    pub command: Option<String>,
}

pub(super) fn edited_file(input: &HookInput) -> Option<&str> {
    matches!(input.tool_name.as_deref(), Some("Edit" | "Write"))
        .then(|| input.tool_input.file_path.as_deref())
        .flatten()
}

pub(super) fn requested_command(input: &HookInput) -> Option<&str> {
    matches!(input.tool_name.as_deref(), Some("Bash"))
        .then(|| input.tool_input.command.as_deref())
        .flatten()
}
