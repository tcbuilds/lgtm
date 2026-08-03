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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_edit_and_write_tools_expose_file_targets() {
        let input = HookInput {
            cwd: None,
            session_id: None,
            tool_name: Some("Edit".to_string()),
            tool_input: ToolInput {
                file_path: Some("src/lib.rs".to_string()),
                command: None,
            },
        };
        assert_eq!(edited_file(&input), Some("src/lib.rs"));

        let mut read = input;
        read.tool_name = Some("Read".to_string());
        assert_eq!(edited_file(&read), None);
    }

    #[test]
    fn only_bash_tools_expose_commands() {
        let input = HookInput {
            cwd: None,
            session_id: None,
            tool_name: Some("Bash".to_string()),
            tool_input: ToolInput {
                file_path: None,
                command: Some("cargo test".to_string()),
            },
        };
        assert_eq!(requested_command(&input), Some("cargo test"));

        let mut write = input;
        write.tool_name = Some("Write".to_string());
        assert_eq!(requested_command(&write), None);
    }
}
