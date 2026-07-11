use serde::Deserialize;

pub(super) const MAX_PAYLOAD_BYTES: u64 = 256 * 1_024;
pub(super) const MAX_PROMPT_BYTES: usize = 64 * 1_024;

#[derive(Debug, Default, Deserialize)]
pub(super) struct HookInput {
    pub cwd: Option<String>,
    pub user_prompt: Option<String>,
    pub prompt: Option<String>,
}

pub(super) fn parse(raw: &str) -> Result<HookInput, serde_json::Error> {
    if raw.trim().is_empty() {
        return Ok(HookInput::default());
    }
    serde_json::from_str(raw)
}

pub(super) fn bounded_prompt(input: HookInput) -> String {
    let prompt = input.user_prompt.or(input.prompt).unwrap_or_default();
    let mut end = prompt.len().min(MAX_PROMPT_BYTES);
    while !prompt.is_char_boundary(end) {
        end -= 1;
    }
    prompt[..end].to_string()
}
