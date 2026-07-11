//! UserPromptSubmit hook: compile a deterministic planning packet.

mod files;
mod input;
mod intent;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::json;

use crate::compile::compile_selected;
use crate::context;
use crate::policy::ChangeType;
use crate::select::select_rules;

use input::{MAX_PAYLOAD_BYTES, bounded_prompt, parse};

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    match run_inner(input, output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            let _ = writeln!(
                std::io::stderr(),
                "user prompt hook failed: entity=stdin reason={reason} retryable=false"
            );
            ExitCode::SUCCESS
        }
    }
}

fn run_inner(input: &mut impl Read, output: &mut impl Write) -> Result<(), String> {
    let mut raw = String::new();
    input
        .take(MAX_PAYLOAD_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|error| error.to_string())?;
    if raw.len() as u64 > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds maximum size".to_string());
    }
    let hook_input = parse(&raw).map_err(|error| error.to_string())?;
    let root = repo_root(hook_input.cwd.as_deref());
    if !root.is_dir() {
        return Err("repository root does not exist".to_string());
    }
    let prompt = bounded_prompt(&hook_input);
    let intent = intent::classify(&prompt);
    persist_intent(&root, hook_input.session_id.as_deref(), intent.label())?;
    let files = files::likely_files(&prompt);
    let context = context::build(&root, &files, &prompt);
    let (_, registry, _) = crate::policy::load_profiled_registry(&root)?;
    let selected = select_rules(&context, &registry, ChangeType::Modify);
    let compiled = compile_selected(&selected, &context.files_touched);
    write_response(output, intent.label(), &compiled.packet)
}

fn persist_intent(root: &Path, session_id: Option<&str>, intent: &str) -> Result<(), String> {
    let directory = root.join(".lgtm/evidence");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create intent directory ({error})"))?;
    let payload = json!({ "session_id": session_id, "intent": intent });
    let bytes =
        serde_json::to_vec(&payload).map_err(|error| format!("serialize intent ({error})"))?;
    if bytes.len() > 4 * 1_024 {
        return Err("intent evidence exceeds maximum size".to_string());
    }
    let path = directory.join("current-task.intent.json");
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err("intent evidence is not a regular file".to_string());
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("inspect intent evidence ({error})"));
        }
        _ => {}
    }
    write_intent_file(&path, &bytes)
}

fn write_intent_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|error| format!("write intent evidence ({error})"))
}

fn write_response(output: &mut impl Write, intent: &str, packet: &str) -> Result<(), String> {
    let additional_context = format!("Detected task intent: {intent}.\n\n{packet}");
    let response = json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": additional_context,
        }
    });
    serde_json::to_writer(&mut *output, &response).map_err(|error| error.to_string())?;
    writeln!(output).map_err(|error| error.to_string())
}

fn repo_root(cwd: Option<&str>) -> PathBuf {
    cwd.filter(|value| !value.is_empty())
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from)
}

#[cfg(test)]
mod tests;
