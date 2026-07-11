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
use crate::policy::{ChangeType, load_embedded_registry};
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
    let prompt = bounded_prompt(hook_input);
    let files = files::likely_files(&prompt);
    let context = context::build(&root, &files, &prompt);
    let registry = load_embedded_registry().map_err(|error| error.to_string())?;
    let selected = select_rules(&context, &registry, ChangeType::Modify);
    let compiled = compile_selected(&selected, &context.files_touched);
    write_response(output, intent::classify(&prompt).label(), &compiled.packet)
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
