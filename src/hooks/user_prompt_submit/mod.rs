//! UserPromptSubmit hook: compile a deterministic planning packet.

mod files;
mod input;
mod intent;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::json;

use crate::adapter::{ClaudeAdapter, HookAdapter};
use crate::compile::{MAX_PACKET_BYTES, compile_selected};
use crate::context;
use crate::policy::{ChangeType, Level, Rule};
use crate::select::select_rules;

use input::{MAX_PAYLOAD_BYTES, bounded_prompt, parse};

/// The compiled packet's per-instruction byte budget.
const MAX_INSTRUCTION_BYTES: usize = 512;

pub fn run(input: &mut impl Read, output: &mut impl Write) -> ExitCode {
    let adapter = ClaudeAdapter;
    run_with_adapter(input, output, &adapter)
}

/// Run UserPromptSubmit with an explicitly selected harness adapter.
pub fn run_with_adapter(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> ExitCode {
    match run_inner(input, output, adapter) {
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

fn run_inner(
    input: &mut impl Read,
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
) -> Result<(), String> {
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
    if adapter.loads_rules_natively() {
        let (_, registry, _, _, _compatibility, _) = crate::policy::load_profiled_registry(&root)?;
        if native_rules_present(&root) {
            return write_native_response(output, adapter, intent.label(), &registry);
        }
        return write_fallback_response(output, adapter, &root, &prompt, &registry, intent.label());
    }
    let files = files::likely_files(&prompt);
    let context = context::build(&root, &files, &prompt);
    let (_, registry, _, _, compatibility, _) = crate::policy::load_profiled_registry(&root)?;
    report_legacy_config(compatibility);
    let selected = select_rules(&context, &registry, ChangeType::Modify);
    let compiled = compile_selected(&selected, &context.files_touched);
    write_response(output, adapter, intent.label(), &compiled.packet)
}

/// Check whether Claude has the LGTM entry document that loads every session.
fn native_rules_present(root: &Path) -> bool {
    crate::fsutil::read_optional_bounded(&root.join(".claude/rules/standards.md"), 64 * 1024)
        .lines()
        .any(|line| line.trim() == crate::init::ENTRY_DOCUMENT_MARKER)
}

/// Report legacy configuration compatibility once per loaded policy.
fn report_legacy_config(compatibility: crate::policy::config_version::Compatibility) {
    if compatibility == crate::policy::config_version::Compatibility::LegacyMissing {
        eprintln!(
            "validate failed: entity=config-version reason=version missing; legacy compatibility accepted, run lgtm init retryable=false"
        );
    }
}

/// Inject only instructions changed by repository policy layers into native
/// Claude loading; native rule files continue to own the rule bodies.
fn write_native_response(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    intent: &str,
    registry: &[Rule],
) -> Result<(), String> {
    match native_instruction_delta(registry)? {
        Some(delta) => write_response(output, adapter, intent, &delta),
        None => write_intent_response(output, adapter, intent),
    }
}

/// Compare resolved instructions with the embedded defaults and render only
/// changed instruction values. Native rule files own the actual path-scoped
/// selection, so each injected delta states its applicability for the reader.
fn native_instruction_delta(registry: &[Rule]) -> Result<Option<String>, String> {
    let defaults = crate::policy::load_embedded_registry().map_err(|error| error.to_string())?;
    let mut changes = Vec::new();
    for rule in registry {
        let default = defaults
            .iter()
            .find(|candidate| candidate.id == rule.id)
            .ok_or_else(|| format!("resolved policy references unknown rule {}", rule.id))?;
        if rule.instruction != default.instruction {
            changes.push(format!(
                "- {} (applies to {}): {}",
                rule.id,
                native_applicability(rule),
                rule.instruction
            ));
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    let packet = format!(
        "Resolved LGTM instruction overrides:\n{}",
        changes.join("\n")
    );
    if packet.len() > MAX_PACKET_BYTES {
        return Ok(Some(format!(
            "Resolved organization/repository instruction overrides omitted: the resolved override content exceeded the {MAX_PACKET_BYTES}-byte packet budget."
        )));
    }
    Ok(Some(packet))
}

/// Describe the rule conditions that the native harness will apply later.
fn native_applicability(rule: &Rule) -> String {
    let mut conditions = Vec::new();
    if !rule.applies_to.languages.is_empty() {
        conditions.push(format!(
            "languages: {}",
            rule.applies_to.languages.join(", ")
        ));
    }
    if !rule.applies_to.domains.is_empty() {
        conditions.push(format!("domains: {}", rule.applies_to.domains.join(", ")));
    }
    if !rule.applies_to.file_patterns.is_empty() {
        conditions.push(format!(
            "files: {}",
            rule.applies_to.file_patterns.join(", ")
        ));
    }
    if !rule.activation.change_types.is_empty() {
        conditions.push(format!(
            "changes: {}",
            rule.activation
                .change_types
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !rule.activation.signals.is_empty() {
        conditions.push(format!("signals: {}", rule.activation.signals.join(", ")));
    }
    if conditions.is_empty() {
        "all tasks".to_string()
    } else {
        conditions.join("; ")
    }
}

/// Inject a bounded fallback packet when native rule files are absent.
fn write_fallback_response(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    root: &Path,
    prompt: &str,
    registry: &[Rule],
    intent: &str,
) -> Result<(), String> {
    let files = files::likely_files(prompt);
    let mut task_context = context::build(root, &files, prompt);
    if intent == "bug-fix" {
        task_context.risk_signals.push(intent.to_string());
        task_context.risk_signals.sort_unstable();
    }
    let scoped = select_rules(&task_context, registry, ChangeType::Modify);
    let (selected, omitted) =
        bounded_fallback_rules(scoped.iter().copied(), &task_context.files_touched);
    let compiled = compile_selected(&selected, &task_context.files_touched);
    let notice = fallback_omission_notice(&omitted);
    let packet = format!("{}{}", compiled.packet, notice);
    let packet = if packet_is_complete(&packet, &selected) {
        packet
    } else {
        format!(
            "Fallback guidance unavailable: the complete packet could not fit within the {MAX_PACKET_BYTES}-byte budget. Install the rule files with `lgtm init` for native loading."
        )
    };
    write_response(output, adapter, intent, &packet)
}

/// Select whole, already-scoped rules so fallback guidance never cuts a section
/// in half: MUST rules first, then review rules in registry order.
fn bounded_fallback_rules<'a>(
    registry: impl IntoIterator<Item = &'a Rule>,
    touched_files: &[String],
) -> (Vec<&'a Rule>, Vec<String>) {
    let mut prioritized: Vec<_> = registry.into_iter().collect();
    prioritized.sort_by_key(|rule| usize::from(rule.level != Level::Must));

    let mut selected = Vec::new();
    let mut omitted = Vec::new();
    for rule in prioritized {
        if !instruction_fits_within_line_budget(rule) {
            omitted.push(rule.id.clone());
            continue;
        }
        let mut candidate = selected.clone();
        candidate.push(rule);
        let packet = compile_selected(&candidate, touched_files).packet;
        if packet_is_complete(&packet, &candidate) {
            selected.push(rule);
        } else {
            omitted.push(rule.id.clone());
        }
    }

    loop {
        let packet = compile_selected(&selected, touched_files).packet;
        let notice = fallback_omission_notice(&omitted);
        if packet_is_complete_with_notice(&packet, &notice, &selected) {
            return (selected, omitted);
        }

        let removable = selected
            .iter()
            .rposition(|rule| rule.level != Level::Must)
            .or_else(|| selected.len().checked_sub(1));
        let Some(index) = removable else {
            return (selected, omitted);
        };
        omitted.push(selected[index].id.clone());
        selected.remove(index);
    }
}

/// State explicitly which guidance was omitted to preserve packet integrity.
fn fallback_omission_notice(omitted: &[String]) -> String {
    if omitted.is_empty() {
        return String::new();
    }
    format!(
        "\nFallback packet bounded: {} rule(s) omitted to keep every section intact (their instruction or rendered content exceeded the packet/line budget): {}. Run `lgtm init` to install the full rule files.\n",
        omitted.len(),
        omitted.join(", ")
    )
}

fn packet_is_complete(packet: &str, rules: &[&Rule]) -> bool {
    packet.len() <= MAX_PACKET_BYTES
        && packet.contains("\nMUST\n")
        && packet.contains("\nREVIEW\n")
        && packet.contains("\nVerification required:\n")
        && packet.contains("\nDo not claim a check passed")
        && rules
            .iter()
            .all(|rule| instruction_fits_within_line_budget(rule))
        && !packet.contains("packet truncated")
}

fn packet_is_complete_with_notice(packet: &str, notice: &str, rules: &[&Rule]) -> bool {
    packet_is_complete(packet, rules)
        && packet.len().saturating_add(notice.len()) <= MAX_PACKET_BYTES
}

/// Match the normalization applied by packet compilation before checking its line budget.
fn instruction_fits_within_line_budget(rule: &Rule) -> bool {
    rule.instruction.replace(['\n', '\r', '\t'], " ").len() <= MAX_INSTRUCTION_BYTES
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

fn write_response(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    intent: &str,
    packet: &str,
) -> Result<(), String> {
    use crate::adapter::{HookEvent, HookResponse};
    let context = format!("Detected task intent: {intent}.\n\n{packet}");
    let encoded = adapter.encode_response(
        HookEvent::UserPromptSubmit,
        HookResponse::InjectContext(context),
    )?;
    crate::adapter::emit(output, &mut std::io::stderr(), &encoded)
}

fn write_intent_response(
    output: &mut impl Write,
    adapter: &dyn HookAdapter,
    intent: &str,
) -> Result<(), String> {
    use crate::adapter::{HookEvent, HookResponse};
    let context = format!("Detected task intent: {intent}.");
    let encoded = adapter.encode_response(
        HookEvent::UserPromptSubmit,
        HookResponse::InjectContext(context),
    )?;
    crate::adapter::emit(output, &mut std::io::stderr(), &encoded)
}

fn repo_root(cwd: Option<&str>) -> PathBuf {
    cwd.filter(|value| !value.is_empty())
        .map_or_else(|| Path::new(".").to_path_buf(), PathBuf::from)
}

#[cfg(test)]
mod tests;
