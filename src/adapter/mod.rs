//! Harness-neutral hook protocol core.
//!
//! An adapter translates a harness's lifecycle payload into a neutral
//! [`HookRequest`] and encodes a normalized [`HookResponse`] back into that
//! harness's exact stdout/stderr bytes and exit code. Policy decisions live in
//! `hooks/` and `checks/`; an adapter only parses input and encodes output, so
//! no adapter can invent a status, block on a non-error, or bypass evidence.

mod claude;
mod codex;

pub use claude::ClaudeAdapter;
pub use codex::CodexAdapter;

use std::io::Write;

use serde_json::Value;

/// Lifecycle events lgtm can normalize across harnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    /// Session start (also fired on resume, clear, and compact).
    SessionStart,
    /// A user prompt was submitted.
    UserPromptSubmit,
    /// A tool call is about to run.
    PreToolUse,
    /// Codex is about to ask for permission for a tool call.
    PermissionRequest,
    /// A Codex subagent has started.
    SubagentStart,
    /// A Codex subagent is trying to stop.
    SubagentStop,
    /// A tool call just completed.
    PostToolUse,
    /// The agent is trying to stop.
    Stop,
}

/// A harness-neutral lifecycle request.
///
/// Carries the event plus the fields any adapter can supply: the tool a
/// Pre/PostToolUse event names, its input payload, the prompt a UserPromptSubmit
/// event carries, and session metadata (id, cwd, transcript, source). Hook
/// handlers still read policy-specific extras from their own bespoke parsers;
/// this type is the shared surface a new adapter (for example Codex) targets.
#[derive(Debug, Clone, PartialEq)]
pub struct HookRequest {
    /// The lifecycle event this request belongs to.
    pub event: HookEvent,
    /// The tool a Pre/PostToolUse or PermissionRequest event names, when present.
    pub tool_name: Option<String>,
    /// The tool input payload, passed through verbatim.
    pub tool_input: Option<Value>,
    /// The submitted prompt, for UserPromptSubmit.
    pub prompt: Option<String>,
    /// The harness session identifier.
    pub session_id: Option<String>,
    /// The working directory the harness reports.
    pub cwd: Option<String>,
    /// The transcript path, when the harness provides one.
    pub transcript_path: Option<String>,
    /// The SessionStart source (startup, resume, clear, compact).
    pub source: Option<String>,
    /// Codex subagent identifier, when present.
    pub agent_id: Option<String>,
    /// Codex subagent type/profile, when present.
    pub agent_type: Option<String>,
    /// Whether Codex already continued this hook, when present.
    pub stop_hook_active: Option<bool>,
}

/// A normalized, closed set of hook outcomes.
///
/// Policy code produces one of these; the adapter maps it to harness bytes. The
/// set is closed so a harness cannot invent a status the Stop gate never
/// authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookResponse {
    /// Proceed with no agent-facing output.
    Allow,
    /// Inject compact context text for the harness to prepend.
    InjectContext(String),
    /// Deny a tool call before it runs, with an operator-facing reason.
    Deny {
        /// Why the tool call was denied.
        reason: String,
    },
    /// Block session/stop completion until a MUST violation is resolved.
    BlockStop {
        /// The unresolved violations that block completion.
        reason: String,
    },
    /// Report a finding after a tool already completed.
    PostToolFeedback {
        /// The feedback and remediation text for the agent.
        reason: String,
    },
    /// Report a clean completion summary without changing the decision.
    Summary(String),
}

/// Which stream an encoded response is written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    /// The agent-facing stdout channel.
    Stdout,
    /// The operator-facing stderr channel (used by Stop's exit-2 block).
    Stderr,
}

/// The exact bytes, stream, and exit code an encoded response writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedResponse {
    /// The response line without its trailing newline; empty means write nothing.
    pub body: String,
    /// The stream [`emit`] writes `body` to.
    pub stream: OutputStream,
    /// The process exit code the hook returns.
    pub exit_code: u8,
}

/// A harness adapter: parse a lifecycle payload into a neutral request, and
/// encode a normalized response into that harness's exact bytes and exit code.
pub trait HookAdapter {
    /// Parse a harness stdin payload into a neutral [`HookRequest`].
    ///
    /// Blank input is accepted as an empty request; malformed input is an error.
    ///
    /// Callers MUST treat an `Err` as fail-open: per lgtm's fail-safe design a
    /// hook that cannot parse its input must not block the agent, so the caller
    /// exits 0 with no output rather than propagating the error as a decision.
    fn parse_request(&self, event: HookEvent, stdin_json: &str) -> Result<HookRequest, String>;

    /// Encode a normalized [`HookResponse`] into harness bytes, stream, and exit
    /// code for the given event.
    ///
    /// Only event-valid pairs encode. Each adapter owns its event capability
    /// matrix; Claude keeps its historical SessionStart/UserPromptSubmit
    /// contract, while Codex adds event-specific context, permission, and
    /// subagent forms. Any unsupported pair returns `Err` rather than
    /// emitting plausible but wrong bytes. Callers MUST treat an `Err` as
    /// fail-open per lgtm's fail-safe design: exit 0 with no output rather than
    /// blocking the agent.
    fn encode_response(
        &self,
        event: HookEvent,
        response: HookResponse,
    ) -> Result<EncodedResponse, String>;
}

/// Write an encoded response as a single newline-terminated line to the stream
/// its [`OutputStream`] names: `stdout` for [`OutputStream::Stdout`], `stderr`
/// for [`OutputStream::Stderr`] (Stop's exit-2 block).
///
/// Both writers are injected so either path is testable; callers pass the real
/// process streams in production. An empty body writes nothing, preserving the
/// silent allow path. This matches the historical `write_line` framing: the
/// compact JSON line plus one `\n`.
pub fn emit(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    encoded: &EncodedResponse,
) -> Result<(), String> {
    if encoded.body.is_empty() {
        return Ok(());
    }
    match encoded.stream {
        OutputStream::Stdout => write_line(stdout, &encoded.body),
        OutputStream::Stderr => write_line(stderr, &encoded.body),
    }
}

/// Write one line plus a trailing newline, converting IO errors to a message.
fn write_line(output: &mut impl Write, line: &str) -> Result<(), String> {
    writeln!(output, "{line}").map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
