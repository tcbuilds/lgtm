//! Claude Code lifecycle hook handlers.
//!
//! Claude's five native events (SessionStart, UserPromptSubmit, PreToolUse,
//! PostToolUse, Stop) and Codex's permission/subagent extensions are dispatched
//! through these handlers. The binary's `hook <event>` subcommand selects the
//! adapter and lifecycle entry.
//!
//! Every handler reads its event payload from stdin as JSON and must fail safe:
//! any internal error exits 0 with a diagnostic on stderr and no contract on
//! stdout, so a broken harness can never corrupt or block an agent session.

pub mod post_tool_use;
pub mod pre_tool_use;
mod root;
pub mod session_start;
pub mod stop;
pub mod user_prompt_submit;
