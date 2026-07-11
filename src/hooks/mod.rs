//! Claude Code lifecycle hook handlers.
//!
//! Each of the five native Claude Code events (SessionStart, UserPromptSubmit,
//! PreToolUse, PostToolUse, Stop) is handled by a submodule here. The binary's
//! `hook <event>` subcommand dispatches to these. The module tree exists so the
//! remaining four events can land beside [`session_start`] without reshaping the
//! command surface.
//!
//! Every handler reads its event payload from stdin as JSON and must fail safe:
//! any internal error exits 0 with a diagnostic on stderr and no contract on
//! stdout, so a broken harness can never corrupt or block an agent session.

pub mod post_tool_use;
pub mod session_start;
pub mod stop;
pub mod user_prompt_submit;
