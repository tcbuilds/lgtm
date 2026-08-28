# Pi adapter contract evidence

This document records the Pi facts used by the M23 adapter work. The lifecycle
contract remains pinned to the Pi 0.84.2 matrix; built-in tool provenance was
re-probed against Pi 0.84.3 after its edit schema gained descriptive metadata.
This is a capability record, not a claim that Pi enforcement is installed. The
checked-in matrix is `tests/fixtures/pi/0.84.2/capability_matrix.json`; every
matrix claim below is tied to source or live evidence. The 0.84.2 capture
manifest and source excerpts remain under `tests/fixtures/pi/0.84.2/`; the
current built-in tool capture is
`tests/fixtures/pi/0.84.3/tool_provenance.json`.

## Verified event contract

- `session_start` is emitted after extension binding and before resource discovery
  (`session-start`, source fixture `source-session-start-types-0.84.2`).
- `before_agent_start` exposes the expanded prompt and current system prompt. Its
  result can provide a custom message or a replacement system prompt
  (`before-agent-start`, source fixture `source-before-agent-start-types-0.84.2`).
- `tool_call` runs before execution and can return `{ block, reason }`. Its input
  is mutable in Pi, so LGTM must treat it as read-only
  (`tool-call-block`, source fixture `source-tool-call-types-0.84.2`).
- `tool_result` runs after execution and can patch `content`, `details`, `isError`,
  and `usage`. It runs before `tool_execution_end` and final tool-result message
  events (`tool-result-feedback`, source fixture `source-tool-result-types-0.84.2`).
- `tool_execution_end` exposes the completed result and error flag but has no
  typed replacement result (`tool-execution-end`, source fixture
  `source-tool-execution-end-types-0.84.2`).
- `agent_end` may be followed by retry, compaction, or queued continuation;
  `agent_settled` means those automatic continuations are finished. Neither
  event declares a blocking response (`agent-end`, `agent-settled`).
- A global or CLI extension can decide project trust with `yes` or `no`; the
  first decided result wins. Both decisions were exercised in a temporary
  runtime probe (`project-trust-yes-no`, fixture `live-project-trust-yes-no-001`).

## Discovery and failures

Pi resolves project extensions from the startup cwd's `.pi/extensions/` directory,
then global extensions from `~/.pi/agent/extensions/`. The loader does not walk
ancestors for project extensions. A live loader probe recorded project-before-
global order at repository-root startup and global-only loading from a nested cwd
(`project-global-discovery-root`, `project-global-discovery-nested`; fixture
`live-discovery-root-order-001` and `live-discovery-nested-global-only-001`).

A module without a default factory is reported as a load error and skipped while
other discovered extensions continue (`malformed-extension`, fixture
`live-malformed-extension-001`). Extension modules run with the user's full
permissions; only trusted extension sources may be installed.

## Tool provenance

The live SDK captures in the versioned `tool_provenance.json` files record
`pi.getAllTools()` output, including parameter schemas and `sourceInfo`, for
built-in `read`, `bash`, `edit`, and `write` (`builtin-read-provenance`,
`builtin-bash-provenance`, `builtin-edit-provenance`,
`builtin-write-provenance`; fixtures `live-sdk-builtins-001` and
`live-sdk-builtins-0.84.3-001`). Pi 0.84.3 added a human-readable `description`
to the `edit.edits` array without changing its type, required fields, item schema,
or built-in provenance. LGTM accepts that optional descriptive field while still
rejecting every other unrecognized structural key. A project extension replacing
`read` reports non-builtin
project source metadata (`same-name-read-override`; fixture
`live-sdk-override-001`). The override is deliberately **unverified** for built-in
enforcement. Custom, MCP, provider, and schema-mismatched tools remain
unverified (`custom-tool-provenance`; fixture
`unverified-custom-tool-provenance`). Tool names alone do not establish
provenance.

## Installation and rollback

Project setup uses `lgtm init --agent pi`. It writes the owned extension to
`.pi/extensions/lgtm.ts`, merges the pinned project package set into
`.pi/settings.json`, and merges the configured language-server routes into
`.pi/pi-lsp.json`. Package identity is compared without its npm version, so an
existing pin or package filter remains authoritative instead of being duplicated.
Existing top-level Pi settings, timeout values, and named LSP server routes are
also preserved. Pi loads these project resources only after project trust; its
package manager, not LGTM, installs missing packages. Neither LGTM nor pi-lsp
installs language-server executables.

Global setup uses the existing `lgtm init -g` command and writes the owned
extension to `~/.pi/agent/extensions/lgtm.ts` alongside the other global harness
files. Both generated extension files embed the absolute executable path, are
upgraded only when their LGTM ownership markers match, and keep one
collision-safe `.bak` copy before a first upgrade. A user-authored extension at
either path is preserved. Remove the owned extension and its backup to roll back
that scope. For project package or LSP rollback, remove only the generated entries
and preserve unrelated JSON settings. No repository `.lgtm` configuration is
written by global init.

A project-root Pi session uses the project extension. When Pi starts in a nested
cwd, the project extension is not discovered, so the global extension prefers the
nearest root with a regular `.lgtm/config.json`; partial `.lgtm` markers are only
a fallback when no initialized config exists. The global extension is inert when
no marker exists and skips a root-start session when the current cwd contains the
owned project extension.

Pi lifecycle hooks use a 10-second transport deadline. Bash pre-tool calls use a
40-second transport deadline because they may run the Pi-specific pre-commit gate;
that gate has a 30-second total budget, including bounded checks and evidence
persistence, and denies on aggregate exhaustion. Claude and Codex keep their
existing full-gate budget.

## Path-scoped guidance

For a verified built-in `read` result, the Pi extension validates the result
shape, safely resolves the path against the event cwd, verifies repository
containment, and forwards only the normalized path and session identity to the
shared M20 path-injection service. The service performs frontmatter matching,
body extraction, ordering, bounds, and persistent per-session deduplication.
Matching bodies are returned as additional text after the original `content`
array; `details`, `isError`, and `usage` are preserved. Malformed results,
unsafe paths, and degraded shared state remain bounded unverified outcomes.
This path is guidance only and does not change tool input or enforcement results.

Pi cannot provide verified context before a direct `edit` or `write` call through
the current event contract. Such calls remain enforced by the pre-tool policy,
but path-scoped guidance is unsupported/unverified for that direct-first-edit
case. A preceding `read` is the supported guidance path.

The supported built-in input paths captured by the fixture are:

| Tool | Required input | Optional input |
| --- | --- | --- |
| `read` | `path` | `offset`, `limit` |
| `bash` | `command` | `timeout` |
| `edit` | `path`, `edits[].oldText`, `edits[].newText` | none |
| `write` | `path`, `content` | none |

## Deferred claims

M23.2 does not claim a hard Stop gate, provider payload coverage, or interception
of custom/MCP/overridden tools. M23.7 does not claim direct pre-execution
path-scoped context for `edit` or `write`; a preceding verified `read` result is
required. The `agent_settled` notification writes current Pi enforcement evidence
through the existing evidence JSONL path; `agent_end` and Stop remain
non-blocking. The adapter preserves original `tool_result` fields and fails open
with an explicit unverified marker when provenance, schema, trust, runtime
loading, or shared guidance state is not proven.
