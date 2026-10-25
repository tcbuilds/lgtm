# Codex observer adapter

This guide describes the observer-only source change, not an installed rollout.
LGTM uses an explicit Codex input/output adapter; it does not guess from a payload.

```bash
lgtm init --agent codex
lgtm hook session-start --adapter codex
lgtm check --tier full
```

Project init merges `.codex/hooks.json` without removing other hooks. It wires
SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest, PostToolUse,
SubagentStart, SubagentStop, and Stop. Known edit and command aliases include
`apply_patch`, `Edit`, `Write`, `exec_command`, `unified_exec`, and `Bash`.
Repeated init is idempotent. A stable installed binary path is recorded when
available; source-tree runs can use the portable `lgtm` command.

Global `lgtm init -g` merges the same wiring and a managed guidance block under
`~/.codex/`. It also configures other supported harnesses. Owner text outside
managed sections and unrelated settings are preserved. Global init does not
create repository policy or command configuration.

## Response contract

Automatic hook responses use exit 0. They cannot deny a tool or block completion.

| Result | Codex response |
| --- | --- |
| Session or prompt guidance | `hookSpecificOutput.additionalContext` |
| Post-tool findings | `hookSpecificOutput.additionalContext` |
| Stop or subagent-stop | `systemMessage` explaining that no checks ran |
| No feedback or pre-tool observation | Empty stdout |

Post-tool feedback states that the tool already ran. It cannot undo side effects.
PreToolUse and PermissionRequest do not enforce legacy command/path lists.
Direct commits do not run a full check or require LGTM evidence. Completion does
not inspect assistant claims or require a baseline or transcript.

## Explicit checking

An explicit check, `lgtm check --tier full`, runs bounded checks and writes evidence.
An actual error-level failed check returns exit status `2`; operational errors return
nonzero. Missing tools and incomplete verification stay unverified rather than
being relabeled passed. An exit-0 result alone does not prove every check ran.

CI or an owner-installed Git hook can choose to run this command. Those are
separate, explicit integrations, not automatic Codex commit authorization.

## Native rules retirement

LGTM no longer generates `.codex/rules/lgtm.rules` command bans. Fresh installs
do not create that file. A normal init or managed refresh replaces an old file
only when it has LGTM's generated header, leaving an inert comment-only file.
This also works when the old `.lgtm/execpolicy.json` source is absent.

User-authored rules without that ownership header, symlink targets, and unreadable
files are preserved. Existing legacy policy data is not rewritten into native
rules. LGTM does not change Codex's own permissions, sandbox, or hook trust state.

## Capability and trust limits

Codex controls whether a project or hook is discovered, trusted, and run.
Review changed hook definitions in `/hooks`; LGTM does not auto-approve them.
Worktree, desktop, MCP, custom-tool, and shell interception coverage is not
universal. An unknown execution path is not a claim of verified observation.
No LGTM hook is an operating-system security boundary.

| Execution path | Observation boundary |
| --- | --- |
| `Bash` | Known payloads support pre/post observation, not permission denial. |
| `apply_patch` and `Edit`/`Write` | Touched-file feedback needs a recognized file path. |
| MCP tools | Parsed names do not prove tool-specific observation. |
| `exec_command` | Compatibility alias; verify the installed host's matcher. |
| `unified_exec` | Interception is incomplete and depends on the host. |
| WebSearch and other tools | Tool-specific observation is unsupported unless implemented. |

Run the optional local conformance smoke without an interactive session:

```bash
LGTM_CODEX_CONFORMANCE=1 cargo test --locked --test codex_conformance -- --nocapture
```

Without that opt-in or a local Codex CLI, the result is not applicable.
Adapter tests alone are not live Codex proof. The offline lifecycle and native
rule tests run through `cargo test --test codex_e2e --test codex_adapter --test init
--test managed_upgrade`.

See [the architecture decision](../adr/0017-observer-hooks-and-explicit-checks.md).
