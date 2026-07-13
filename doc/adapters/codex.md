# Codex adapter

LGTM supports Codex through the same policy engine, but Codex needs its own
input and output adapter. Select it explicitly; LGTM never guesses an adapter
from a payload:

```bash
lgtm init --agent codex
lgtm hook session-start --adapter codex
lgtm check --tier full
```

`lgtm init --agent codex` writes or merges `.codex/hooks.json` without removing
other hooks. It registers `SessionStart`, `UserPromptSubmit`, `PreToolUse`,
`PostToolUse`, `PermissionRequest`, `SubagentStart`, `SubagentStop`, and
`Stop`. Edit and command matchers include Codex's `apply_patch`, `Edit`,
`Write`, `exec_command`, `unified_exec`, and `Bash` names. Re-running init is
idempotent. When `lgtm` is installed at a stable absolute path, init records
that path so Codex does not depend on the session's `PATH`; source-tree runs
fall back to the portable `lgtm` command. Re-run init if the binary moves.

## Response contract

LGTM deliberately emits every enforcement response as explicit JSON on stdout
with exit status `0`. Current Codex also accepts exit status `2` with a reason
on stderr, but using JSON/exit-0 keeps all LGTM outcomes deterministic across
events and avoids relying on Claude-specific framing.

| Normalized result | Codex response |
| --- | --- |
| `Deny` on `PreToolUse` | `hookSpecificOutput.permissionDecision = "deny"` plus a reason |
| `BlockStop` on `PostToolUse` or `Stop` | `{"decision":"block","reason":"..."}` continuation feedback |
| `InjectContext` on session/prompt/post-tool events | `hookSpecificOutput.additionalContext` |
| `InjectContext` on `PreToolUse` | top-level `systemMessage` fallback; `additionalContext` is not relied on there |
| `Allow` | empty stdout, exit `0` |

The adapter rejects event/response combinations it cannot encode. It never
adds unsupported fields such as `continue` or `stopReason` to an enforcement
decision. Evidence, waivers, rule IDs, and failure meanings remain shared with
the Claude adapter.

`Stop` with `decision: "block"` asks Codex to continue with a new repair
prompt; it does not permanently reject the turn. `PostToolUse` runs after the
tool has completed, so its feedback cannot undo side effects that already ran.
LGTM prefixes PostToolUse feedback with that fact so the agent does not mistake
post-execution feedback for a pre-execution denial.

## Trust and platform limits

Codex SHA-256-pins hook definitions. After installation, review and trust the
LGTM entries in Codex's `/hooks` screen. Trust state belongs to Codex's own
configuration, so `lgtm init` does not silently edit or auto-approve it. If a
hook is not trusted, Codex may skip it without running the command.

Project hooks also depend on Codex discovering and trusting the project-local
`.codex/hooks.json`. Worktree and desktop discovery behavior is controlled by
Codex, not LGTM; keep CI and the Git pre-push full gate enabled as the
bypass-resistant backstop.

Codex's `notify`-style hooks are observation-only and cannot enforce a deny or
Stop continuation. The current Codex runtime also has incomplete interception
for `unified_exec` and equivalent shell paths, so native hooks are not a
universal shell-security boundary. MCP tools cannot force a final verification
call, so a native Codex Stop hook or `lgtm check --tier full` remains necessary
for completion enforcement.

## Execution-path capability matrix

| Path | LGTM status | Meaning |
| --- | --- | --- |
| `Bash` | supported for simple shell calls | PreToolUse can deny before execution; PostToolUse can only report after execution |
| `apply_patch` (`Edit`/`Write` aliases) | supported | File-target checks and fast scans run when the payload includes a file path |
| MCP tools | parsed, not universally policy-scanned | Unknown tool names are preserved; tool-specific coverage must be added explicitly |
| `exec_command` | compatibility alias | Kept for older Codex payloads; verify the installed Codex build's matcher behavior |
| `unified_exec` | incomplete | Codex interception is not universal; do not treat this as a shell-security boundary |
| WebSearch and other non-shell tools | unsupported | No LGTM PreToolUse enforcement is claimed |

The Git pre-push wrapper, CI `lgtm check --tier full`, and repository policy
remain the bypass-resistant backstop for paths native hooks cannot intercept.

To run the optional local conformance smoke test without launching an
interactive Codex session:

```bash
LGTM_CODEX_CONFORMANCE=1 cargo test --locked --test codex_conformance -- --nocapture
```

Without the environment variable, or without a local Codex CLI, the test is
reported as `not_applicable`; adapter tests are not presented as live Codex
proof.

## Optional execpolicy backstop

Create `.lgtm/execpolicy.json` when a project wants a second command-level net:

```json
{
  "prohibited_commands": [["git", "reset", "--hard"]],
  "prohibited_paths": ["secrets/**"]
}
```

Codex command prefixes are generated at `.codex/rules/lgtm.rules` as deny
`prefix_rule` entries. Existing rule files are preserved. Codex prefix rules
match command argv, not filesystem targets, so path patterns remain enforced by
LGTM's PreToolUse hook and are recorded as explanatory comments only.

For headless or non-hooked runs, use `lgtm check --tier full`. It uses the same
bounded commands, evidence schema, and exit semantics as CI. Missing tools are
reported as `unverified`, never silently passed.
