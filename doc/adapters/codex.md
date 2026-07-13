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
`PostToolUse`, and `Stop`. Edit and command matchers include Codex's
`apply_patch`, `Edit`, `Write`, `exec_command`, `unified_exec`, and `Bash`
names. Re-running init is idempotent.

## Response contract

Every Codex enforcement response is explicit JSON on stdout with exit status
`0`. Codex does not use Claude's Stop exit status `2` as the enforcement signal.

| Normalized result | Codex response |
| --- | --- |
| `Deny` on `PreToolUse` | `hookSpecificOutput.permissionDecision = "deny"` plus a reason |
| `BlockStop` on `PostToolUse` or `Stop` | `{"decision":"block","reason":"..."}` |
| `InjectContext` on session/prompt/post-tool events | `hookSpecificOutput.additionalContext` |
| `InjectContext` on `PreToolUse` | top-level `systemMessage` fallback; `additionalContext` is not relied on there |
| `Allow` | empty stdout, exit `0` |

The adapter rejects event/response combinations it cannot encode. It never
adds unsupported fields such as `continue` or `stopReason` to an enforcement
decision. Evidence, waivers, rule IDs, and failure meanings remain shared with
the Claude adapter.

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
Stop block. MCP tools also cannot force a final verification call, so a native
Codex Stop hook or `lgtm check --tier full` remains necessary for completion
enforcement.

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
