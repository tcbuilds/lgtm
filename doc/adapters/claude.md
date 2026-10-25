# Claude Code observer hooks

This guide describes the observer-only source change. It is not a claim that
an installed release or running Claude session has already changed.

## Automatic behavior

- Session and prompt hooks provide relevant engineering guidance.
- PreToolUse records a baseline and shell tracking when possible. It does not
  deny commands, reject edit paths, rewrite Git commands, or request approval.
- PostToolUse can scan touched files and record findings. Its response is
  nonblocking `hookSpecificOutput.additionalContext`, not a block decision.
- Stop reports that no completion checks ran. It does not inspect claims, run
  repository commands, or prevent completion.

A post-tool finding cannot undo a completed side effect. LGTM says this in the
feedback. Secret values remain redacted.

## Request a check

Run verification when you or CI need it:

```bash
lgtm check --tier full
lgtm check --workspace WORKSPACE_ID --tier targeted
```

Use an actual workspace ID from `.lgtm/config.json`. Error-level failed checks
return exit 2. Operational errors return nonzero. Warnings and unavailable
checks remain visible; an exit-0 result alone is not proof that every check
passed. Evidence is stored under `.lgtm/evidence/`.

Commits use ordinary Git commands. The guarded-commit wrapper, staged-index
assessment, approval challenges, and post-confirmation revalidation are removed.
There is no waiver or permissive mode that restores that automatic flow.

## Host permissions and privacy

Claude still owns its permissions and sandbox. LGTM does not grant permission,
bypass a denied operation, or remove owner-authored settings. Init's existing
settings merge and ownership protections remain separate from the observer
response. See the official
[hooks reference](https://code.claude.com/docs/en/hooks).

Timeouts, bounded input/output, secret redaction, and process cleanup remain in
place. A failure in LGTM must be visible without vetoing the development tool.

## Verification and rollout

Run `cargo test --test pre_tool_use --test hook_safety --test adapter_golden
--test post_tool_use --test commands` for the observer and explicit-check
contracts. Tests send hook requests; they do not execute destructive commands.

Source changes alone do not replace an installed binary or loaded hooks.
Update and refresh only through an owner-approved rollout, then restart the
agent as needed. Keep custom settings and existing backups. Rollback requires
the matching prior binary and hook files; it restores the older behavior.

See [the architecture decision](../adr/0017-observer-hooks-and-explicit-checks.md)
for scope and trade-offs.
