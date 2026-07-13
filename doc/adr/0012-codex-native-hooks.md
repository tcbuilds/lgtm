# ADR-0012: Native Codex hook adapter

## Status

Accepted

## Date

2026-07-12

## Supersedes

ADR-0004 decision 10 (Codex adapter deferred as CI-only integration).

## Context

The Claude adapter proved the shared policy, evidence, and hard-stop loop.
Codex now exposes stable lifecycle hooks, but its JSON response envelopes and
trust model differ from Claude's. Reusing Claude output or exit codes would
silently weaken enforcement because Codex expects explicit JSON decisions.
Codex also has incomplete interception for some shell execution paths, so the
adapter cannot claim universal command coverage.

## Decision

Keep policy and evidence agent-neutral, and add a dedicated `CodexAdapter`.
Select it explicitly with `--adapter codex`; never sniff the payload to choose a
harness. LGTM emits JSON on stdout with exit status `0`: deny through the
PreToolUse permission envelope, request continuation through `decision:
"block"`, and inject context through event-supported context fields. Current
Codex also accepts exit status `2` with stderr, but LGTM does not depend on it.
Codex hook trust remains user-controlled; LGTM prints the `/hooks` trust step
but does not edit Codex's private trust state.

## Consequences

- Claude output and lifecycle behavior remain unchanged.
- Codex gets native hooks while CI and pre-push remain the final backstop.
- Exact-byte adapter tests and end-to-end payload replays protect the wire
  contract.
- PostToolUse feedback cannot undo completed side effects, and Stop block
  decisions request a continuation rather than permanently rejecting a turn.
- Codex-specific trust, worktree discovery, and UI behavior remain documented
  limitations rather than hidden assumptions.
