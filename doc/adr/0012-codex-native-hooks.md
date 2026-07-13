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

## Decision

Keep policy and evidence agent-neutral, and add a dedicated `CodexAdapter`.
Select it explicitly with `--adapter codex`; never sniff the payload to choose a
harness. Codex responses are JSON on stdout with exit status `0`: deny through
the PreToolUse permission envelope, block through `decision: "block"`, and
inject context through event-supported context fields. Codex hook trust remains
user-controlled; LGTM prints the `/hooks` trust step but does not edit Codex's
private trust state.

## Consequences

- Claude output and lifecycle behavior remain unchanged.
- Codex gets native hooks while CI and pre-push remain the final backstop.
- Exact-byte adapter tests and end-to-end payload replays protect the wire
  contract.
- Codex-specific trust, worktree discovery, and UI behavior remain documented
  limitations rather than hidden assumptions.
