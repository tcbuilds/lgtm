# ADR-0014: Run the full gate before agent commits

## Status

Accepted

## Date

2026-08-12

## Supersedes

The tier-placement part of
[ADR-0011](0011-hook-roots-and-tiered-gates.md). ADR-0011's root-resolution and
workspace-scoping decisions remain accepted.

## Context

Stop fires whenever an agent tries to yield control, including ordinary
conversation turns. Running a repository's full test, build, and coverage
suite there repeats expensive work even when the agent is not creating a
checkpoint. In large repositories this made Stop take several minutes and
produced lifecycle noise unrelated to the user's request.

The agent shell hook already sees a pending `git commit` before it executes.
That boundary is late enough to validate the complete staged change and early
enough to deny creation of an unverified commit.

## Decision

PostToolUse keeps the `fast` tier. Stop defaults to `targeted`. When Claude Code
or Codex attempts a direct `git commit`, PreToolUse runs the `full` tier and
denies the command if a required check fails. A successful full result may be
reused only for the same agent session, policy and binary versions, config
digest, and touched-file digest.

Explicit `lgtm check --tier full`, the optional Git pre-push hook, and CI remain
available as full gates for humans, unsupported agents, and bypass-resistant
remote enforcement. LGTM does not install or overwrite a repository
`pre-commit` hook.

## Consequences

Ordinary Stop events stay responsive and do not repeatedly run full suites.
Agent-authored commits still require current full evidence. An unchanged retry
after a denied commit does not repeat successful work. Shell indirection such
as `sh -c 'git commit ...'` is outside direct command detection; pre-push and CI
remain the backstops for indirect or bypassed commits.
