# ADR-0017: Observe automatically and check on demand

## Status

Accepted for source implementation. Installed rollout is a separate owner action.

## Date

2026-10-24

## Supersedes

This replaces automatic tool, commit, and completion vetoes from
[ADR-0003](0003-hard-blocking-stop-gate-no-waivers.md),
[ADR-0011](0011-hook-roots-and-tiered-gates.md),
[ADR-0012](0012-codex-native-hooks.md),
[ADR-0014](0014-full-gate-before-agent-commit.md), and the automatic-gate parts of
[ADR-0015](0015-aggregate-command-budget.md).

Root resolution, explicit command scope and budgets, and
[process containment](0016-configured-command-descendant-containment.md) remain.

## Context

Automatic permission checks made LGTM control whether development could continue.
Commit parsing, approval challenges, runtime checks, and repeated verification
added failure paths that were separate from the requested code change.

The owner chose removal, not another permissive mode or waiver layer. LGTM must
still report real check results without claiming that an unavailable check passed.

## Decision

Automatic hooks observe and advise:

- PreToolUse and PermissionRequest never deny or approve an operation. Baseline
  capture and shell attribution remain best effort. A commit is an ordinary
  shell request, not a trigger for verification.
- PostToolUse may scan touched files, store findings, and add nonblocking context.
  The tool already ran, so feedback cannot undo its side effects.
- Stop and subagent-stop report completion without repository verification,
  claim auditing, or a completion veto.
- The shared adapter interface cannot express denial, approval, or BlockStop.
  The guarded-commit wrapper and staged-commit assessment are removed.
- Pi makes one bounded observer request per tool event. There is no approval
  dialog, commit-specific runtime gate, or notice revalidation transaction.
- Codex init no longer creates native command bans. Init and managed refresh
  retire only files with LGTM's generated ownership header. User rules,
  symlink targets, unreadable files, and host permission settings are preserved.

Request repository verification explicitly:

```bash
lgtm check --tier full
lgtm check --workspace WORKSPACE_ID --tier targeted
```

Use an actual configured workspace ID. Error-level failed checks return exit 2.
Operational errors return nonzero. Warnings and unverified results remain visible.
An exit-0 result alone does not prove that every requested check passed.

Optional CI or an owner-installed Git hook may run this explicit command.
Neither is implicit agent commit authorization.

## What stays protected

Host permissions and sandbox rules still belong to the host. LGTM does not
bypass them. Bounded reads and output, command deadlines, cancellation,
descendant cleanup, secret redaction, and installer ownership checks remain.

Optional Jev tools still check trusted runtime identity, governed reads, and
private data before sending advisory requests. A failed or busy advisory request
cannot veto normal development. Existing routing limits and provider settings
do not change.

## Consequences

Agents can continue when LGTM cannot observe or verify something. They must not
describe that uncertainty as a passed check. Verification cost moves to explicit
requests and owner-configured CI, rather than every completion or commit attempt.

A full check is evidence of what ran at that time. It does not approve a later
commit. Concurrent edits and unobserved tools remain limits of file attribution.

## Validation and rollout

Integration checks cover non-vetoing tools and completion, no automatic command
execution, explicit command failure, advisory findings, rule retirement, privacy,
timeouts, cancellation, and cleanup. Native host discovery and UI support still
require their own runtime checks; offline fixtures are not live-host proof.

Changing source does not update an installed binary or loaded extension.
Roll out only with owner approval, preserve custom files, and reload running
agents afterward. Rollback needs the matching prior binary and hooks and restores
their older behavior; do not silently restore it as a compatibility mode.
