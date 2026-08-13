# ADR-0015: Bound aggregate repository-command execution

## Status

Accepted

## Date

2026-08-13

## Context

V2 repository commands already have individual 1–3600 second timeouts, but a
configuration can select many structured commands and coverage commands. The
Stop-facing path runs selected structured commands before full-tier coverage,
so independent timeouts can still produce an unbounded total gate duration.
Coverage records also had no count bound, and an interrupted coverage phase was
represented only as evidence, which could leave a truncated gate looking clean.

## Decision

V2 accepts at most 64 workspaces, 64 structured commands in aggregate across
those workspaces, and 64 coverage commands in aggregate. The JSON schema
documents 64-item array limits, while typed validation enforces the aggregate
totals. V1's existing 64-command limit and migration behavior remain intact.

The Stop-facing repository-command runner uses one monotonic
`STOP_COMMAND_BUDGET` of 3,600 seconds. Each process receives the lesser of
its configured timeout and the remaining gate time. Selected structured
commands run in their existing order; full-tier coverage follows them under the
same budget. Targeted Stop remains targeted and does not run coverage, while
explicit full checks and the pre-commit full gate use the shared structured and
coverage budget.

When the budget expires, the existing bounded runner terminates the active
process group. The active structured command and every later structured command
are recorded in order with null exit codes and unverified results. Active or
unrun coverage commands are recorded in order with `status: "unverified"` and
no metrics. A gate-level unverified repository-command result makes the Stop
summary say `action required`; an exit code observed after the deadline is not
classified as passed.

## Consequences

Repository-command gates have a fixed one-hour wall-clock ceiling without a
new dependency, scheduler, or user override. Operators can distinguish a
completed pass from an incomplete gate using existing nullable evidence fields
and the unverified status. A large repository may need a later explicit
decision about a larger budget, staged selection, or parallel execution; this
 decision does not add those escape hatches.
