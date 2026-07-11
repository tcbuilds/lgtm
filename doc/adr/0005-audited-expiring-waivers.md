# ADR-0005: Narrow audited expiring waivers

## Status

Accepted

## Date

2026-07-11

## Supersedes

This ADR supersedes only ADR-0003's no-waiver decision. ADR-0003's hard-blocking Stop gate remains accepted.

## Context

ADR-0003 deferred waiver machinery unless the no-waiver wall blocked legitimate dogfood work more than once. That trigger has now occurred twice. Severity overrides do not capture a time limit, owner, or exception reason.

## Decision

Add `lgtm waive --rule RULE_ID --reason REASON --owner OWNER --expires YYYY-MM-DD`.

Waivers are repository-local, deterministic, bounded, atomically persisted in `.lgtm/waivers.json`, and copied into Stop evidence. Active waivers produce the distinct `waived` result status. Expired or malformed waivers are configuration errors and never apply. Security, authentication, secrets, SQL parameterization, and destructive-operation rules cannot be waived.

## Consequences

Legitimate non-security exceptions can proceed without hiding the accepted risk. Every exception has an accountable owner, reason, and UTC expiry. The hard Stop gate remains unchanged for unwaived and protected rules.
