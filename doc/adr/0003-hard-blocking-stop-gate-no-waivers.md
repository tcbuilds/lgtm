# ADR-0003: Hard-blocking Stop gate with no waiver machinery in MVP

## Status

Accepted

## Date

2026-07-11

## Context

The core value proposition of `lgtm` is that "LGTM" should actually mean something: the harness must be able to prevent an agent from declaring a task complete while unresolved MUST violations remain. The Claude Code Stop hook is the final gate in the lifecycle — it runs required repository commands, verifies claimed tests actually ran, inspects the final diff, and writes the evidence record.

Two design tensions bear on this gate:

1. **How strict should the gate be?** A soft gate that warns but lets the agent finish would preserve the same failure mode the tool exists to eliminate: an agent claiming compliance without it being true.
2. **Should there be an escape hatch (a waiver flow) for legitimate MUST exceptions in the MVP?** The spec's position is direct: MUST means must, with waiver machinery deferred to post-MVP.

The MVP is scoped to prove the full loop (select → inject → check → evidence) on one language (Python) against one dogfood repo, so scope discipline matters.

## Decision

Ship a hard-blocking Stop gate and no waiver machinery in the MVP.

- The Stop hook exits 2 with precise repair instructions when unresolved MUST violations exist. This hard block "is the whole point."
- There is no waiver flow in the MVP. MUST means must.
- The only relief valve is a repo-level severity override in `.lgtm/config.json` for rules explicitly marked `overridable: true`. Every override is recorded in the evidence ledger. Security-critical rules are `overridable: false` and cannot be downgraded.
- One deliberate exception to hard-blocking: a MUST rule that is `unverified` because its wrapped tool is missing is surfaced prominently in the Stop report but does not hard-block, because blocking on missing tooling would make fresh machines unusable (see the missing-tool degradation decision in ADR-0004).

## Consequences

- The gate delivers the product's central promise: agents cannot finish over the top of unresolved MUST violations, and cannot claim checks passed that were not run.
- **Accepted risk:** hard block plus no waivers means a legitimate MUST exception has no escape hatch in the MVP.
- **Fallback for genuine emergencies:** a `.lgtm/config.json` severity override on an `overridable: true` rule, recorded in evidence. Security-critical rules remain non-overridable, so the fallback cannot be used to silence the highest-risk rules.
- **Trigger to reconsider:** if the absence of a waiver flow bites more than once during dogfooding, the waiver flow gets pulled forward from the post-MVP backlog. The waiver flow (`lgtm waive` with reason/owner/expiry) is already specified as a future capability for exactly this reason.
- Scope stays tight for the MVP, letting the enforcement loop be proven before investing in waiver auditing, expiry, and ownership tracking.
