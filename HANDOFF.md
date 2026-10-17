# Handoff — M26 implementation in progress

> Updated: 2026-10-17T15:39:09.897Z
> Branch: `docs/jev-v2-file-reads`
> M26 review baseline: `56d70055ea3ff21275fa3c9ec77c792f328cc54f`

## Current authority

The owner authorized **all M26**, commits in verified slices, and Pi review
**once over the whole phase at the end**, not per slice. Implementation is
direct; no writer subagents were launched.

Jev is on by default and must fail gracefully without Jev/API/auth/provider.
Normal tools and deterministic LGTM enforcement keep working. Existing global
`~/.pi/agent/extensions/jev-auto.ts` stays unchanged. Do not revive jev-classify.

The owner approved a live replay budget of **$1 maximum, at most 64 calls,
16 KiB of reviewed public LGTM source per call**. Do not send credentials,
private logs, or user transcripts. Stop if cost cannot be bounded. No actual
global deployment, release, model switch, or package install is authorized.

## Scope and plan

Read `jev_v2.md`, `research.md`, and local `implementation_plan.md` **M26**.
The detailed plan is gitignored; do not force-add it. Older M20/M22 work is
unrelated. Old M23 checkboxes are stale; the Pi adapter already exists.

Nine slices:
1. Managed single-file questions.
2. Bounded multi-file preview/scouting.
3. Question preflight and real replay.
4. Separate review-risk flags.
5. Scope/evidence consistency advice.
6. Diagnostic triage.
7. Optional compaction advice.
8. Lower-priority suspicious-output advice.
9. Measured cache decision; no cache unless justified.

## Completed setup

- Owner approved merging upstream. The five upstream fixes merged cleanly.
- Review baseline is the merge above, after compatibility change `f833bf3`.
- Baseline: 68 Pi/init/refresh integration tests passed.
- Context7 is unavailable; installed Pi 1.3.0 docs/source were inspected.
- Native classifier: OpenRouter `~typesafe/jev-latest`; catalog input price
  observed as $0.042/M tokens. This is not a guarantee of future pricing.
- Pi-subagents 0.50.0 and executable reviewer profile are available.
  No final review has been launched. Apply the governing model-routing policy
  at dispatch and report any skill/global policy mismatch explicitly.

## Slice 26.1

Implementation is present; final phase review is still pending.

- `templates/pi/jev.js`: rendered fragment, not another installed extension.
  Registers `lgtm_jev_files` through existing session startup, with codemode
  exposure and no startup inference. Uses native classifier and governed reads.
- `src/init/pi.rs`: expands the fragment before hashing/rendering, retains
  previous project/global canonical digests, and uses one extension-location
  accessor. Existing fake-runtime tests still work.
- Single-file boolean question: 16 KiB, 1,500 lines, five-second deadline.
  Trusted workspace, file identity, prohibited paths, credential guards,
  stale snapshots, cancellation, provider errors, and metadata privacy checked.
- Native read filters remain authoritative. Only a surviving original source
  block is classified; appended LGTM guidance is not treated as file content.
- `tests/jev_pi.rs` and `tests/fixtures/pi/jev_integration.cjs` exercise the
  generated extension with actual file IO and a fake paid-provider boundary.
  No new unit tests or live-code mock data.
- User guide updated in `doc/adapters/pi.md`.

Verified:
- Regression first failed because the operation did not exist.
- 61 focused integration checks passed after implementation.
- Project, global, and combined loading exercise one effective registration.
- Native Pi argument validation accepted the generated schema.
- Scratch pre-Jev upgrades preserved exact backups and refresh idempotence.
- Rust/JS diagnostics passed; Markdown has no supported LSP route.
- Whole-suite tests, Clippy, live replay, mutation probes, and final phase
  review remain pending. No paid replay calls have been launched yet.

## Continue

Commit verified 26.1 paths only, then implement 26.2. Keep plan checkboxes
unchecked until the whole-phase gate is complete; record slice-local evidence.
Reuse native codemode for general state classification; add no second client,
private command runner, database, browser stack, or universal per-turn hook.

Use Pi session metadata for safe decisions/usage, never source/question bodies.
Keep malformed, unavailable, no-match, and stale outcomes distinct.
No semantic judgment creates command proof or overrides a deterministic gate.

Unrelated untracked paths: `.killer-whale/`, `.pi/`, `triage.md`. Preserve them.
Task scratch directory: `/tmp/lgtm-m26.w7q1OW` (baseline binary/source and upgrade
probes). Clean it after review unless it is needed as retained failure evidence.

The historical August handoff is `HANDOFF.2026-08-13.md`.
