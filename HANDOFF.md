# Handoff — Jev v2 belongs in LGTM init

> Updated: 2026-10-17T14:56:18.736Z
> Branch: `docs/jev-v2-file-reads`; latest observed code: `f833bf3`.
> Jev research originally compared enforcement code base `29af281`.
> Revalidate after code/global-hook changes or a branch change.
> Local main was five commits behind `origin/main` (`75124a5`); no merge or
> source update was performed for this docs-only checkpoint.

## Mission context

The owner wants a simple Jev file-question capability **shipped by LGTM's
Pi init flow**, building on the existing native `jev-auto.ts` approach.
This is not a standalone package project. **Do not revive jev-classify.**

Read [jev_v2.md](jev_v2.md) first. It is the short explanation of the idea.
This request authorized documentation only, not implementation, installation,
global settings changes, or another paid benchmark.

## What changed

- Added `jev_v2.md` in this LGTM repository; the owner then approved adding
  the ranked follow-on recommendations from the repo comparison.
- Recorded the 13-repo survey in `research.md`. The owner then approved adding
  its top three candidates and four useful refinements to `jev_v2.md`.
- Replaced the stale August issue-41 handoff with this current direction.
- Preserved its exact contents in
  [HANDOFF.2026-08-13.md](HANDOFF.2026-08-13.md). That file is historical,
  not current branch/worktree/release guidance.
- Added M26 to the local, gitignored `implementation_plan.md` from the latest
  `/roadmap jev_v2.md` request; prior milestones were preserved. The owner chose
  default-on Jev availability with graceful fallback, not session opt-in.
- This planning checkpoint changes no production source, templates, manifests,
  or enforcement behavior.
- Documentation is on a separate branch so unrelated upstream code changes
  and local untracked files are not mixed into this checkpoint.

## Intended behavior

- A small Pi operation reads selected files, calls Pi's native classifier
  API, and returns typed answers/probabilities instead of raw file contents.
- The operation is callable from native codemode. No new provider client,
  secret store, sandbox, or general-purpose tool router is needed.
- Normal reads remain available. Read actual code before edits, quotes,
  or correctness claims.
- Init installs/updates the helper without requiring authentication or
  making classifier requests. Runtime failures must not break ordinary
  reads or LGTM enforcement.
- Existing automatic tool routing is a separate concern. Do not silently
  change its default, model alias, or the owner's installed global hook.
- Preserve workspace boundaries, reject credentials, bound work, and report
  truncated/skipped files. Uncertain results must not hide needed files.

## Approved follow-on recommendations

Earlier requests added these to the proposal. The latest `/roadmap` request
now plans them in local `implementation_plan.md` M26. Full scope is in
[jev_v2.md](jev_v2.md#follow-on-recommendations).

1. Level 4: explicit uncertainty and safe normal-inspection fallbacks.
2. Level 3: separate diff-risk questions to focus review, never waive checks.
3. Level 7: optional task-boundary advice using Pi's existing compaction.
4. Level 6, lower priority: suspicious external-output warnings only;
   report inspected coverage and do not imply that unflagged text is safe.

The owner also approved adding these from the wider survey:

1. Question preflight and replay evaluation, first strengthening uncertainty.
2. Advisory scope/evidence consistency checks, never execution proof.
3. Diagnostic triage over approved, minimized excerpts using governed tools.

The approved refinements are outbound-work previews, source-snapshot
identity, recommendation-versus-action records, and bounded caching only
when measurements justify it. See
[the expanded recommendations](jev_v2.md#recommendations-from-the-wider-survey)
and [refinements](jev_v2.md#useful-refinements).

[research.md](research.md) keeps the source matrix and limits of the survey.
It records the research-time candidate assessment; this handoff and the
proposal record the later approval to include those candidates in the doc.
Selective context pruning and the SQL/browser package stacks were not added.

Levels 8–9 remain the planned file-question capability. Native codemode
already provides much of Level 10's general typed-question capability;
do not add a duplicate client or private command runner. Do not add
automatic model switching, classifier-based permission overrides, or
classifier verdicts as proof of test success.

This expands the documentation only. No implementation, rollout, paid
evaluation, or global configuration change was authorized.

## Existing code to inspect before implementation

CodeGraph was used to locate these seams:

- `src/init/pi.rs` — embedded Pi extension, rendering, ownership checks,
  collision preservation, and backups.
- `src/init/pi_config.rs` and `templates/pi/` — managed Pi settings.
- `src/init/global.rs` and `src/init/runner.rs` — global/project init paths.
- `src/init/managed_refresh.rs` and `src/init/pi_installations.rs` —
  tracked installation refresh.
- `src/pi_state.rs` — existing Pi enforcement/attestation boundaries.

No Jev-specific implementation was found in the relevant local init source
or the checked `origin/main` source/templates/docs. The live reference is
`~/.pi/agent/extensions/jev-auto.ts`, which currently routes tools, not files.
Future code must use LGTM's managed install/refresh rules and must not
overwrite a user's unrelated extension or change hard-stop enforcement.

## Evidence and rejected directions

- Instruction-only classifier use was inconsistent.
- The separate fixed-vocabulary router produced bad live recommendations
  and was removed. Do not restart that design or its old roadmap.
- Routing evidence was mixed: deferred-tool preloading saved round trips,
  while directly declared tools and small real builds showed no reliable gain.
- None of those experiments measured selective Jev file reads.
- CodeGraph `explore` already returns source. Do not load that source into
  the main context and then claim Jev avoided reading it.
- Author code for Levels 3–4 and 6–10 was inspected in
  [disler/ten-levels-of-jev](https://github.com/disler/ten-levels-of-jev).
  Direct video retrieval was unavailable; do not claim it was watched.
- Do not copy the demo's cost ratios as measurements of this server.

Local evidence remains outside this repository:
`~/jev-benchmark/hard-report.md`,
`~/jev-benchmark/build/REPORT.md`, and
`~/jev-benchmark/nemotron-report.md`.
Do not commit raw benchmark artifacts or treat their old task scores as
evidence that file reads already work.

## State and checks

At roadmap start, unrelated Pi source/tests/docs edits were present; they
landed separately during planning. Preserve the unrelated untracked
`.killer-whale/`, `.pi/`, and `triage.md`.

Concurrent Pi compatibility work was committed separately as `f833bf3`
(`src/init/pi.rs`, `tests/init_pi.rs`, and `doc/adapters/pi.md`). It was not
implemented by this planning task. Re-read it before M26 production edits;
CodeGraph reported index drift. Older source observations refer to their
recorded base, not an acceptance review of that change.

- `cargo fmt --check`: passed, exit 0, after the compatibility commit landed.
- `cargo build --locked --offline`: passed, exit 0; this is not a full review
  of the separate compatibility change.
- Document structure, nine unchecked M26 slices, spec coverage, source/test
  references, local links, and ignored-plan status: checked.
- Full Rust tests/Clippy: not rerun for this docs-only change.
- Markdown LSP: unavailable; no configured server supports these files.
- This checkpoint adds documentation only. Review concurrent source edits
  before claiming that any Jev capability is implemented.

## Open decisions

- Resolved: on by default; missing Jev/API/auth/provider must leave ordinary
  tools and deterministic LGTM checks usable. Init makes no classifier calls.
- Plan: reuse the existing managed `lgtm.ts` install/refresh path; verify one
  effective operation when project and global extensions coexist.
- Still open before paid evaluation: owner-approved corpus/data handling and
  budget. No paid replay or global install was authorized by `/roadmap`.

These decisions do not authorize new work by themselves.

## Continue here

1. Read `jev_v2.md`, this handoff, and local `implementation_plan.md` **M26**.
2. M26 has nine unchecked slices: managed single-file questions; bounded batch
   preview/scouting; preflight/replay; review focus; scope/evidence checks;
   diagnostic triage; compaction advice; lower-priority output warnings; and a
   conditional cache decision. M20/M22 remain unrelated retained work; M23's
   older status is stale. None is the target of this request.
3. Keep all work in LGTM. Before code work, reconcile upstream and `f833bf3`,
   re-read changed files, and recheck init/refresh callers and Pi compatibility.
4. Wait for an explicit implementation request. Start with M26.1 if approved.
   Default-on means the capability is available, not automatic scanning or
   per-turn calls. Paid replay needs separate data/budget approval.
5. The detailed plan is intentionally local/gitignored; do not force-add it.
   This tracked handoff summarizes its scope, and `jev_v2.md` remains the spec.

## Resume bootstrap

```text
/warmup
Read /home/ubuntu/lgtm/jev_v2.md
Read /home/ubuntu/lgtm/HANDOFF.md
```
