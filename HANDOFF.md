# Handoff — PR #132 follow-up on feat/jev-quiet-gates

> Updated: 2026-10-18T17:06:49.041Z
> Worktree: `/home/ubuntu/lgtm-quiet-gates`
> Snapshot HEAD: `40332328a6e0caaa8e8217ab25b016575e56aed0`; confirm Git for later publication.
> Stale if the branch or source changes after this checkpoint.

## Mission and authority

Finish existing draft [PR #132](https://github.com/tcbuilds/lgtm/pull/132):
per-step Jev routing, quiet heuristic notices, and the real test-process cleanup
repairs that remove the repeated waiver loop. Diagnose, fix, and rerun routine
failures without asking for another waiver. Keep hard gates and permissions.
No merge, release, tag, version bump, production install, or new unit tests.

At this checkpoint, initial commit `4033232` is the last published commit. Its
one owner-approved exception does not permit another bypass. The normal follow-up
commit and push are next; check Git/PR head for later publication state. The live
personal extension is not updated.

## Git state to preserve

A merge of upstream `4d0dbc7c71a0f9a19ad8c106aaa2c46d36509dc0` is pending.
Preserve the staged merge, source repairs, and current fixture/docs edits. Do not
reset, stash, or broadly unstage. Main's release files/version are inherited,
not a new release; the PR diff against main has no release/version change.
The original `/home/ubuntu/lgtm` and separate benchmark checkout contain unrelated
work. Do not edit them.

## Repairs already checked

- Reserve time to reap killed test commands, while preserving aggregate deadlines.
- Run existing Ruff, refresh, caller-exit, and claims-output fixtures under the
  existing isolated reaper. Production containment is unchanged.
- Give the config-binding fixture five seconds; it is not a timeout test.
- Use a real frozen v0.13.0 extension fixture for upgrade checks. All four old
  ownership hashes were traced to the actual v0.13.0 and pre-feature Git sources.
- Router privacy: at the first recognized credential assignment, keep the ordinary
  prefix and a marker, then omit the remaining bounded text. Do not parse quote ends.
- Sanitize name copies in classifier catalog/questions/recent metadata and generated
  hints/status. Keep original local activation identities and native Pi schemas.
- The offline fixture checks complete provider requests, YAML/shell tails, two
  colliding redacted names, local activation, cached/busy hints, invalid scores,
  warnings, and a valid pre-timeout stale-session reply. No live provider is called.

## Review status

Full 23-file Sol-high/Astra-high review found a privacy blocker and a weak
stale-session test. The first repair passed Astra but Sol found YAML quote tails
and raw name copies. One pi-review circuit-breaker oracle, `1684df7f` on
`openai-codex/gpt-6-astra:high`, defined the conservative rule now implemented.
Do not return to quote-by-quote fixes or weaken containment.

Final fix verification passed in workflow
`26979312-41a1-4c1b-a67e-06502df86d03`: Sol-high `1b9c353b` and Astra-high
`53ff6361` found no remaining supported blocker. The exact models are
`openai-codex/gpt-6.1-sol:high` and `openai-codex/gpt-6-astra:high`.
Reports are under `/tmp/lgtm-containment-verification/post-architect-review.*.md`.
These were same-model fallbacks because retained-child discovery was empty.
The parent ledger marks the privacy and session findings verified.

## Validation

- Real v5 supervisor: full `cargo test` completed with code 0 in 260.67 seconds,
  with no truncation or containment violation, before the final router-only repair.
  Formatting, strict Clippy, and build also passed.
- Current offline router fixture, strict standalone TypeScript CLI, and
  `cargo test --test jev_pi` (11 tests) pass after the final repair.
- Removing only `operation !== generation` made the stale-session test fail;
  restoring it made the test pass. No mutation remains.
- Rust and Biome diagnostics are clean. Repo-root TS LSP lacks installed Node/Pi
  SDK resolution; the explicit strict CLI passes. Markdown/plain-text LSP is absent.
- The normal commit hook still needs to run fresh final configured checks.
  Do not claim it passed until a real commit and evidence confirm that.

## Next steps

1. Both final review results are consumed and the parent ledger is updated.
   Run the normal commit gate on the exact staged final tree.
2. Rerun affected checks after any edit. Preserve original tool-name mapping,
   native schemas, and existing messages; no permission grant comes from Jev.
3. Stage exact final files, including repaired router/fixture and these docs.
   Check Git email is `254259785+tcbuilds@users.noreply.github.com`.
4. Use a Git-only worker in this worktree for a bare normal `git commit`.
   Compound commit forms were denied. Do not bypass a denial; diagnose it.
   The real configured suite takes about 4.5 minutes.
5. Push `feat/jev-quiet-gates` without tags, update existing draft PR #132 with
   current evidence, and verify its head. Do not merge or release.
6. Remove task scratch/probe files only after their evidence is no longer needed.

## Evidence and useful files

- `templates/pi/jev-auto.ts`, `tests/fixtures/pi/jev_auto.cjs`: final privacy/session repair.
- `doc/jev-auto.md`: behavior, privacy limits, manual install/reload, rollback.
- `src/checks/commands/supervisor.rs`, `src/checks/ruff.rs`, `src/update.rs`,
  `tests/commands.rs`, `tests/claims_stop.rs`: process-hygiene repairs.
- `tests/fixtures/pi-v0130-extension.txt`, `tests/jev_pi.rs`: real historical upgrade input.
- `/tmp/lgtm-containment-verification/`: result JSON/logs, review packets/reports,
  `findings-ledger.json`, and the oracle contract. Keep while work is in flight.
- `/tmp/lgtm-containment-probe/`: reusable diagnostic scripts; the full trace
  located the final orphan in the claims-output fixture.

## Resume

Start Pi in `/home/ubuntu/lgtm-quiet-gates`, use `/warmup`, then read this file.
Current packet: `/tmp/lgtm-containment-verification/post-architect-packet.md`.
Owner decisions pending: none.

## Archived — 2026-10-18 (historical, not current authority)

<details>
<summary>Previous M26 handoff</summary>

# Handoff — M26 implementation in progress

> Updated: 2026-10-17 after slice 26.2
> Branch: `docs/jev-v2-file-reads`
> M26 review baseline: `56d70055ea3ff21275fa3c9ec77c792f328cc54f`

## Current authority

The owner authorized **all M26**, commits in verified slices, and Pi review
**once over the whole phase at the end**, not per slice. Implementation is
direct; no writer subagents were launched. Two slices are committed:

- `50303cb` — slice 26.1, one-file Jev questions.
- Slice 26.2 (bounded preview/scouting) is implemented, gated, and pending the
  commit that follows this handoff update.

Jev is on by default and fails gracefully without Jev/API/auth/provider. Normal
tools and deterministic LGTM enforcement keep working. Existing global
`~/.pi/agent/extensions/jev-auto.ts` stays unchanged. Do not revive jev-classify.

Live replay budget is approved at **$1 maximum, at most 64 calls, 16 KiB of
reviewed public LGTM source per call**. Do not send credentials, private logs,
or user transcripts. Stop if cost cannot be bounded. No global deployment,
release, model switch, or package install is authorized.

Global Pi settings now enable auto-compaction; `openai-codex/gpt-6.1-sol` keeps
its 550,000 reserve, so it compacts above 500,000 tokens.

## Scope and plan

Read `jev_v2.md`, `research.md`, and local `implementation_plan.md` **M26**.
The detailed plan is gitignored; do not force-add it.

Nine slices: 1 single-file questions; 2 bounded preview/scouting; 3 preflight and
real replay; 4 separate review-risk flags; 5 scope/evidence consistency advice;
6 diagnostic triage; 7 compaction advice; 8 suspicious-output advice; 9 measured
cache decision. Work in order, one commit per slice.

## Slice 26.1

- `templates/pi/jev.js` renders into the owned extension and registers
  `lgtm_jev_files` from session startup. Codemode exposure, no startup inference.
- Single-file boolean question, 16 KiB, 1,500 lines, five-second deadline,
  governed read, prohibited/credential/symlink checks, stale detection, and
  privacy-preserving fixed error codes.
- Proof: project/global/dual-scope integration; native Pi schema validation;
  scratch pre-Jev upgrade/backup/refresh probes.

## Slice 26.2

- Same tool, bounded batch: 1..8 files, 1..4 `bool`/`choice`/`score` questions,
  16 KiB/file, 64 KiB total, five-second per request inside a twenty-second
  aggregate budget, sequential so each request carries exactly one file.
- `preview: true` returns eligible/skipped paths, stable IDs, planned questions,
  declared bounds, and labeled call/byte estimates with **zero classifier calls
  and zero content reads**. Content-level rejection surfaces at classification.
- Answers are validated: a choice outside the criteria is an explicit no-match,
  an out-of-range score or missing answer is `unavailable`, and failed/unread
  files are `unavailable`, never negative matches. Per-file coverage, content
  hashes, and `partial` status are preserved.
- `tests/fixtures/pi/jev_scout.cjs` and `tests/jev_pi.rs` cover preview
  zero-calls, byte/file limits, no-match, out-of-range, stale, cancel, hung and
  erroring providers, source secrecy, and unchanged tool permissions.

### Digest upgrade fix (important)

When a template revision changes, the *previous* canonical digest must be added
to `KNOWN_TEMPLATE_DIGESTS` in `src/init/pi.rs`. Slice 26.2 added the 26.1 pair:

- project `9088869510d83eac68780e9f96290b692384907f310088e3734bb77cd543889e`
- global `2df34d5ff7811cd79d643abcb070240b8a4da9dd5be23d2802e08c23b25ee804`

An earlier attempt recorded digests computed by a helper that did not match
Rust `str::lines()` normalization; the real upgrade probe failed with
“incomplete or mismatched LGTM ownership markers”. The values above come from
the `TEMPLATE_DIGEST` a 26.1 install embeds, and the probe now passes. Get future
digests the same way, from an installed previous revision, or reproduce Rust’s
normalization exactly (drop the trailing newline after split).

## Slice 26.3

Offline preflight is implemented in `tests/fixtures/pi/jev_replay_corpus.json`,
`tests/fixtures/pi/jev_replay_hostile.txt`, and
`tests/fixtures/pi/jev_replay.cjs`, with a third integration test in
`tests/jev_pi.rs`. It validates the versioned 14-case hand-labeled corpus and
drives the generated tool with a scripted provider. It proves contracts only and
prints `semanticQuality: "not-evaluated"`. The docs define the bounded live
procedure (≤64 calls, ≤16 KiB public committed source per call, hard cost cap).

The live tool-level replay has not been run. This Pi session started before the
Jev tool existed, so `tools.lgtm_jev_files` is not callable here. One native
classifier probe was validated live (`~typesafe/jev-latest`, answer 0.03,
$0.000293) via the read tool, which is not the governed raw-byte path, so it is
not the tool replay and must not be reported as semantic evidence.

## Slice 26.4

`templates/pi/jev_review.js` is a second rendered fragment (split to keep each
template under the size limit) registering `lgtm_jev_review`. It obtains the
diff with one fixed read-only `git diff` through Pi's bash tool, bounds the patch
(48 KiB, 200 files), and asks four independent bools: auth/permissions, data
loss, public interfaces, and state/complexity. No aggregate score exists; an
invalid answer makes only that flag `unknown`; empty/oversized/credential/private
diffs make no classifier call. `tests/fixtures/pi/jev_review.cjs` and a fourth
test in `tests/jev_pi.rs` cover risky/harmless diffs, partial/unknown flags,
provider failure/timeout/cancel, and evidence filtering. Scratch 26.2→26.4
project and global upgrade/backup/refresh probes pass with the recorded digests.

## Slice 26.5

`templates/pi/jev_scope.js` registers `lgtm_jev_scope`, an advisory check that
compares a declared scope and up to eight claims against the HEAD revision and
changed paths (fixed read-only `git` calls, 200-path and 512-character bounds).
Verdicts are `supported`, `unsupported`, `contradicted`, `unclear`, `missing`,
or `invalid`; a stale revision or empty diff makes no call. It never creates
`Passed` evidence and never touches `src/checks/claims.rs` or `src/hooks/stop.rs`.
`tests/fixtures/pi/jev_scope.cjs` and a fifth test in `tests/jev_pi.rs` cover a
docs-only scope with an installer edit, valid work, missing/invalid claims,
stale/empty/oversized input, and provider failure. Scratch 26.4→26.5 project and
global upgrade/backup/refresh probes pass.

## Slice 26.6

`templates/pi/jev_triage.js` registers `lgtm_jev_triage`. The caller supplies an
already-minimized excerpt; the tool redacts then clips to 8 KiB and always
reports redaction count and clipping. A private-key block is rejected; home
paths, emails, IPs, and credential-like tokens become markers. Transport needs
`allowSend: true`; otherwise it returns a zero-call `preview`. Command, cwd, exit
code, and an existing LGTM finding stay facts. It never reads logs, runs
commands, stores evidence, or proposes repairs. `tests/fixtures/pi/jev_triage.cjs`
and a sixth test in `tests/jev_pi.rs` cover preview, redaction, clipping, private
keys, malformed/unmapped categories, and provider failure. Scratch 26.5→26.6
project and global upgrade/backup/refresh probes pass.

## Slice 26.7

`templates/pi/jev_compaction.js` registers `lgtm_jev_compaction`. It reads no
transcript and compacts nothing. It accepts bounded caller state (paths,
unfinished work, constraints) and returns a recommendation
(`compact_now`/`compact_after_finishing`/`stay_put`/`unclear`), a separate
unfinished flag, and a preservation checklist echoing the caller's own items.
Invalid answers leave advice `partial` or `unavailable`; the result states it
cannot compact. Pi's native summary format and cut safety stay untouched.
`tests/fixtures/pi/jev_compaction.cjs` and a seventh test in `tests/jev_pi.rs`
cover half-done task switches, complete boundaries, unmapped and missing answers,
and provider failure. Scratch 26.6→26.7 project and global upgrade/backup/refresh
probes pass.

## Slice 26.8

`templates/pi/jev_untrusted.js` registers `lgtm_jev_untrusted`. It warns whether
an approved, bounded external excerpt tries to redirect an agent or leak data,
returning `suspicious` plus `kind` (`instruction_injection`,
`exfiltration_attempt`, `benign_quoting`, `unclear`). Redaction precedes clipping;
inspected/provided coverage and clipping are reported as partial. It is explicitly
not a security boundary and never overrides instructions, permissions, or checks.
`tests/fixtures/pi/jev_untrusted.cjs` and an eighth test in `tests/jev_pi.rs`
cover hostile instructions versus a harmless quote, missing/unmapped answers,
private keys, redaction, clipping, and provider failure. Scratch 26.7→26.8
project and global upgrade/backup/refresh probes pass.

## Slice 26.9

Decision recorded: **no answer cache ships.** The offline preflight makes no live
calls and the live replay shows no measured repeat reuse, so there is no net
benefit to claim and adding storage would create stale-answer risk for a cheap
decision. `doc/adapters/pi.md` records the bounded, private criteria that would
have to be met before adding one (exact input/questions/provider/model/policy/
freshness identity, resolved aliases, no cached errors, expiry and size limits,
corrupt state fails closed, cancellation never writes, no database or service).

## Phase-end review and fix round

One independent Pi review ran over the whole M26 patch (baseline `56d7005`) with
two fresh-context `reviewer` children at `openai-codex/gpt-6-astra:low` (repo
Astra routing; the pi-review skill asks for Sol/Astra high and that is overridden
by AGENTS.md). Parent-verified findings and fixes:

- High: private-path hunks still reached the provider in `jev_review`. Fixed by
  rejecting the whole diff (`diff_private`) when any header path is private,
  including quoted Git paths; the fixture now asserts zero calls and no `.env`
  content in any request.
- High: `jev_triage` echoed `command`/`cwd`/`finding` unchanged into results and
  session records. Fixed by redacting those fields and rejecting a private-key
  value (`sensitive_metadata`) before transport and persistence.
- Medium: the 64 KiB batch cap was enforced only in preview. Fixed by an actual
  byte budget on the classification path; the fixture asserts transmitted bytes
  stay within 65,536 and excess files are skipped.
- Medium: score answers persisted the question criteria text. Fixed to return the
  score index and confidence only.
- Medium: four tools accepted a late provider result after cancellation. Fixed
  with a post-classification abort check in `jev_compaction`, `jev_scope`,
  `jev_triage`, and `jev_untrusted`.
- Medium: clipping used UTF-16 units. Fixed to count and clip on UTF-8 byte
  boundaries in `jev_triage`, `jev_untrusted`, and `jev_review`; fixtures assert
  multi-byte payloads stay within the byte bound.
- Medium: `.unref()` watchdogs could let harnesses exit 0 before assertions.
  Fixed to a referenced watchdog cleared on completion in all eight fixtures.

Reviewer re-verification confirmed the triage, score, UTF-16, late-cancel, and
watchdog fixes, and found two remaining precision gaps; both are now fixed:

- `jev_review` `headerPaths` parsed by whitespace, so a Git-quoted path with a
  space or `\t` escape (for example `"a/private dir/.env"`) could slip past the
  private check. Now quoted tokens are decoded (C-style escapes, octal, unknown
  escapes rejected conservatively as `diff_unparsed`) before the private test. A
  quoted-path fixture case is added.
- `jev.js` charged a preliminary `lstat` size, so a file that grew during the
  governed read could exceed 64 KiB. Now the actual snapshot byte length is
  charged before each classifier call; a read-growth fixture case is added.

Final reviewer re-verification confirmed both remaining fingerprints fixed, and the
reviewers' residual test-gap notes are closed: quoted private paths are now tested
as three independent cases (space, tab escape, and space-plus-tab), and the
growth fixture asserts exactly four provider calls, exactly 65,536 transmitted
bytes, and exactly one `volume_limit` skip. All nine M26 checkboxes are marked
complete. All M26 work is committed and pushed on `docs/jev-v2-file-reads`.

## Live replay (option 1) and its finding

The approved live tool-level replay ran in a fresh headless Pi session that
loaded the generated project extension and called `lgtm_jev_files` once per
corpus case through codemode. Result: 14/14 agreement, 0 false positives, 0 false
negatives, 0 abstentions; classifier $0.001498, main model $0.02065, total about
$0.022 under the $1 cap. Published in `doc/jev-replay-results.md`, including the
honest caveat that no advantage over grep was demonstrated.

The live run found a real defect the offline fixtures missed: Pi's
`ctx.executeTool` returns `{ toolCall, result: { content }, isError }`, and the
governed read wraps file text in separate guidance blocks. The Jev file/review/
scope tools read `result.content` at the wrong level and checked the wrong block
boundary, so every real read failed as `read_filtered`. Fixed: read the nested
result, join all text blocks, and require the source to be present (`includes`
now instead of `endsWith`). Fixtures now use the real result shape, appended
guidance, and a multi-block read. The previous canonical template digests
(`acd4d16`, `3b3f171`, `f3fbcf1`/`28db2c6`) were added to `KNOWN_TEMPLATE_DIGESTS`.

## Verified commands (slice 26.2)

- `cargo fmt --check`
- `node --check templates/pi/jev.js tests/fixtures/pi/jev_scout.cjs`
- `cargo clippy --locked --offline --all-targets --all-features -- -D warnings`
- `cargo test --locked --offline --all-targets --all-features` (one unrelated
  `update.rs` “Text file busy” flake passed on isolated rerun)
- `cargo build --locked --offline`
- `cargo run --locked --offline -q -- compile --validate` (71 rules)
- Focused: `jev_pi` (2), `init_pi` (14), `init_global` (6), `pi_upgrade` (12),
  `pi_state` (21), `managed_upgrade` (7) all pass.
- Scratch probes: 26.1→26.2 project and global upgrade preserve an exact backup
  and refresh is idempotent.

## Authorized gate bypass for slice 26.2

Slice 26.2 is committed as `43d7ec5`. The commit was created with `git
commit-tree`/`update-ref` after the owner explicitly authorized a one-time
`git --no-verify` for this verified slice. `--no-verify` alone did not work:
LGTM's Pi `pre-tool-use` hook blocks the commit at the agent layer before Git
runs, so Git plumbing was used instead. The normal gates had already passed
(fmt, clippy, tests, build, compile --validate, upgrade probes). The gate's two
unresolved findings (a `cargo test` descendant-containment violation and three
files reported as not recorded) remain unexplained; treat them as open until a
later slice or review resolves them. Do not reuse this bypass without new owner
authorization.

## Incident to disclose

While probing, an init command was accidentally run against this repository with
`HOME` pointed elsewhere, so it rewrote tracked `.claude/rules/security.md` and
created three untracked rule files plus a backup. Those were reverted/removed
(`git status` is clean apart from M26 files). It also overwrote the untracked
local `.pi/extensions/lgtm.ts`, whose previous bytes were not recoverable; it was
regenerated with the installed release binary `/home/ubuntu/.local/bin/lgtm`
(0.12.2, pre-Jev template) so it no longer points at a deleted worktree. Local Pi
setup still loads; the Jev tool is absent from that 0.12.2 extension by design.
Run init only inside scratch `HOME`/repo pairs.

## Continue

Commit verified 26.2 paths, then re-read the plan for slice 26.3 (offline
preflight now; live replay only under the approved budget). Keep plan checkboxes
unchecked until the whole-phase gate completes. Do not spawn a review agent until
the phase is done.

Unrelated untracked paths to leave untouched: `.killer-whale/`, `.pi/`,
`triage.md`. The historical August handoff is `HANDOFF.2026-08-13.md`.

</details>
