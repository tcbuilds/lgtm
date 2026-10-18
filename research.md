# Research: Jev patterns for the LGTM harness

**Retrieved:** 2026-10-17T14:29:10.971Z
**Status:** Research candidates, not approved implementation tasks.
**Comparison:** [current proposal](jev_v2.md) at `b35184b`; local
enforcement code base `29af281`. Unmerged upstream changes were not applied.

## Summary

All 13 requested repositories were reached. The most useful new ideas are
question validation with replay-based evaluation, scope/evidence consistency
checks, and diagnostic triage. These can use Pi's native classifier API and
existing OpenRouter authentication. They do not require installing these
projects or adding another provider client.

Most routing, review, injection-warning, and compaction ideas overlap our
existing proposal. Useful refinements are a preview of outbound work,
source-snapshot checks, and records that distinguish a proposed action from
what actually happened. These are design patterns, not reasons to add more
services.

Selective context pruning is different from compaction advice, but it needs
more proof before adoption. The SQL and browser projects are not a good fit
as LGTM dependencies. Borrow their planning and trace patterns instead.

This research did not install packages, run external project tests, or
launch paid classifier/evaluation requests. Published benchmark numbers are
author claims, not results measured on our harness. No candidate below has
a verified benefit for LGTM yet.

## Coverage and limits

- Relevant README sections were inspected for all 13 repositories.
- Ten README downloads were complete. The Jev MCP README and both directory
  READMEs were capped at 45,000 bytes.
- Selected source definitions were inspected in nine implementation repos;
  the source index below records the retrieved file blobs.
- The two SQL projects and two directories were assessed from README
  sections, not a source audit.
- This is not a full security, license, maintenance, or runtime audit.
  Directory entries and passing-test badges are not proof of quality.
- Context7 was unavailable. Sources were the public repositories, installed
  Pi documentation already examined for the proposal, and local LGTM
  CodeGraph results. No private source was sent to a classifier.

## Every repository: what transfers

| Repository | Useful pattern | Fit for LGTM / limitation |
|---|---|---|
| [nexibeo/jev-cookbook](https://github.com/nexibeo/jev-cookbook) | Atomic questions, log triage, choosing existing evidence candidates rather than generating values. | Good question-design examples. Recipe 11 compares a broad severity score with separate critical-event questions. Its small datasets do not establish our accuracy; do not copy its thresholds or closed categories blindly. |
| [chr-kelly/jev-cookbook](https://github.com/chr-kelly/jev-cookbook) | Offline question-shape linting, explicit no-match choices, labeled replay and confidence/error reports. | Strong foundation. Its linter catches malformed wire shapes, but it is not a complete semantic validator. Adapt the checks to Pi's native types; do not copy its direct API client. |
| [jonathanavis96/jev-kit](https://github.com/jonathanavis96/jev-kit) | Shadow mode, local checks before model calls, redaction before truncation, and diagnostic triage. | Borrow the rollout/data-minimization patterns. Its README explicitly says it fails open, permits overrides for most rules, and is not a security control. Never replace LGTM hard stops with those semantics. |
| [jkudish/jev-mcp](https://github.com/jkudish/jev-mcp) | Claim/evidence relationships, source IDs, subject matching, and separate invalid-response status. | Useful for advisory report checks. Missing evidence is not automatically a contradiction. Do not install a second MCP/client layer or let a semantic verdict certify command success. |
| [dzhng/jevgrep](https://github.com/dzhng/jevgrep) | Bounded discovery, verbatim source ranges from the judged snapshot, explicit partial coverage, versioned answer caching. | Refines file scouting. Do not add a second code index/parser by default; compare against CodeGraph/grep first. Previews can miss useful code, and completed discovery is not proof of complete recall. |
| [openlayer-ai/jevals](https://github.com/openlayer-ai/jevals) | Did the agent stay in scope, use tool results, make progress, or repeat work? Replayable evaluations. | Strong rubric examples for an advisory end-of-slice check. The README labels the project alpha and distinguishes live-exercised paths from mock-tested adapters. Do not import all its guardrails or assume truncated traces capture all constraints. |
| [tamaratran/fast-jev-compaction](https://github.com/tamaratran/fast-jev-compaction) | Keep, shorten, or remove old tool material while preserving call/result relationships. | Later experiment, not a default. It uses Claude-specific message/hook shapes, repeats fitted conversation state across batches, and can lose important evidence. Its default transport is not our required Pi/OpenRouter path. |
| [kylemclaren/jevql](https://github.com/kylemclaren/jevql) | Collect/filter first, explain the work before paying, then judge; deduplicate and bound batches. | Borrow the preview/planning idea. It is a Go SQL-processing client, not a required database extension. LGTM does not need Postgres or a semantic SQL layer for this work. |
| [realZachi/pg-jev](https://github.com/realZachi/pg-jev) | Batch shared work, expose request/token/cache statistics, and separate read-ahead limits from other resource limits. | Useful resource-budget lesson only. The README warns that its read-ahead limit does not bound the answer cache or total session memory. No database extension is justified for LGTM. |
| [jkudish/jev-browser](https://github.com/jkudish/jev-browser) | Record proposed versus executed actions, explicit stop reasons, deadlines, and partial extraction failures. | Borrow the trace shape, not a browser stack. A model declaring “done” or a goal score is not independent proof of completion. |
| [aurelio-labs/semantic-router](https://github.com/aurelio-labs/semantic-router) | Fit confidence against labeled outcomes, allow no route, and use a cheap stage before a more expensive one. | Learn from calibration and abstention. Do not add its Python routing/index stack or change our fixed model-routing policy. Calibration fitted to one task does not cover another task or shifted traffic. |
| [yibie/awesome-jev](https://github.com/yibie/awesome-jev) | Find projects and related evaluation/research sources. | Discovery only. Its inclusion policy explicitly says entries are not quality/security reviews or proof that a project runs. Only selected directory material was inspected. |
| [AbdelStark/awesome-typesafe-jev](https://github.com/AbdelStark/awesome-typesafe-jev) | Find cookbooks, independent evaluations, and warnings about forced choices and shifted data. | Discovery and cross-checking leads, not independent validation of every linked claim. Linked evaluation studies were not reproduced or fully audited here. |

## New candidates worth considering

### 1. Question preflight and replay evaluation — first priority

Before spending money, check our question sets for wrong shapes, unusable
labels, missing no-match outcomes, and unclear score levels. Reuse Pi's
runtime validation first; add only missing project-specific checks.
The cookbook's raw `noul` examples must map to Pi's native `bool` contract,
not be copied as wire payloads.

Then rerun a small set of real, labeled LGTM cases without changing
permissions or execution. Include irrelevant files, ambiguous cases,
negation, hostile text, and changed source. Keep separate held-out examples.
Report missed useful files, wrong answers, needless abstentions, failures,
latency, and total cost. Unknown cost must stay unknown, not become zero.

Keep provider/protocol failure separate from a valid “none fits” answer.
Version the questions, policy, and model identity used for the run.
A moving model alias is not a frozen model version.

**Proof needed:** bad question shapes fail before a request; frozen cases
show which thresholds help this task and which mistakes remain.
This strengthens our existing uncertainty recommendation rather than
creating a new runtime guard.

**Sources:** chr-kelly's linter/eval guide, jev-kit's shadow-mode description,
and semantic-router's calibration implementation.

### 2. Scope and evidence consistency — advisory only

At a completed slice, compare the actual user-approved scope, changed
paths, tool receipts, and final claims. Ask whether the work stayed in scope
and whether the answer reflects the evidence.

For example: the owner requested documentation, but the agent changed an
installer; or the report says runtime checks were added, but only prose
changed. Bind evidence to the same subject and revision. Unsupported,
contradicted, unavailable, and malformed are different outcomes.

This would complement `src/checks/claims.rs`, not replace it. That check
requires current successful command evidence for verification claims.
A Jev judgment must never create `Passed` evidence or weaken a hard stop.
Likewise, `src/checks/auth.rs` already distinguishes lexical signals from
unverified runtime behavior.

**Proof needed:** known scope drift and unsupported claims are flagged,
while valid work and unrelated evidence are not called contradictions.
Truncated or missing evidence must cause uncertainty, not a clean bill.

**Sources:** jevals' `StayedInScope` / `UsedToolResult` and Jev MCP's
claim relation, subject check, and invalid-response handling.

### 3. Diagnostic triage without dumping every log into context

Keep command name, working directory, exit status, and existing LGTM
findings as deterministic facts. For an ambiguous failure, send only an
approved, minimized diagnostic excerpt. Return a small category such as
code failure, missing tool, environment problem, or unknown, plus pointers
to the original evidence.

Use the existing governed tools through native codemode. Do not add a
private shell runner, daemon, automatic dependency install, or guessed fix.
Retain the original diagnostic for inspection before making a change.

Exclude sensitive content before transport. If redaction is needed, do it
before truncation so a split credential is not partly exposed. Regex
redaction alone does not establish that arbitrary logs are safe to upload.

**Proof needed:** real failed commands remain failures; categories help
find the right evidence without hiding the useful error or leaking input.
This is a concrete use of Level 10, not another general-purpose client.

**Sources:** nexibeo recipe 11 and jev-kit's redact-first approach.

## Useful refinements to the current proposal

- **Preview outbound work.** Borrow jevQL's explain-before-judge pattern:
  show eligible candidate count, scope, skipped files, planned questions,
  and bounded input size before classification. Estimates must be labeled;
  unknown prices remain unknown. A preview must not make a classifier call.
- **Tie answers to source snapshots.** Return stable file/evidence IDs,
  content identity, and inspected coverage. Re-read changed files before
  using the answer. Jevgrep returns ranges from the snapshot it judged;
  paths alone are not sufficient evidence.
- **Distinguish recommendation from action.** Reuse Pi's session records
  for the suggested action, actual action or refusal, fallback reason,
  model/question version, and reported usage. Do not create a separate
  telemetry service or duplicate native accounting. Jev Browser's trace
  makes the proposed/executed distinction explicit.
- **Cache only if measurements justify it.** If needed, bound storage and
  lifetime and include input, questions, model/provider, and policy in cache
  identity. Handle moving aliases and changed files explicitly. A failed
  request must not be cached as a negative answer.

## Later experiment: pruning, not another summarizer

The fast-compaction package separately judges whether knowing a call
happened and retaining its result are useful. That is a different operation
from asking when to summarize.

Do not copy the plugin into LGTM or change global compaction settings.
A Pi-native experiment would have to preserve user constraints, approvals,
unfinished work, tool-call/result integrity, raw history, and verification
receipts. A previous tool result cannot always be recreated safely:
commands can have side effects and source or external state can change.

Measure task completion and re-read cost, including repeated state sent to
Jev and prompt-cache effects—not just characters removed. If quality drops
or the saving is absent, keep native compaction. This is lower priority
than the existing file-question and review-focus work.

## Do not adopt from these projects

- New provider clients, credential stores, MCP services, routing daemons,
  vector indexes, database extensions, or a browser stack without a separate
  real requirement.
- Fail-open rules or agent-written override stamps for LGTM hard stops.
- A single weighted score that hides a serious security concern.
- Probabilistic “done”, test-pass, or security verdicts as execution proof.
- Raw prompt, source, credential, or transcript logging by default.
- Benchmark savings or accuracy claims presented as measured LGTM results.

## Integration recommendation

Keep the approved [Jev proposal](jev_v2.md) unchanged until the owner selects
new candidates. First strengthen question quality and replay evaluation.
Next consider the advisory scope/evidence check and diagnostic triage.
Treat preview, source identity, and trace quality as refinements, not a
reason to add separate frameworks.

Any implementation must use Pi's native classifier API, existing
OpenRouter authentication, governed tool paths, and LGTM's managed
init/refresh behavior. No implementation or paid evaluation is authorized
by this report.

## Selected source index

These are retrieved Git blob prefixes, not repository commit IDs.
README/source downloads may be cached or come from different snapshots.
Links follow the public default branch and can change; no single pinned
checkout was executed. Only the relevant definitions were inspected.

- [chr-kelly/jev-cookbook: jev_lint/__init__.py](https://github.com/chr-kelly/jev-cookbook/blob/main/jev_lint/__init__.py) — blob `e0f3d978f950`.
- [chr-kelly/jev-cookbook: eval/README.md](https://github.com/chr-kelly/jev-cookbook/blob/main/eval/README.md) — blob `29aaa2b6dced`.
- [nexibeo/jev-cookbook: recipes/11-log-triage/triage-logs.mjs](https://github.com/nexibeo/jev-cookbook/blob/main/recipes/11-log-triage/triage-logs.mjs) — blob `171d7d9ea068`.
- [jonathanavis96/jev-kit: airlock/redact.py](https://github.com/jonathanavis96/jev-kit/blob/main/airlock/redact.py) — blob `a2b6ae10c080`.
- [aurelio-labs/semantic-router: semantic_router/calibration.py](https://github.com/aurelio-labs/semantic-router/blob/main/semantic_router/calibration.py) — blob `b9e9557dade8`.
- [jkudish/jev-mcp: src/server.ts](https://github.com/jkudish/jev-mcp/blob/main/src/server.ts) — blob `7b221f452fd1`.
- [jkudish/jev-mcp: src/lib.ts](https://github.com/jkudish/jev-mcp/blob/main/src/lib.ts) — blob `5a183e44818c`.
- [openlayer-ai/jevals: src/jevals/agent/_evals.py](https://github.com/openlayer-ai/jevals/blob/main/src/jevals/agent/_evals.py) — blob `d984875820fa`.
- [dzhng/jevgrep: docs/architecture.md](https://github.com/dzhng/jevgrep/blob/main/docs/architecture.md) — blob `5828153613bd`.
- [dzhng/jevgrep: packages/core/src/cache.ts](https://github.com/dzhng/jevgrep/blob/main/packages/core/src/cache.ts) — blob `ea766dcda6d0`.
- [tamaratran/fast-jev-compaction: src/compact.ts](https://github.com/tamaratran/fast-jev-compaction/blob/main/src/compact.ts) — blob `bc04bb890638`.
- [jkudish/jev-browser: src/navigate.ts](https://github.com/jkudish/jev-browser/blob/main/src/navigate.ts) — blob `a1aa09015176`.
