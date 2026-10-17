# Jev v2: ask about files before reading them all

## What we want

Ship a small Pi helper through `lgtm init --agent pi`, built on the
existing `jev-auto.ts` approach. Use Pi's built-in Jev support and the
user's configured OpenRouter credentials—not a separate router package.

## The simple idea

A normal read puts file text in the main model's context. A Jev file
question sends that text to Jev instead. The main model gets a short
answer and probability.

Example: “Does this file run policy checks, or only define policy data?”

1. Find a short list of candidate file paths.
2. The helper reads those files and asks Jev the question.
3. Return paths, answers, probabilities, and any skipped/truncated status.
4. The main model reads the useful files normally before editing or quoting.

The file-question operation should also work inside native codemode.
It is an explicit tool, not a hidden replacement for every read.

## When it helps

Use it to scout many files for meaning without loading all their text.
Use grep for exact strings and code for counting.

For focused code investigation, CodeGraph may already be enough.
Its `explore` output includes source: filtering after that source reaches
the main model is too late to save those context tokens.

## Keep it safe and optional

- Keep uncertain files available for a normal read. A low score is not proof.
- Bound file sizes, candidate counts, concurrency, and request time.
- Exclude credentials; enforce workspace paths and report incomplete reads.
- Missing authentication or a failed request must leave normal reads and
  LGTM's deterministic enforcement usable.
- Init installs the capability; it does not send files or require an API key.
- Existing auto-routing and its enablement are separate from this new tool.

## Follow-on recommendations

These are proposed additions, in priority order—not implemented features.
Keep using Pi's native API and existing LGTM controls.

1. **Uncertainty handling — Level 4.** Make “not sure” a clear outcome
   for file scouting and other Jev judgments. Invalid replies, unavailable
   models, and uncertain answers must leave normal inspection available.
   Check with ambiguous inputs and failed requests. Do not copy the demo's
   thresholds without checking them against labeled real examples.

2. **Review focus — Level 3.** Ask separate questions about a diff:
   authentication/permissions, possible data loss, public interfaces, and
   complex state changes. Use the answers to direct reviewer attention.
   Do not blend them into one score that lets good style cancel a security
   concern. Check whether labeled risky diffs surface the right review area;
   no answer may waive required checks.

3. **Task-aware compaction advice — Level 7.** Reuse Pi's compaction.
   Suggest a good task boundary and what the summary must retain: user
   constraints, decisions, file paths, unfinished work, and the next step.
   Start with optional advice at clear checkpoints—not a call after every
   turn or the demo's small token limits. Check a task switch with unfinished
   work to make sure its state survives.

4. **Suspicious-output warnings — Level 6, lower priority.** Warn when
   untrusted external documents or logs appear to instruct the agent.
   This is only an extra signal, not an injection defense or permission
   system. Check both hostile instructions and harmless quoted examples.
   Report which text was inspected; never mark unscanned text as safe.

Measure each addition against the existing harness before making it
automatic. These benefits are not verified yet.

## Recommendations from the wider survey

Add these three priorities from the [13-repo research](research.md).
They extend the proposal; they do not authorize implementation or paid runs.

1. **Question checks and replay evaluation.** Reuse Pi's validation before
   a paid call. Check question shapes, usable labels, no-match outcomes,
   and clear score levels. Rerun labeled LGTM cases in shadow mode, without
   changing permissions or execution. Include ambiguous, irrelevant, hostile,
   and changed-source cases, with separate held-out examples. Record errors,
   abstentions, failures, latency, and total cost; unknown cost stays unknown.
   Version the questions, policy, and model identity.
   **Check:** bad shapes fail before a request, and replay results show the
   remaining errors and trade-offs. This strengthens uncertainty handling.

2. **Scope and evidence consistency.** Compare the user-approved scope,
   actual changed paths, tool receipts, and final claims at a completed slice.
   Warn about unrequested changes or unsupported claims. Match evidence to
   the same subject and revision; missing evidence is not automatically a
   contradiction. Keep invalid replies separate from genuine judgments.
   This only advises: current command evidence still decides verification,
   and no Jev answer may create a passed check or weaken a hard stop.
   **Check:** known scope drift is flagged, while valid work and unrelated
   evidence are not wrongly called contradictions.

3. **Diagnostic triage.** Keep command name, working directory, exit status,
   and LGTM findings as facts. For ambiguous failures, classify only an
   approved, minimized excerpt and return a small failure category plus
   pointers to the original diagnostic. Exclude sensitive content first;
   redact before truncating when redaction is needed. A regex alone does not
   prove that arbitrary logs are safe to upload. Use governed tools through
   native codemode, not a new runner, daemon, automatic install, or guessed fix.
   **Check:** failures remain failures, useful errors stay available, and
   triage does not expose private input. This is a use of Level 10.

## Useful refinements

Borrow these patterns, not the research projects' package stacks.

- **Preview outbound work.** Show candidate scope/count, skipped files,
  planned questions, and bounded input size before classification. Label
  estimates and unknown prices. The preview makes no classifier call.
- **Bind answers to source snapshots.** Return stable file/evidence IDs,
  content identity, and inspected coverage. Re-read changed files before
  trusting an answer; an answer about old bytes does not cover new bytes.
- **Record recommendations versus actions.** Use Pi's existing session
  records for the suggestion, actual action or refusal, fallback reason,
  model/question version, and reported usage. Do not add another telemetry
  service, duplicate accounting, or log raw prompts/source by default.
- **Cache only when measurements justify it.** Bound storage and lifetime.
  Include input, questions, provider/model, and policy in cache identity.
  Handle changed files and moving aliases explicitly. A failed request is
  not a negative answer and must not be cached as one. Check that edits and
  changed questions cannot reuse an old answer.

## Do not add

- Another standalone router/client or automatic model-switching layer.
- Probabilistic approval of dangerous commands or permission overrides.
- A private command runner around LGTM's governed tools.
- Jev verdicts as proof that tests passed; use current command evidence
  and exit status instead.

## Status

This is a proposal, not a shipped feature. Our routing/build benchmarks did
not test Jev file reads. Compare it with CodeGraph/grep alone, including
missed files, cached-input prices, later full reads, and elapsed time.

Reference: [10 Levels of Jev](https://github.com/disler/ten-levels-of-jev).
