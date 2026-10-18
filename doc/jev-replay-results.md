# Jev live replay results (2026-10-17)

This is a historical run of the earlier inline-input draft. The planned v13.0.0
API uses bounded request-file references. The numbers below do not verify that
new contract; its repair checks are offline and make no paid classifier calls.
See [the current API and privacy guide](adapters/pi.md#jev-advisory-tools-and-request-privacy).

## What ran

A bounded, owner-approved live replay of the real `lgtm_jev_files` tool, not a
fixture. A fresh headless Pi session loaded the generated project extension and
called the tool once per case through codemode against the versioned corpus in
`tests/fixtures/pi/jev_replay_corpus.json` (`lgtm-pi-jev-replay-v1`, 14 cases).

- Source: public committed LGTM files copied to a scratch workspace, each within
  the 16 KiB per-call bound.
- Model: Pi's native OpenRouter classifier `~typesafe/jev-latest` (reported as
  `~typesafe/jev-latest`; an unresolved alias is not a pinned version).
- Bounds: 14 classifier calls, far below the 64-call cap. Fully sequential.

## Result

**14 / 14 agreement with the hand labels. 0 false positives, 0 false negatives,
0 abstentions.**

| case | category | question | label | answer | confidence |
| --- | --- | --- | --- | --- | --- |
| diff-subprocess | useful | subprocess | true | true | 0.96 |
| gitleaks-subprocess | useful | subprocess | true | true | 0.98 |
| semgrep-subprocess | useful | subprocess | true | true | 0.99 |
| guarded-subprocess | useful | subprocess | true | true | 0.98 |
| adapter-subprocess | irrelevant | subprocess | false | false | 0.03 |
| config-subprocess | irrelevant | subprocess | false | false | 0.04 |
| packet-subprocess | irrelevant | subprocess | false | false | 0.02 |
| structure-subprocess | held-out | subprocess | false | false | 0.03 |
| diff-no-subprocess | negation | no_subprocess | false | false | 0.03 |
| adapter-no-subprocess | negation | no_subprocess | true | true | 0.97 |
| api-role | useful | role | commands | commands | 1.00 |
| diff-role | useful | role | analysis | analysis | 0.77 |
| config-role | useful | role | data | data | 0.37 |
| hostile-subprocess | hostile | subprocess | false | false | 0.02 |

Every case returned `ok` with a source hash and reported usage. The hostile case
was carried as data and answered correctly.

## Cost

- Classifier: **$0.001498** for the 14-case run, plus **$0.000293** for one earlier
  interactive classifier probe = **$0.001791**.
- Main model (all live-session attempts, including failed setup probes):
  **$0.02065**.
- Total: **about $0.022**, well under the $1 cap. No cache or fallback reads were
  used.

## Honest caveats

- The corpus is small (14 cases) and hand-labeled by the author. 14/14 is a
  positive signal, not proof of general accuracy.
- The questions are mostly answerable by `grep` or a careful read. **No measured
  advantage over grep alone was demonstrated.** The value shown here is that the
  real transport works and agrees with labels on a narrow rubric.
- One run, no tuning, no repeat trials. Confidence on the `role` choice was low
  for the data case (0.37), so a harder rubric could disagree.
- The live run found a real integration defect that offline fixtures had missed:
  Pi's `executeTool` returns `{ result: { content }, isError }`, and the LGTM read
  tool wraps file text in separate guidance blocks. The tool read the wrong field
  and rejected every case as `read_filtered`. That is fixed, and the fixtures now
  use the real result shape and an appended-guidance block order.
- This run does not authorize automatic hooks, serve as command evidence, or
  prove savings. Jev stays explicit and advisory.
