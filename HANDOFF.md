# Handoff — main @ 50ebbc1

> Generated: 2026-08-03
> Stale if HEAD moves past `50ebbc1` or branch differs.
> Supersedes the 2026-08-02 handoff at `6aea7a1`.

## What shipped to main this session

Two commits, both pushed, both on the noreply identity.

- `24e06f7` — **claims gate fix.** `evidence-claims-honest` treated any line containing the
  substring `test` and the substring `pass`, in any order, as a tests-passed claim. Now
  requires whole-token matching with a pass word following a test word within eight tokens.
- `9b1f124` — **M24 slices 1-3.** Prohibited-command matching by shape rather than token
  prefix, credential redaction in deny reasons, and honest documentation of the residual
  evasion surface with a drift test.

- `50ebbc1` — **M21 slices 1-3 and 5-6.** Inversion tests for the two security-relevant
  mutation survivors, waiver expiry boundary coverage against an injected clock, and a
  checked-in reviewed survivor baseline of 41 entries. `config.rs` went from 20 survivors to
  zero. CI wiring deferred to M25.

`v0.6.0` remains the latest tag. No release cut.

## M24 is complete. Its diagnosis was wrong and is corrected in the plan.

**Slices 1-3 shipped.** `argv.starts_with(prefix)` recognized exactly one spelling. Verified
against the released binary: `rm -rf` denied while `rm -r -f`, `rm --recursive --force`,
`rm -Rf`, `sudo rm -rf`, and `chmod 777 -R` were all allowed. Both policy entry and command
are now reduced to executable plus flag set plus ordered operands. Flag equivalence is
reconciled at compare time rather than by expanding aliases, so `-r` and `-R` never become
interchangeable — they are synonyms for `rm` but different options for `ls`.

The two documented exclusions hold in every form tested: `git push --force-with-lease`
(including `=origin/main`, trailing position, and sudo-wrapped) and bare `git clean -fd`
and `-ffd`.

**Slices 4-5 were closed, not implemented.** They targeted "claims accumulate across the
whole session transcript." That mechanism does not exist. `parse_claims` keeps only the last
assistant entry, and `parses_only_last_assistant_text_claims` has pinned that since before
the blocks that motivated the slices. The real defect was substring co-occurrence, fixed in
`24e06f7`. The correction and the reasoning are written into the M24 preamble.

**Residual friction worth knowing.** Writing a shorthand command in prose (`` `cargo test` ``
when `cargo test --locked --all-targets --all-features` is what ran) still produces an
unprovable claim. That is the gate working correctly on imprecise prose, not a defect, but
"quote the command verbatim" is currently an unwritten contract discovered by being blocked.

## Wave 1: three milestones in parallel worktrees, none merged

All three branch from `9b1f124` and sit in sibling worktrees. Each was implemented by Codex
`gpt-5.6-luna` at `xhigh`, reviewed first by the orchestrator, then gated by Codex
`gpt-5.6-sol` at `high`.

| Branch | Worktree | Diff vs main | Gate rounds |
|---|---|---|---|
| `m17-test-association` | `../lgtm-m17` | 4 files, +647/-145, 6 untracked | 1 → 7 → 3 → 4 → 2 → **GATE PASSED**, 454 tests |
| `m19-rule-files-single-source` | `../lgtm-m19` | 71 files, +5846/-4017, 1 untracked | 1 → 6 findings |
| `m21-mutation-strength` | **MERGED as `50ebbc1`** | 8 files, +878/-2 | 3 → 4 → 4 → 1 → 1 → 4 → **PASSED** |

Detailed status for each is written into the milestone preambles in
`implementation_plan.md`. Summary of what matters:

**M17 hit the circuit breaker and the owner chose to ship it as a review signal.** The
invariant "an absent test must not count as evidence" survived two fixes. Round 2 excluded
deleted paths; round 3 handled recreation; round 4 found that the exclusion set is
order-dependent across cached and unstaged status, and that rename source paths are never
excluded at all. The classification work is good — seven language packs, workspace-aware,
anchored filename conventions — but the evidence model cannot support blocking. The verdict
downgrades to `Unverified` where it depends on that model, with four false-pass paths
documented by name and a drift test.

After the downgrade it produced zero P1 findings across three consecutive gates, and the
final confirmation returned no actionable defects. Ready to merge.

**M19 achieved its slices but initially missed its purpose.** Round one: all 71 machine
records were relocated into one file's frontmatter as a single 71,948-character line while 28
rule files carried prose alone. Every acceptance clause passed. The seam ADR-0013 exists to
close was simply moved one file left. Round two also caught two guidance regressions —
non-native harnesses received no rules at all, and default installs got guidance from neither
path because `lgtm init` does not write `.claude/rules/`. Both fixed.

**M21 was split.** Its Rust work passed review clean on the first pass and ships: 453 tests,
zero survivors in both security guards, `config.rs` from 20 survivors to zero, 41 fully
documented baseline entries. All six rounds of findings landed in
`.github/workflows/mutation.yml`, including three recurrences of one invariant — a job
reporting success without running mutations. The workflow is removed from the branch and
becomes **M25**, specified from those findings.

Two facts worth carrying: `cargo mutants --timeout` is a per-test bound, not a process
deadline, so the declared 900-second budget was never enforced despite a round of fixing it.
And cargo-mutants counts UNVIABLE mutants in its tested total — an orchestrator run reported
`177 mutants tested in 15m: 28 missed, 141 caught, 8 unviable`, where 177 is the sum of all
three. So a positive tested-count assertion passes even when nothing was actually mutated.

## The lesson this wave produced

Acceptance clauses written as prose can be satisfied by an implementation that misses the
point. M17 classified `contest.py` as a test and passed. M19 relocated the registry and
passed. M21's clauses were arithmetic — "zero survivors in these two functions" — and it
passed review on the first attempt. Write clauses a wrong implementation cannot satisfy.

The same lesson the M21 preamble already records about `execpolicy.rs` scoring zero mutation
survivors while shipping four bypasses.

## A process defect in how this session ran the review gate

The review contract requires the final confirmation to be independent, with no prior findings
ledger supplied. Every confirmation dispatched this session left `.codex-brief.md` in the
worktree, and Codex can read the workspace — one review cited `.codex-brief.md:18-20`
directly. So the confirmations had access to the prior findings and were weaker than claimed.

Delete the brief before dispatching any confirmation. The findings those gates produced still
stand, since each was verified independently against the code, but their independence was
compromised.

A second, larger pattern: by the later rounds most surviving findings were defects in the
BRIEFS rather than in the implementations. An underspecified presence check, a guard that
asserted overlap where coverage was required, and two requirements that could not both hold
(full-set fallback plus a 900-second budget). Implementation quality was consistently high;
specification quality is what kept failing.

## Merge hazards — resolve by hand, do not take one side

1. **`policy/rules.json`.** M17 widens its language applicability and scope to match the new
   language packs. M19 deletes the file entirely. The widened applicability must be carried
   into M19's frontmatter registry, then M17's `enforced_rule_scope_matches_every_language_pack`
   test re-run against the merged result. That test is what makes this resolvable rather than
   guesswork.
2. **`src/policy/mod.rs`.** Touched by both M19 and M21. Each was told to change only its own
   lines and leave the other's byte-identical, but verify by hand.
3. **`src/init/mod.rs`.** M19 owns `rules.rs`, M21 owns `execpolicy.rs`; both may have touched
   the shared module file.

## Recurring defect class in this codebase

Substring matching where token matching is required, found three separate times in one day:

- `src/checks/claims.rs` — "contest" contains "test", fixed in `24e06f7`
- `src/checks/diff/association.rs` — `contest.py` and `latest_value.py` classified as tests
- and the same shape underlies the destructive-command spelling problem in M24

Worth its own rule rather than being caught by review each time.

## Parser-differential is the other recurring shape

The destructive-command policy, M17's association gate, and M21's CI trigger all failed the
same way: an enumeration that must anticipate every spelling. The fix that worked in each
case was inverting to a positive assertion or a bounded parser, not adding another entry.

Prior art confirms this is a known dead end. `AnswerDotAI/safecmd` states it outright:
blacklisting dangerous patterns is "error-prone and easy to bypass"; it uses `shfmt` to build
an AST plus an allowlist. `banyudu/claude-warden` parses with bash-parser and recurses into
`sh -c` and subshells. Claude Code itself reportedly carries ~4,437 lines across 23 files of
hand-rolled recursive-descent parsing for this. `tree-sitter-bash` is on crates.io if the
Rust path is ever taken.

The decision recorded this session: lgtm defends against a careless agent, not an adversary,
so a blocklist is defensible **provided the documentation says so plainly**. That is what
M24 slice 3 now does.

## Tooling changes made outside the repo

Both live under `~/.claude/skills/` and were written with explicit user approval, since this
repo's harness confines writes to the repository.

- `codex-implement/assets/executors/luna-xhigh.json` — `gpt-5.6-luna`, `xhigh`,
  `workspace-write`, background dispatch, 30-minute budget, 45s poll.
- `codex-review/assets/executors/sol-high.json` — `gpt-5.6-sol`, `high`, `read-only`,
  background dispatch, 30-minute budget.
- Both SKILL.md files now read model, effort, and sandbox from those assets. Eight hardcoded
  model literals removed.
- `codex-implement` gained a concurrency rule (one brief per repo; parallel only when file
  scopes are disjoint) and background-dispatch guidance replacing the "pass timeout: 600000"
  advice, which cannot work: **600000ms is the Bash tool maximum**, so a 30-minute budget is
  only reachable via `run_in_background` plus polling.
- `codex-review` had two real bugs fixed: `$OUT` holds prose on the diff path and is NOT
  empty as documented (observed 1.4KB of findings against a 1MB stdout log), and
  `git add -N -- $UNTRACKED` swept every untracked file into the review scope.

## Environment notes

- **`~/.local/bin/lgtm` is no longer the v0.6.0 release artifact.** It was replaced with a
  dev build carrying the `24e06f7` claims fix so the hooks would pick it up. The real v0.6.0
  is preserved at `~/.local/bin/lgtm-v0.6.0`. Both report version `0.6.0` because
  `Cargo.toml` is unchanged — do not mistake one for the other when probing.
  Undo is `cp ~/.local/bin/lgtm-v0.6.0 ~/.local/bin/lgtm`.
- The correct Codex model slug is `gpt-5.6-luna`. Bare `luna` is rejected with
  "The 'luna' model is not supported when using Codex with a ChatGPT account."
- `--dangerously-bypass-approvals-and-sandbox` is refused by the Claude Code auto-mode
  classifier. Use `--sandbox workspace-write` for code edits.
- **Apostrophes break heredocs passed through the PreToolUse policy check.** An odd quote
  count fails the `shlex` parse and returns `prohibited command policy unverified: command
  has invalid quoting`. Write briefs without possessives.
- The `rtk` grep proxy returned a false "0 matches" for a parenthesized pattern
  (`grep -n 'cfg(test)'`) that a direct grep found. It caused one incorrect severity call.
  Verify structured data by parsing it, not by pattern matching.
- `cargo-mutants` 27.1.0 at `~/.cargo/bin/cargo-mutants`.
- `implementation_plan.md` is gitignored and local-only.

## Known-open defects, carried forward

- `rust-no-unwrap-expect` fires on `#[cfg(test)]` code while its message says "production
  paths". Warning only; it fired repeatedly this session on test modules.
- Evidence records hardcode `agent: "claude-code"` at `src/hooks/stop.rs:552`, pinned by
  `"const": "claude-code"` in `schemas/evidence.schema.json`. Every Codex run is mislabelled.
- Review-level PostToolUse findings (`function-size`, `file-size`, `function-complexity`) are
  announced identically to hard failures despite being `severity: warning` and never blocking.
- The unreproduced `EXIT=101` lib-test failure from 2026-08-02 did not recur in any run this
  session.

## Open decisions

- Whether to track `.lgtm/execpolicy.json`, `.lgtm/config.json`, and `.claude/settings.json`.
  Still untracked, so a fresh clone still starts with destructive-command blocking inactive.
  Raised on 2026-08-02, still unanswered.
- Whether to redesign M17's evidence model as a new milestone, or leave the gate as a review
  signal permanently.
- Whether the substring-versus-token defect class deserves its own enforced rule.

## Plan state

42 open slices. M18 and M24 complete. M17, M19, M21 implemented on branches but unmerged, so
their boxes are deliberately unchecked.

| Milestone | Slices | Subject |
|---|---|---|
| M17 | 3 | cross-language test association — on branch, review signal |
| M19 | 8 | rule files as single source — on branch |
| M20 | 7 | path-scoped rule injection — blocked behind M19 |
| M21 | 6 | test strength through mutation testing — on branch |
| M22 | 9 | OpenCode adapter — `opencode` installed, 4 slices need live-session fixtures |
| M23 | 9 | Pi adapter — **blocked, `pi` not installed**, acceptance forbids guessing |

## Continue here

```text
1. Read the gate results still in flight: M17 downgrade, M19 confirmation, M21 round three.
   Run dirs are under /tmp/codex-review/ and /tmp/codex-implement/.
2. Verify each branch yourself before merging. Do not trust a report.
3. Merge in this order: m21 (smallest, isolated), then m19, then m17. Resolve the three
   merge hazards above by hand.
4. Tick the 17 slice boxes only after each merge lands and gates pass on main.
5. Rewrite this handoff once main moves.
```

## Resume bootstrap

```text
/warmup
cat HANDOFF.md
git worktree list
```
