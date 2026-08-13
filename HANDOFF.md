# Handoff — issue #41 @ 39b56b4

> Generated: 2026-08-13
> Linked worktree: `/home/ubuntu/lgtm-issue-41-validate-policy-config`
> Branch: `issue-41-validate-policy-config`

## Current state

Issue #41 implementation is complete and ready for Reviewer. The linked worktree is
non-main and remains associated with issue #41. The phase was fast-forwarded from the
verified temporary phase worktree at `39b56b4`.

- `fabed3e` — schema severity enum, canonical runtime preflight, initial parity tests.
- `90672a4` — V1/V2 parity matrix and valid-path proof.
- `8049644` — bounded, control-free schema diagnostics.
- `39b56b4` — bounded, control-free semantic policy diagnostics at `run_config`.
- `implementation_plan.md` is updated with completed criteria and evidence.
- CodeGraph was synced and reports 165 files, 2,601 nodes, 6,348 edges, up to date.
- Fresh Sol review: PASS; no findings; six config tests audited as non-vacuous.

Current verification evidence:

- `cargo fmt --check`, `git diff --check`, Clippy, locked build: exit 0.
- `cargo test --locked --all-targets --all-features`: 552 passed.
- CLI help, 71-rule policy validation, config validation, shellcheck, and installer tests: exit 0.
- `cargo run --locked -- check --tier full`: `passed=20 warning=6 unverified=13 failed=0`.

Issue state is transitioned to `agent:review`; do not merge or switch the issue branch.

## Historical repository context

| Milestone | Status |
|---|---|
| M24 | complete — shipped in `9b1f124`, slices 4-5 closed as misdiagnosed |
| M21 | complete — merged `50ebbc1`, CI wiring split out to M25 |
| M19 | complete — merged `efe636a` |
| M17 | complete — merged `6bcb12d` as a review signal, not enforcement |
| M20 | 7 open — path-scoped injection; was blocked behind M19, now unblocked |
| M22 | 9 open — OpenCode adapter; `opencode` installed, 4 slices need live fixtures |
| M23 | 9 open — Pi adapter; **blocked**, `pi` not installed, acceptance forbids guessing |
| M25 | 5 open — mutation testing in CI, split from M21 |

## What shipped

- `24e06f7` — claims gate: whole-token matching with an ordered, bounded pass-word window.
  Previously any line containing the substrings `test` and `pass` in any order was a claim.
- `9b1f124` — M24: prohibited commands matched by shape rather than token prefix, credential
  redaction in deny reasons, and the residual evasion surface documented with a drift test.
- `50ebbc1` — M21: inversion tests for the two security-relevant mutation survivors, waiver
  expiry boundary against an injected clock, and a 41-entry reviewed survivor baseline.
  `config.rs` went from 20 survivors to zero.
- `efe636a` — M19: rule files as the single source. `policy/rules.json` and the retired
  aggregate standards document are gone, machine fields co-located with prose, plain
  `lgtm init` now installs rule files alongside hooks, transactionally and symlink-safe.
- `6bcb12d` — M17: cross-language test association across seven language packs, shipping as
  `unverified` rather than blocking.

`v0.6.0` remains the latest tag. No release cut. **A release note will need to cover four
milestones**, including two user-visible behavior changes: `lgtm init` now writes rule files,
and the test-association gate reports rather than blocks.

## Defects found that a green suite could not see

These are the reason the independent review gate earned its cost. Every one of them passed
`cargo test`, `clippy`, and orchestrator review before an independent reviewer caught it.

1. **52 rules selected for nothing.** M19 stored multi-extension scopes as brace globs, which
   the production matcher compared as literal bytes. Among the dead rules was
   `auth-change-security-review`, one of four `overridable: false` protected rules. The test
   that should have caught it expanded braces itself before comparing, so it exercised its own
   expansion rather than the matcher.
2. **The secrets rule stopped covering secrets.** Co-location narrowed `no-committed-secrets`
   from `**/*` to source extensions, dropping `.env`, YAML, Dockerfiles, and CI workflows.
   Separately, dotenv matching used the full path, so `config/.env.local` was missed.
3. **Upgrades would have stranded every existing install.** Adding frontmatter changed every
   shipped template, so v0.5/v0.6 installations would classify their own clean generated files
   as user edits and never update, keeping stale rules while the hook injected fallback
   guidance on top. Both Claude and Codex paths.
4. **A path escape in `init`.** Rule installation ran outside the staged-write transaction with
   symlink-following writes, so a symlinked `.claude/rules` could write outside the repository.
5. **A CRLF checkout yields a zero-rule registry.** LF-only frontmatter parsing meant every
   rule file read as having none, and `load_registry()` returned nothing.
6. **A mutation job that ran no mutations reported green**, three separate ways, most recently
   because cargo-mutants counts unviable mutants in its tested total.

## Standing invariants added, and what each replaced

The durable output of this session is not the fixes; it is the guards. Each converts a defect
review caught into one the build catches.

- `protected_rules_select_representative_production_scopes` — pins all four unwaivable rules by
  selection outcome through the production selector. Both regressions above wrote patterns that
  read correctly and matched nothing, so asserting on outcomes rather than pattern strings is
  the only version worth having.
- `every_rule_scope_is_loadable_from_its_document` — a rule cannot declare a file pattern its
  own document will not load for.
- `every_scanned_extension_is_covered_by_guidance_scope` — a rule's scope must cover the
  extensions its own checks scan, so guidance and enforcement cannot drift.
- `every_current_template_has_a_matching_digest_record` — a template cannot change without its
  digest, so the migration table cannot silently fall behind.
- M25's end-of-job assertion — a mutation job must prove it ran, completed, and matched the
  baseline. Absence of evidence is not a pass.
- `bundle_digest_sources()` — one function feeds both the digest and the export, so they cannot
  diverge by construction rather than by test.

## The two recurring defect classes in this codebase

**Substring where token matching was required.** Four instances in one day: `claims.rs`
("contest" contains "test"), `association.rs` (`contest.py`, `latest_value.py` classified as
tests), the destructive-command matcher, and a `#L` check matching `#License`. Treat any bare
`contains` on a structured token as suspect. This deserves its own rule.

**Parser differential — an enumeration that must anticipate every spelling.** The
destructive-command policy, M17's association gate, and M21's CI trigger all failed this way.
What worked every time was inverting to a positive assertion or removing the need to guess:
init installing rules so detection stops mattering, a content marker instead of filename
inference, one function feeding both digest and export.

Prior art agrees this is a dead end. `AnswerDotAI/safecmd` states it outright — blacklisting
dangerous patterns is "error-prone and easy to bypass" — and uses `shfmt` plus an allowlist.
`banyudu/claude-warden` parses with bash-parser and recurses into `sh -c`. `tree-sitter-bash`
is on crates.io if the Rust path is ever taken.

The decision recorded this session: lgtm defends against a careless agent, not an adversary, so
a blocklist is defensible **provided the documentation says so plainly**. M24 slice 3 does that.

## Process lessons, recorded because they cost real time

- **One slice per brief.** M19 was dispatched as eight slices in one brief and took sixteen
  review rounds. M21's Rust half was arithmetic-verifiable and passed review first time.
  Bundling hid which slice a blocker belonged to until the whole brief returned.
- **Acceptance clauses written as prose can be satisfied by an implementation that misses the
  point.** M17 classified `contest.py` as a test and passed its clause. M19 relocated the
  registry into one file and passed every clause. Write clauses a wrong implementation cannot
  satisfy.
- **Most late-round findings were defects in the briefs, not the implementations.** An
  underspecified presence check, a guard asserting overlap where coverage was required, two
  requirements that could not both hold, and an untransacted write. Codex twice pushed back
  correctly on a wrong instruction rather than complying.
- **Backlogging is for Medium and Low.** The upgrade migration was treated as backlog for three
  rounds while being a P1 regression this branch introduced. Re-read the finding each time
  rather than restating the earlier decision.
- **Delete `.codex-brief.md` before dispatching a confirmation.** Codex reads the workspace, so
  a brief left in the worktree hands the reviewer the prior findings ledger. One review cited
  it by line number.
- **Verify structured data by parsing it, not by pattern matching.** Four false readings this
  session came from greps and regexes over structured output, including one that briefly looked
  like all four protected rules had lost their flag.

## Environment notes

- **`~/.local/bin/lgtm` is a dev build, not the v0.6.0 release.** It carries the `24e06f7`
  claims fix so the hooks pick it up. The real release artifact is preserved at
  `~/.local/bin/lgtm-v0.6.0`. Both report version `0.6.0` because `Cargo.toml` is unchanged.
  Undo with `cp ~/.local/bin/lgtm-v0.6.0 ~/.local/bin/lgtm`.
- **The `rtk` proxy garbles output.** Confirmed four times: a false "0 matches" for
  `grep -n 'cfg(test)'`, and `git log -1 --format='%s'` returning the wrong subject twice. Use
  `git cat-file -p HEAD` and `git reflog` for git ground truth.
- **Apostrophes break heredocs** passed through the PreToolUse policy check — an odd quote count
  fails the `shlex` parse. Write briefs without possessives.
- Codex model slug is `gpt-5.6-luna`; bare `luna` is rejected.
  `--dangerously-bypass-approvals-and-sandbox` is refused by the auto-mode classifier; use
  `--sandbox workspace-write`.
- Worktrees `../lgtm-m17`, `../lgtm-m19`, `../lgtm-m21` still exist and are merged. Remove with
  `git worktree remove` when convenient.
- `implementation_plan.md` is gitignored and local-only.

## Known-open defects, carried forward

- `rust-no-unwrap-expect` fires on `#[cfg(test)]` code while its message says "production paths".
- Evidence records hardcode `agent: "claude-code"` at `src/hooks/stop.rs:552`, pinned by
  `"const": "claude-code"` in `schemas/evidence.schema.json`. Every Codex run is mislabelled.
- Review-level PostToolUse findings are announced identically to hard failures.
- M17's evidence model still has four documented false-pass paths; redesigning it is deferred
  and is why the gate reports rather than blocks.

## Open decisions

- Whether to track `.lgtm/execpolicy.json`, `.lgtm/config.json`, and `.claude/settings.json`.
  Still untracked, so a fresh clone starts with destructive-command blocking inactive. Raised
  2026-08-02, still unanswered.
- Whether the substring-versus-token class deserves its own enforced rule.
- Whether to cut a release covering the four closed milestones, given two user-visible behavior
  changes.

## Continue here

```text
1. M20 is now unblocked by M19 and is the natural next milestone: path-scoped rule injection
   for any hooked harness, 7 slices.
2. M25 (5 slices) is specified from evidence and can run in parallel — it touches only
   .github/workflows/ and the baseline.
3. M22 needs live OpenCode session fixtures for 4 of its 9 slices.
4. M23 stays blocked until `pi` is installed.
5. One slice per brief. The wave-1 worktree pattern works; the bundling did not.
```

## Resume bootstrap

```text
/warmup
cat HANDOFF.md
git worktree list
```
