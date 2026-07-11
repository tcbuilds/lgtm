# ADR-0004: Consolidated MVP scope and platform decisions

## Status

Accepted

## Date

2026-07-11

## Context

The `lgtm` spec (`idea.md`, "Key Decisions (Resolved)") locks 17 decisions in its Key Decisions table. The most irreversible are recorded in separate ADRs: the Rust single binary (ADR-0001), the embedded policy registry with repo-local overrides (ADR-0002), and the hard-blocking Stop gate with no waivers (ADR-0003) — where ADR-0003 covers two table rows (Stop-gate strictness and Waivers). That accounts for four table decisions across ADRs 0001–0003. This ADR records the remaining 13 locked decisions together. Each is settled and should not be re-litigated; they define the shape and boundaries of the MVP. The authoritative source is the `idea.md` document as a whole, of which the Key Decisions table is the summary index; this record captures the decisions and their recorded rationale — drawing on the relevant `idea.md` sections, not the table alone — so the reasoning survives outside that document.

## Decision

1. **MVP language coverage: Python only.** Prove the full loop (select → inject → check → evidence) on one language first. TypeScript is a fast follow. Rule IDs stay stable as `applies_to.languages` widens later.

2. **Hook events: all five Claude Code native events.** SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, and Stop are all wired in the MVP.

3. **Check engine: wrap existing tools.** gitleaks (secrets), ruff (Python lint/AST rules), semgrep (SQL, timeouts, validation patterns), and native Rust `git diff` parsing. `lgtm` orchestrates these and normalizes their output to enforcement-result JSON. Native tree-sitter checks are post-MVP. Rationale: `lgtm` is explicitly not a new general-purpose linter (Non-Goals), so it orchestrates and normalizes existing tools rather than reimplementing them.

4. **Adoption via `lgtm init`.** With the binary on PATH (`cargo install` or GitHub release), `lgtm init` writes `.claude/settings.json` hook entries (merged, never clobbered) and `.lgtm/config.json`, detects languages and commands, and gitignores the evidence directory.

5. **Task-context detection: deterministic only.** Context is derived from observables — file paths, extensions, diff content, imports, and keyword match on prompt text. No LLM calls inside hooks. Rationale: predictable and testable. `intent` is a keyword-derived label, nothing smarter in the MVP.

6. **Evidence storage: `.lgtm/evidence/`, gitignored.** Local JSONL, one file per task, gitignored by `lgtm init`. Attachable to PRs later via a flag. Rationale: zero commit noise.

7. **Missing wrapped tools: degrade to `unverified`.** If a wrapped tool is not installed, affected rules report `unverified` — never a silent pass. `lgtm doctor` lists missing tools with install commands. Unverified MUST rules are surfaced prominently in the Stop report but do not hard-block in the MVP, because blocking on missing tooling would make fresh machines unusable.

8. **Profiles: all four in the MVP.** default, strict, prototype, and infrastructure. Profiles modify severity and required evidence; they do not duplicate the rule set.

   *(Waivers — "none in the MVP" — is a locked decision too, but it is one of the two table rows covered by ADR-0003, so it is not re-counted here.)*

9. **Dogfood target: one active Python revenue repo.** Candidate is internal-python-repo or alternate-python-repo — whichever has the most active Python agent work when the build starts. Rationale: prove the Claude Code loop on a real revenue repo before expanding.

10. **Codex adapter: post-MVP.** Built only after the Claude Code loop is proven on the dogfood repo. The core harness stays agent-neutral; only the adapter differs, and it reuses the same policy registry, rule IDs, and evidence schema.

11. **Revenue model: internal accelerator.** `lgtm` is a force multiplier for all revenue repos with no direct monetization.

12. **Relationship to nautilus: standalone repo.** The harness is runtime tooling; `nautilus` is the SDLC playbook (process docs). `nautilus` references `lgtm`.

13. **Name: `lgtm`.** Short, memorable, ironic — the tool that makes "LGTM" actually mean something.

## Consequences

- The MVP is a vertical slice: one language, one agent, one dogfood repo, full lifecycle, real evidence — enough to prove the enforcement loop end to end before broadening.
- Reusing existing tools keeps `lgtm` out of the business of reimplementing linters and lets it focus on selection, orchestration, normalization, and evidence.
- Deterministic context detection and gitignored local evidence keep hooks fast, predictable, and free of commit noise, consistent with the fast-failing-hook posture of ADR-0001.
- Degrading missing tools to `unverified` rather than passing or hard-blocking keeps the "never a silent pass, but never unusable on a fresh machine" invariant intact.
- Shipping all four profiles and all five hook events up front means the MVP exercises the full policy and lifecycle surface.
- Deferring the Codex adapter and TypeScript coverage bounds MVP scope while the agent-neutral core and stable rule IDs keep both cheap to add later.
- The internal-accelerator positioning sets the success bar as cleaner agent sessions on the dogfood repo (measured by evidence records), not revenue — the value is safer, faster agent output across every revenue project.
