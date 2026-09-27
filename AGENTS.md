# Repository Guidelines

## Project Structure & Module Organization

`lgtm` is a Rust 2024 CLI that compiles engineering policy into agent hooks and enforcement results. CLI wiring lives in `src/main.rs`; reusable behavior is exposed through `src/lib.rs`. Keep features in focused modules such as `src/hooks/`, `src/checks/`, and `src/policy/`. Integration tests live in `tests/`, with shared helpers in `tests/common/` and inputs in `tests/fixtures/`. Policy data and its schema live in `policy/`. Architectural decisions are recorded in `doc/adr/`; implementation status is tracked in `implementation_plan.md`. Use `examples/python-service/` for end-to-end hook scenarios.

## Build, Test, and Development Commands

- `cargo build` compiles the debug binary.
- `cargo run -- --help` checks CLI command wiring locally.
- `cargo test` runs unit and integration tests.
- `cargo fmt --check` verifies Rust formatting without changing files.
- `cargo clippy --all-targets --all-features -- -D warnings` rejects lint warnings across targets.
- `cargo run -- compile --validate` validates and prints the embedded policy registry.

Run formatting, Clippy, tests, and a build before opening a pull request.

## Coding Style & Naming Conventions

Follow the tracked rule templates under `templates/claude-rules/rules/` and standard `rustfmt` output (four-space indentation). Prefer small modules, guard clauses, explicit error context, and typed errors. Functions use verb-first `snake_case` names, such as `validate_config`; types use domain-focused `PascalCase`; constants use `SCREAMING_SNAKE_CASE` and include units where relevant. Do not swallow errors, add unbounded work, or invoke external processes without a timeout. Add dependencies only when they replace substantial, risky code.

## Testing Guidelines

Write deterministic behavior tests beside unit code or as integration tests in `tests/`. Name Rust tests after observable behavior, for example `rejects_duplicate_rule_ids`. Bug fixes require a regression test. Public CLI behavior needs integration coverage, including exit status and output. Target at least 80% unit coverage and full behavioral coverage for security and hard-stop paths.

## Commit & Pull Request Guidelines

History uses Conventional Commits, for example `feat(core): ...` and `docs(adr): ...`. Keep commits atomic, imperative, and under 72 characters. Pull requests must state the problem, summarize the implementation, list test evidence, and note security, migration, or rollback impact. Include screenshots only for user-visible UI or rendered-output changes. Never commit secrets, generated evidence, or unrelated formatting churn.

## Codex Review Workflow

When Codex executes `implementation_plan.md`, review each slice directly. Do not invoke `codex-review` or create a review subagent. Inspect diffs for correctness, security, regressions, scope, and standards compliance. Repeat review → fix → verify until clean; only then mark the plan item complete.

<!-- lgtm-pi-guidance:start -->
<!-- lgtm-entry-document: standards-v1 -->
# Engineering Standards

Language-specific rules live in `.claude/rules/` and load automatically when you
touch a matching file. Do not read them manually.

<!-- lgtm-normative-headings: Review And Change Standards, Debugging Protocol, Quality Gates, AI-Assisted Coding Standards -->

## Language-Specific Standards

Language guidance is split by file type under `.claude/rules/`. Use the matching
language file and its pattern file when both exist.

## The Four Rules

**1. Think before coding.** State assumptions explicitly. If uncertain, ask. If
multiple interpretations exist, present them — do not pick silently. If a simpler
approach exists, say so. Push back when warranted.

**2. Simplicity first.** Minimum code that solves the problem. No features beyond
what was asked. No abstractions for single-use code. No flexibility that was not
requested. No error handling for impossible scenarios. If 200 lines could be 50,
rewrite.

**3. Surgical changes.** Touch only what you must. Do not improve adjacent code,
comments, or formatting. Do not refactor what is not broken. Match existing style
even where you would do it differently. Mention pre-existing dead code; do not
delete it unless asked. Every changed line must trace to the request.

**4. Goal-driven execution.** Turn tasks into verifiable goals: "add validation"
becomes "write tests for invalid inputs, then make them pass." For multi-step work,
state a brief plan with a verify check per step.

## The Ladder

Before writing code, walk this in order and stop at the first rung that works:

1. Does this need to exist at all?
2. Does it already exist in this codebase?
3. Does the standard library provide it?
4. Is it a native platform or framework feature?
5. Is it in an already-installed dependency?
6. Can it be one line?
7. Only now: the minimum viable implementation.

The ladder governs *scaffolding*. It never applies to input validation, error
handling, security, or accessibility — those are load-bearing and get written in
full every time. Skipping them is not minimalism, it is a defect.

## Non-Negotiable

- No secrets, tokens, private keys, or production credentials in code, logs,
  fixtures, screenshots, or commit history.
- No swallowed errors. If an error is deliberately ignored, document why.
- No unbounded queues, retries, caches, loops, tasks, threads, timers, or
  subscriptions.
- No network call, database call, subprocess, lock wait, or external API call
  without a timeout.
- No public API accepts unvalidated input.
- No string-built SQL, shell commands, HTML, URLs, or JSON where a safe builder
  exists.
- No disabled lint, type, security, or test rule without a justification comment
  at the suppression site.
- No "temporary" code without an owner, a date, and a deletion condition.
- No large feature merge without tests, run instructions, and rollback notes.

## Verification

Never state that a command succeeded unless you ran it and saw exit status 0.
Predictions are not results. If you did not run it, say so plainly.

Every bug fix carries a regression test in the same change. Write it first where
you can.

## Reject On Sight

- Vague names that hide domain meaning.
- Large functions mixing multiple abstraction levels.
- Boolean flags that create hidden modes.
- Shared mutable global state.
- Copy-pasted branches with tiny differences.
- Magic numbers or stringly-typed protocols.
- Catch-all error handlers.
- Comments explaining confusing code instead of simplifying the code.
- Assertions that code ran rather than what behavior occurred.
- Render paths recomputing heavy derived state.
- Synchronous slow work in request hot paths.
- Infrastructure changes without rollback or validation commands.

## Size Limits

Functions: aim 20–30 lines, split before 50. Files: review at 300 lines, split
before 500. Exceeding either requires a documented reason.

## Review And Change Standards

- Before a PR, run format, lint, type checks, tests, and the touched-area build; inspect the diff for debug code, dead code, unsafe logs, and actionable failures.
- A PR states the problem, implementation, test evidence, security/performance notes, screenshots for UI changes, and migration or rollback impact when relevant.

## Debugging Protocol

- Reproduce with the exact input, configuration, command, seed, timestamp, version, and environment; read the nearest code before changing it.
- State one hypothesis, repair the root cause, add a regression test, and remove temporary diagnostics or turn them into useful structured logs.

## Quality Gates

- A change is ready only when it builds, is formatted, passes linting and tests, covers new behavior and failure paths, and validates security-sensitive inputs.
- Report residual risk and unrun checks honestly; infrastructure changes include a validation command and rollback path.

## AI-Assisted Coding Standards

- AI-generated code meets the human bar: read surrounding code, keep patches small, use real APIs and files, preserve unrelated work, and never invent verification.
- Run relevant checks, replace generic generated names, remove scaffolding comments, verify security assumptions, and report residual or unrun risk.

<!-- lgtm-rule: preserve-unrelated-user-changes -->
#### Preserve unrelated user changes
<!-- lgtm-rule: required-repository-commands -->
#### Required repository commands pass
<!-- lgtm-rule: evidence-claims-honest -->
#### Verification claims require evidence
<!-- lgtm-rule: ai-assisted-discipline -->
#### Review AI-assisted coding discipline
<!-- lgtm-rule: commit-pr-evidence -->
#### Review commit and PR evidence
<!-- lgtm-rule: justification-metadata -->
#### Require temporary-code justification
<!-- lgtm-rule: debugging-protocol -->
#### Follow the debugging protocol
<!-- lgtm-pi-guidance:end -->
