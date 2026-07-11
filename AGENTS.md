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

Follow `codingStandards.md` and standard `rustfmt` output (four-space indentation). Prefer small modules, guard clauses, explicit error context, and typed errors. Functions use verb-first `snake_case` names, such as `validate_config`; types use domain-focused `PascalCase`; constants use `SCREAMING_SNAKE_CASE` and include units where relevant. Do not swallow errors, add unbounded work, or invoke external processes without a timeout. Add dependencies only when they replace substantial, risky code.

## Testing Guidelines

Write deterministic behavior tests beside unit code or as integration tests in `tests/`. Name Rust tests after observable behavior, for example `rejects_duplicate_rule_ids`. Bug fixes require a regression test. Public CLI behavior needs integration coverage, including exit status and output. Target at least 80% unit coverage and full behavioral coverage for security and hard-stop paths.

## Commit & Pull Request Guidelines

History uses Conventional Commits, for example `feat(core): ...` and `docs(adr): ...`. Keep commits atomic, imperative, and under 72 characters. Pull requests must state the problem, summarize the implementation, list test evidence, and note security, migration, or rollback impact. Include screenshots only for user-visible UI or rendered-output changes. Never commit secrets, generated evidence, or unrelated formatting churn.

## Codex Review Workflow

When Codex executes `implementation_plan.md`, review each slice directly. Do not invoke `codex-review` or create a review subagent. Inspect diffs for correctness, security, regressions, scope, and standards compliance. Repeat review → fix → verify until clean; only then mark the plan item complete.
