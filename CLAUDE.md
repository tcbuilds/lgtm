# CLAUDE.md

Operational guidance for Claude Code contributors to `lgtm`.

## Scope and Architecture

`lgtm` is a Rust 2024 CLI that compiles engineering policy into Claude Code hooks, normalized enforcement results, and local evidence. The v0.1.3 MVP supports Python repositories and Claude Code.

- `src/main.rs` wires CLI commands; `src/lib.rs` exposes reusable modules.
- `src/hooks/` implements the five Claude Code lifecycle hooks.
- `src/checks/` contains native and wrapped checks; `src/policy/` loads profiles, overrides, and waivers.
- `src/init/` safely merges repo configuration and hook settings.
- `src/report.rs` renders evidence summaries.
- `policy/rules.json`, `policy/profiles/`, and `policy/semgrep-python.yml` define embedded policy.
- `policy/rule.schema.json` and `schemas/` define validation contracts.
- `tests/` contains integration coverage; `doc/adr/` records architectural decisions.

Read `AGENTS.md`, `codingStandards.md`, and relevant ADRs before changing behavior. Keep edits focused and add regression coverage for fixes.

## Build and Verification

```sh
cargo build --locked
cargo run --locked -- --help
cargo run --locked -- compile --validate
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
shellcheck scripts/install.sh scripts/test-install.sh
scripts/test-install.sh
```

Run the applicable gates before reporting work complete. Use `cargo run --locked -- <command> --help` to verify CLI examples. Never claim a check passed unless it ran.

## Release Workflow

`.github/workflows/release.yml` builds public x86_64 Linux musl and macOS archives when a `v*` tag is pushed. The tag must exactly match `v` plus the package version in `Cargo.toml`; the current package version is `0.1.3`. The workflow runs tests, packages binaries, publishes SHA-256 files, and creates the GitHub release.

Do not change versions, create tags, or publish releases without explicit authorization. Every release commit must add `doc/releases/vX.Y.Z.md` with concise user-visible changes, affected users, upgrade guidance, and any migration or compatibility impact; the release workflow rejects a tag without this file and uses it as the GitHub release description. Validate installer changes with `shellcheck` and `scripts/test-install.sh`. `scripts/install.sh` anonymously downloads public release assets and verifies their checksum before installation.
