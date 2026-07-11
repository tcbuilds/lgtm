# ADR-0001: Rust single binary

## Status

Accepted

## Date

2026-07-11

## Context

`lgtm` is a policy compiler and enforcement runtime that runs inside AI coding-agent hook lifecycles. In the Claude Code adapter it is invoked on all five native hook events (SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop). PreToolUse and PostToolUse fire on every tool call (including each edit), so the harness process is spawned many times per agent session. Hook startup latency is therefore paid repeatedly and directly taxes the agent's feedback loop; a slow harness makes the whole tool feel sluggish and discourages adoption.

The harness must also run inside arbitrary consumer repositories — the revenue projects it is meant to accelerate. Those repos already have their own toolchains and dependency graphs. Anything the harness drags in (an interpreter, a virtual environment, a lockfile) becomes setup friction and a source of version drift in every repo that adopts it.

A further requirement is per-repo version pinning: a consuming repo needs to lock to a specific harness version so its enforcement behavior is reproducible, and upgrading rules should mean upgrading one artifact, not reconciling a dependency tree.

The spec records the decision against a Python baseline (~80ms interpreter startup versus ~5ms for a native binary); other candidate implementations were not documented.

## Decision

Implement `lgtm` as a single Rust binary.

Rationale, as recorded in the spec's Key Decisions table:

- **Startup latency:** approximately 5ms hook startup for a native binary versus roughly 80ms or more for a Python process. Because hooks fire on every edit, this difference compounds across a session.
- **Zero environment setup in consumer repos:** a single binary requires no virtualenv, no interpreter, and no dependency installation inside the repos that adopt it.
- **Per-repo version pinning via one downloaded artifact:** distributing one binary makes version pinning trivial, following the precedent already set by `rtk` (the token-optimization CLI proxy) in this portfolio. Upgrading the rule set equals upgrading the binary.

Distribution is via `cargo install` or GitHub release. The per-repo version pin is a version string in `.lgtm/config.json` that the binary checks at startup.

## Consequences

- The agent feedback loop stays fast; hooks fail safely and fast with no interpreter to warm up.
- Consumer repos gain enforcement with no added language runtime, virtualenv, or dependency footprint of their own.
- Rule upgrades are delivered by shipping a new binary, and repos pin to a known version for reproducible enforcement.
- The team commits to Rust for the core: contributors need Rust proficiency, and the language-specific Rust standards from `codingStandards.md` (§Rust: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` must pass; no unchecked `unwrap()`/`expect()` in production paths; `thiserror` for libraries/domain errors and `anyhow` at binary boundaries) apply to the harness itself.
- The default policy registry is compiled into the binary (see ADR-0002), so the binary is the unit of both code and default rules.
- A binary distribution channel must be chosen at first release (GitHub releases with an install script versus cargo-only); this is tracked as an open question and does not change this decision.
